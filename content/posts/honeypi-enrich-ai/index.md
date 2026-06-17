---
title: "HoneyPi Part 6: AI Reporting"
date: 2026-06-17T10:00:00-05:00
tags:
  - dshield
  - honeypot
  - ai
  - claude
  - python
  - loki
  - threat-intel
  - isc-internship
draft: false
---

The [previous two](/posts/enrich-honeypi/) [posts](/posts/enrich-mac/) got all three streams into Loki, unified by `src_ip` and joinable by Community ID. That's a powerful dataset, but it has a problem: it's enormous. A single day produces tens of thousands of Cowrie events, thousands of Suricata alerts, and thousands of Zeek records. Nobody is reading that by hand every morning. This post covers the layer that makes the whole thing usable, a Python script that pulls the day's data, scores attackers by how interesting they are, and hands the most significant ones to Claude to write up as per-attacker narratives.

This was the original motivation for the entire project. The dashboards are great for investigating something I already know to look at, but the report is what tells me *what* to look at. It's the tier-1 triage I'd otherwise do by hand, done while I sleep.

The full script is [`honeypot_report_v2.py`](https://github.com/jsburnett/honeypi/blob/main/reporting/honeypot_report_v2.py) in the [honeypi repo](https://github.com/jsburnett/honeypi). I'll walk the design rather than dump all of it.

## The shape of the problem

The script does four things in sequence: pull each stream out of Loki, aggregate per-stream statistics, score every source IP for "interestingness," then build a correlated timeline for the top-scoring attackers and have Claude narrate them. The output is a markdown report with an executive summary, an activity table, a narrative section per notable attacker, a credential analysis, and an IOC table.

The reason it's structured this way, and not "send everything to Claude and ask for a report," is cost and signal. Tens of thousands of events won't fit usefully in a prompt, and most of them are identical brute-force noise. The scoring stage is what cuts the data down to the handful of actors actually worth a paragraph.

## Pulling from Loki

Loki's `query_range` API caps how much it returns per call, so the fetch pages backward through time using the oldest timestamp from each batch as the next cursor:

```python
def fetch_loki(loki_url, query, start, end):
    events = []
    cursor_end = int(end.timestamp() * 1e9)
    start_ns = int(start.timestamp() * 1e9)

    for _ in range(MAX_PAGES):
        resp = requests.get(
            f"{loki_url}/loki/api/v1/query_range",
            params={
                "query": query,
                "start": start_ns,
                "end": cursor_end,
                "limit": PAGE_LIMIT,
                "direction": "backward",
            },
            timeout=120,
        )
        # ... parse, collect, then:
        cursor_end = oldest - 1   # walk the window back
```

Three queries, one per stream:

```python
cowrie   = fetch_loki(args.loki, '{job="cowrie"}', start, end)
suricata = fetch_loki(args.loki, '{job="suricata", event_type="alert"}', start, end)
zeek     = fetch_loki(args.loki, '{job="zeek"}', start, end)
```

Note the Suricata query filters to `event_type="alert"` right in the label selector. I don't want flow or DNS EVE records in the report; only the alerts grade the traffic. Doing that filter at the label level rather than after the fact is cheaper for Loki and for me.

## Scoring: what makes an attacker interesting

This is the heart of it. Most sources hitting the honeypot are doing the same boring thing: a handful of credential guesses, then gone. A few do something that warrants attention, a successful login, a command, a file transfer, a high-severity signature. The scoring function encodes that judgment as weights:

```python
SCORE_LOGIN_SUCCESS = 10
SCORE_FILE_TRANSFER = 8
SCORE_ALERT_SEV1    = 6
SCORE_COMMANDS      = 5
SCORE_ALERT_SEV2    = 3
SCORE_MANY_FAILURES = 1   # per 50 failed logins, capped at 3
```

The weighting reflects a deliberate ordering of what tells a story. A successful login is the most interesting thing that can happen, since it means the attacker is now *in* and whatever they do next is real post-compromise behavior. File transfers (a dropped payload or exfil) come next. High-severity Suricata signatures, then command execution, then medium-severity alerts. Raw brute-force volume is weighted lowest and capped, because ten thousand failed guesses is loud but tells me almost nothing beyond "a scanner found me." The cap matters: without it, a single noisy brute-forcer would outscore a quiet actor who logged in and dropped a binary, which is exactly backwards from what I care about.

One important detail lives in the scoring function: the exclusion of the sensor's own gateway.

```python
EXCLUDED_IPS = {"<your-gateway-ip>"}
```

As covered in the Pi post, Suricata sees the honeypot's own management traffic (Alloy pushing logs, my admin SSH). That gateway IP would otherwise accumulate a score from all that activity and show up as a phantom "attacker." Excluding it here means the analysis output is clean regardless of whether the raw data has been filtered at the capture layer yet. This is the scoring-level half of the two-part fix; the capture-layer BPF filter is the other half and is purely about keeping the raw counts honest.

## Building the attacker bundle

For each top-scoring IP, the script assembles a single chronological timeline merging that IP's events from all three streams, then truncates intelligently if it's huge:

```python
timeline.sort(key=lambda t: t[0])
if len(timeline) > max_events:
    head = timeline[: max_events // 2]
    tail = timeline[-max_events // 2:]
    timeline = head + [(0, "meta", "truncated",
                        f"{len(timeline) - max_events} events omitted")] + tail
```

Keeping the head and tail with a marked gap in the middle preserves the *shape* of a long campaign, when it started, how it ended, and an explicit note of how much was elided, without flooding the prompt with the repetitive middle. For a brute-force that ran for hours, the first and last few events tell the analyst everything; the 23,000 identical attempts in between do not.

The merged timeline is what makes the narratives genuinely cross-stream. A single attacker's entry might interleave a Suricata blocklist alert, a Cowrie login success, the command they ran, and the Zeek record of the connection, all in time order. That's the holistic per-attack view that no single tool produces on its own.

## Handing it to Claude

The aggregates and attacker bundles go to Claude via the [API](https://platform.claude.com/) with a system prompt that frames the role and a report prompt that specifies the structure. The model is `claude-sonnet-4-6`.

The single most important thing in the prompt is the instruction against speculation. An early version of this happily invented plausible-sounding detail, attributing malware families and decoding intent that wasn't actually supported by the events. For a report that's supposed to feed a formal research writeup, confident fabrication is worse than useless; it's actively misleading. So the prompt is explicit:

```
Rules: cite only supplied data; mark inferences as inferences; "No activity
observed" for empty sections; when a file hash or download artifact is
ambiguous, report it as raw observation only, do not infer the delivery
mechanism or whether a payload was blocked
```

That last clause came directly from a real failure. The script had captured a file hash that turned out to be the SHA-256 of the single byte `1`, an artifact of how Cowrie intercepted an `echo` probe, not a real payload. The early prompt led Claude to confidently narrate a malware download. The fix was teaching it to report ambiguous artifacts as raw observations and let me make the call. The reports are better for it: where they make an inference now, they label it, and the formal writeup can lean on that distinction.

The system prompt also pins the audience and the terminology expectations:

```python
SYSTEM_PROMPT = """You are a threat intelligence analyst producing a report from a \
multi-instrumented honeypot: Cowrie (SSH/Telnet, decrypted application layer), \
Suricata (ET Open signatures), and Zeek (network metadata from PCAP). It is a DShield \
sensor on a dedicated public IP. The audience is a SANS ICS internship instructor; \
the report feeds a multi-month formal attack research writeup. Be precise, use \
correct terminology, map to MITRE ATT&CK technique IDs where confident, and never \
speculate beyond the data. Output clean markdown only."""
```

## Cost guardrails

Running this daily against an API has a cost, and it's worth being deliberate about it rather than surprised by a bill. Two controls matter. First, the scoring-and-truncation pipeline means only a bounded amount of data ever reaches the model, the top N attackers (default 5), each capped at 120 timeline events. The cost per run is therefore predictable regardless of whether the honeypot saw 10,000 events or 100,000. Second, the `--dry-run` flag prints the scoreboard and aggregates without making any API call at all, which is how I tune scoring weights or sanity-check a window for free:

```bash
python3 honeypot_report_v2.py --dry-run        # stats + scoreboard, no API call
python3 honeypot_report_v2.py --hours 168 --top 8   # weekly, more narratives
```

## Scheduling

The report runs daily from cron. The one real caveat on a Mac is sleep: a laptop that's asleep at the scheduled time silently skips the run. For the internship duration I've accepted that gap, but the proper fix is an always-on machine (a Mac mini or just running it on the same box that hosts the compose stack if that stays up). Noting it here because a missing daily report is the kind of thing that's easy to misread as a script failure when it's really just power management.

```cron
30 12 * * * cd /Users/<youruser>/Projects/honeypi && .venv/bin/python3 honeypot_report_v2.py >> report.log 2>&1
```

Running it inside a virtualenv keeps the `anthropic` and `requests` dependencies off the system Python, which on macOS is its own small headache worth avoiding. This job and the others are collected in [`docs/crontab-examples.md`](https://github.com/jsburnett/honeypi/blob/main/docs/crontab-examples.md).

## What the reports actually catch

A few days in, the pipeline has already produced findings that prove the design works. The reports surfaced, without me reading a single raw log:

- An SSH brute-force that succeeded on `root:123456` and immediately pulled a Linux ELF from a C2 host through a multi-fallback downloader (curl, then wget, then raw `/dev/tcp`), writing the guessed credential to `/tmp/.opass`, behavior consistent with a Mirai-lineage loader. The runtime config argument was passed encrypted; decoding it is deferred to the forensics section of the formal report.
- A `SSH-2.0-Go` scanner correlated across Suricata (blocklist alerts on two ports) and the Cowrie session, the multi-stream correlation working exactly as intended.
- A pair of IPs in the same subnet running coordinated Hikvision CVE-2021-36260 scans against `/SDK/webLanguage`, with matching byte signatures and staggered port enumeration, an inference only possible *because* the streams were combined.

That last one is the whole thesis in miniature: a conclusion you simply cannot reach from any one tool alone, surfaced automatically by correlating across all three.

## Where this leaves the project

The operator role has shifted from builder to analyst. The Pi captures and ships, the Mac pulls and processes, the dashboard is live, and the daily brief writes itself. What I read each morning is no longer raw logs; it's a triaged report telling me which handful of the day's thousands of attackers actually did something worth my time.

There's a backlog of optional enrichment I may pick up as the deployment continues: GeoLite2 tagging for country and ASN context in Zeek, VirusTotal and Shodan pivots on captured C2 IPs and hashes, decoding those XOR-encrypted malware configs for a deeper forensics section, and an always-on host to close the cron sleep gap. None of it blocks anything; the core pipeline is complete and running.

That's the build. The rest of the internship is the part I actually wanted to get to: reading what shows up.

