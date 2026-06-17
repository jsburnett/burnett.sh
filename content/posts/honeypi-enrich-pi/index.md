---
title: "HoneyPi Part 4: Setting up the Streams on the Pi"
date: 2026-06-15T08:00:00-05:00
tags: [dshield, honeypot, alloy, cowrie, suricata, loki, grafana, isc-internship]
draft: false
---
A quick preface before we get into the technical stuff. The next several sections are AI generated. I dumped my notes, config files, scripts and all the rest into a project in Claude, then prompted it through how I wanted the post compiled, linked and published. I have already had many nights of tinkering, troubleshooting and building a rather large note repository on this project, I didn't want to take another week trying to type up, link and copy/paste code snippets in here. This is just much more efficient and I highly encourage it. Now, on to the juicy details!

In the [last post](/posts/honeypi-enrich-plan/) I laid out the plan: three complementary streams. Cowrie for what the attacker *did*, Suricata for the alert context, and Zeek for the protocol narrative, all correlated against a single attacker IP. This post is the first of three build-out guides. Here I'll cover everything that runs **on the HoneyPi itself**: pointing Cowrie's logs at a transport, standing up Suricata with the ET Open ruleset, and wiring both into Grafana Alloy to ship off the Pi. The [next post](/posts/honeypi-enrich-mac/) handles the Mac side (Zeek, the second Alloy instance, Loki, Grafana), and the [final post](/posts/honeypi-enrich-ai/) covers the AI reporting script.

A quick note on the code. Rather than paste every config file in full and watch them go stale the moment I change something, the complete artifacts live in the [honeypi repo](https://github.com/jsburnett/honeypi). I'll inline the lines that matter to the narrative, the bits that bit me and the bits worth understanding, and link the full file for the rest. Where I reference a file, assume the repo has the current version; the snippets here are illustrative.

> **A word on the architecture before we start.** The whole point of this is correlation. Three tools watching the same wire from three vantage points only become *useful* if I can ask "show me everything this one IP did" and get an answer that spans all three. That requirement, one shared key (`src_ip`) across every stream, drives almost every decision below. Keep it in mind; it's why I fuss over label normalization later.

## The transport choice: Alloy

The DShield package already ships Cowrie events to the ISC collector. That's the whole point of the sensor; it feeds the aggregate threat feeds. But that data goes *up* to ISC. It doesn't give me a local, queryable copy I can slice however I want. For that I need my own pipeline: something to read the logs on the Pi and ship them to storage on my Mac.

I went with [Grafana Alloy](https://grafana.com/docs/alloy/latest/) as the transport. Alloy is the successor to Promtail and the Grafana Agent: one binary that tails files, runs them through a processing pipeline (parse, relabel, drop), and forwards to Loki. It runs as a service on the Pi and on the Mac, and the same mental model applies on both ends, which keeps the cognitive load down.

Install on the Pi (it's in Grafana's apt repo):

```bash
sudo apt-get install -y gpg
sudo mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt-get update
sudo apt-get install -y alloy
```

Alloy runs as a systemd service (`alloy.service`) reading from `/etc/alloy/config.alloy`. Config reloads cleanly with `sudo systemctl reload alloy` once you've validated the file. More on validation below, because that saved me repeatedly.

## Shipping Cowrie

Cowrie writes a structured JSON log, one event object per line, to `/srv/cowrie/var/log/cowrie/cowrie.json` (path depends on your DShield install; check yours). JSON-per-line is the friendly case for a log shipper: no multiline stitching, every field already named.

The Alloy pipeline for Cowrie is three stages: tail the file, parse the JSON to pull out the fields I want as labels, set those labels, and forward. Here's the core of it (the full config with both pipelines is [`pi/alloy/config.alloy`](https://github.com/jsburnett/honeypi/blob/main/pi/alloy/config.alloy)):

```alloy
local.file_match "cowrie" {
  path_targets = [{
    __path__ = "/srv/cowrie/var/log/cowrie/cowrie.json",
    job      = "cowrie",
    host     = "honeypot-pi",
  }]
}

loki.source.file "cowrie" {
  targets    = local.file_match.cowrie.targets
  forward_to = [loki.process.cowrie_json.receiver]
}

loki.process "cowrie_json" {
  stage.json {
    expressions = {
      eventid = "eventid",
      src_ip  = "src_ip",
    }
  }
  stage.labels {
    values = {
      eventid = "eventid",
      src_ip  = "src_ip",
    }
  }
  forward_to = [loki.write.loki_server.receiver]
}

loki.write "loki_server" {
  endpoint {
    url = "http://<loki-host>:3100/loki/api/v1/push"
  }
}
```

Two things worth calling out here.

**Label cardinality.** I'm promoting `src_ip` to a Loki *label*, which is deliberate but not free. Labels are indexed; every distinct value creates a new stream in Loki. For a honeypot getting hammered by thousands of unique source IPs a day, that's real cardinality. I accepted it because `src_ip` is the correlation key. The entire pivot-by-attacker workflow depends on being able to select `{src_ip="x.x.x.x"}` cheaply across all three jobs. The rest of the rich Cowrie data (`username`, `password`, `input`, `shasum`) I leave in the log body and parse at query time with `| json`. Promote what you pivot on; parse the rest on read. If this were a production SIEM ingesting from thousands of *sensors* I'd think harder, but for one sensor it's the right trade.

**`eventid` as a label** earns its keep because nearly every Cowrie query filters on it: `cowrie.login.success`, `cowrie.command.input`, `cowrie.session.file_download`. Indexing it makes those dashboard panels snappy.

Reload, then confirm in Grafana Explore (set the datasource to Loki, not the default "Random Walk" test source, which stumped me for a minute the first time):

```logql
{job="cowrie"}
```

First time I ran this and saw a real `cowrie.login.success` come through with the attacker's chosen credentials sitting right there in the body, the whole thing felt worth it.

## Suricata: grading the data

Cowrie tells me *what happened* in the SSH/Telnet session. It tells me nothing about the traffic hitting every other port, and it has no concept of "this source is known-bad." That's Suricata's job: run the [ET Open ruleset](https://rules.emergingthreats.net/) against everything on the wire and emit alerts I can sort by severity.

Install on the Pi:

```bash
sudo apt-get install -y suricata
```

Then pull the ruleset. `suricata-update` fetches ET Open and compiles it in:

```bash
sudo suricata-update
```

On my run this loaded **50,687 rules**. That number is worth internalizing; it's why Suricata is the "grade the data" layer. Out of fifty thousand signatures, the handful that fire on a given source tell me whether I'm looking at a generic scanner or something that warrants a narrative.

The one configuration detail that matters for everything downstream: Suricata's `eve.json` output. EVE is Suricata's unified JSON event log, and like Cowrie it's one object per line. Confirm it's enabled in `/etc/suricata/suricata.yaml` under `outputs:`, the `eve-log` section, with `alert` in its types list. By default it lands at `/var/log/suricata/eve.json`.

Set the capture interface to your honeypot's physical NIC (`eth0` on the Pi in my case) and start it:

```bash
sudo systemctl enable --now suricata
```

Watch it come alive:

```bash
sudo tail -f /var/log/suricata/eve.json | grep '"event_type":"alert"'
```

On a sensor sitting on a public IP, you will not wait long.

### Shipping Suricata through the same Alloy

The second Alloy pipeline block tails `eve.json`. It's structurally the same as Cowrie's, with two differences: I extract `event_type` (so I can separate alerts from flow/dns/http EVE records) and `src_ip`, and I **drop the stats events**, which Suricata emits every few seconds and which are pure noise for my purposes.

```alloy
local.file_match "suricata" {
  path_targets = [{
    __path__ = "/var/log/suricata/eve.json",
    job      = "suricata",
    host     = "honeypot-pi",
  }]
}

loki.source.file "suricata" {
  targets    = local.file_match.suricata.targets
  forward_to = [loki.process.suricata.receiver]
}

loki.process "suricata" {
  stage.json {
    expressions = {
      event_type = "event_type",
      src_ip     = "src_ip",
    }
  }
  // Drop periodic stats records, not useful, just volume
  stage.drop {
    source = "event_type"
    value  = "stats"
  }
  stage.labels {
    values = {
      event_type = "",
      src_ip     = "",
    }
  }
  forward_to = [loki.write.loki_server.receiver]
}
```

A couple of notes on this block. Both pipelines forward to the **same** `loki.write.loki_server` block: one egress, two sources. Both promote `src_ip` to a label using the identical key. That's not an accident; that shared key is what lets the dashboard's `$src_ip` variable pivot across `{job="cowrie"}` and `{job="suricata"}` in one motion. And critically, I keep `alert.signature` *out* of the labels and in the log body. Signature names are extremely high-cardinality, and I can always pull them at query time with `| json | signature=~"..."`. Promote the join key, not the descriptive text.

Confirm:

```logql
{job="suricata", event_type="alert"}
```

## Technical hiccups (the part I'd have wanted to read)

A few things bit me. Documenting them because the clean version above hides the troubleshooting.

**Validate before you reload.** Alloy fails closed: a syntax error and the service won't come back up, which on a remote Pi means an anxious moment. Always run:

```bash
alloy fmt /etc/alloy/config.alloy        # formats and catches syntax errors
```

before reloading. `alloy fmt` doubles as a linter; if it can't parse the file it tells you the line. (Raspberry Pi Connect earned its keep here when I locked myself out of a clean reload and needed to get back on the box.)

**Dotted JSON keys need quoting.** This one is mostly a Zeek-side problem (next post), but it shows up anywhere nested EVE fields get parsed. Alloy's `stage.json` uses JMESPath, and a bare `id.orig_h` is interpreted as *nested* access (`id` then `orig_h`), not a literal key named `id.orig_h`. The fix is to quote the key inside the expression string: `"\"id.orig_h\""`. Cowrie and the top-level Suricata fields are flat so it didn't hurt here, but it's the kind of thing that fails silently. You get an empty label, not an error, so I'm flagging it early.

**Suricata sees its own telemetry.** This is the big one, and it's still open as I write this. Suricata captures everything on `eth0`, including the Alloy stream pushing logs *to* the Mac, and my admin SSH on 12222. The result is the sensor logging its own management traffic as if it were attacker activity: you'll see the gateway address and `POST /loki/api/v1/push` with a `User-Agent: Alloy/...` showing up in the EVE data. There's even a mild feedback loop, since pushes generate EVE records which get pushed which generate records, bounded only because Alloy batches.

> **Pending change, not yet live as of this writing.**
> Two-part fix. The reporting script already excludes the sensor's own gateway IP from attacker *scoring* (an `EXCLUDED_IPS` set), so it never pollutes a narrative or fakes an attacker. But the events are still *in* Loki, inflating raw counts and aggregate stats. The proper fix is a BPF filter at Suricata's capture layer so it never ingests the management traffic in the first place, excluding the Mac's IP on the Loki push port and my admin SSH port. Note this is a data-hygiene fix, not a correctness fix: because scoring already drops the gateway, my analysis output is already clean. I'll update this section with the exact `suricata.yaml` capture filter once it's applied and verified for a full day. **tcpdump's** captures are already clean, since that exclusion lives in the tcpdump command line (see the capture unit [`pi/systemd/honeypi-pcap.service`](https://github.com/jsburnett/honeypi/blob/main/pi/systemd/honeypi-pcap.service)), so this is specifically a Suricata-capture-layer gap.

**The `src_ip` label key had to be unified deliberately.** Cowrie and Suricata both happen to emit a field literally named `src_ip`, so on the Pi it's a freebie. The trap is Zeek, which calls it `id.orig_h`, and if I'd let that ship as-is, the dashboard's per-attacker pivot would silently miss the entire Zeek stream. So the rule across the whole project is: **everything normalizes to `src_ip` before it hits Loki.** On the Pi that's automatic; on the Mac it takes an explicit relabel stage. Calling it out here because it's the single most important invariant in the design, and it's easy to not notice until a pivot comes back empty.

## Where this leaves us

At the end of the Pi-side work, two of the three streams are live and shipping:

- **Cowrie** to `{job="cowrie"}`, `src_ip` and `eventid` indexed, full session detail in the body.
- **Suricata** to `{job="suricata"}`, ET Open's 50k+ rules grading every packet, `src_ip` and `event_type` indexed, stats dropped, signatures kept in the body.

Both ride one Alloy instance, one egress to Loki on the Mac, one shared `src_ip` key. The third stream, Zeek against the rotated PCAPs, runs on the Mac and gets its own post, because that's where the correlation thesis actually pays off: same attacker, three independent tools, joinable by Community ID.

That's next.
