---
title: "Enrichment Appendix: 130.12.180.51 RedTail Payload Attribution"
date: 2026-07-08T10:33:00-05:00
draft: false
summary: "OSINT enrichment for the RedTail SSH campaign: per-indicator attribution of six hashes (four RedTail ELF variants plus loader/installer scripts), VirusTotal detection context, and a triage recommendation. Companion appendix to the third attack observation."
description: "Automated enrichment output for the 130.12.180.51 RedTail cryptominer campaign, with per-hash VirusTotal attribution, MITRE ATT&CK mapping, triage verdicts, and raw OSINT data."
tags:
  - redtail
  - cryptominer
  - virustotal
  - osint-enrichment
  - threat-intel
  - malware-attribution
  - mirai
  - dshield
  - cowrie
  - ioc
  - mitre-attack
categories:
  - honeypot
---

*Generated 2026-07-08 by [enrich.py](https://github.com/jsburnett/honeypi/blob/main/reporting/enrich.py) 15:33 UTC | 0 IPs, 6 hashes, 0 URLs queried*

## Enrichment Synthesis — 2026-07-08

### Key Findings

- **A coordinated multi-architecture malware deployment campaign is evident.** Four ELF binaries targeting ARM7, ARM8 (AArch64), i686, and an unknown architecture were dropped via SFTP to `/root/`, indicating a deliberate cross-platform infection chain, not a random scan artifact.
- **The ELF payloads are attributed to Redtail cryptominer and Mirai botnet families.** VT popular labels include `miner.usblfi26`, `trojan.usblem26/abminer`, and `trojan.mirai/usble726`, with detection rates of 34–37/62+, indicating well-known, actively maintained commodity malware with mining and DDoS capability.
- **The dropper shell script (`clean_sh`, `197c74...`) labeled `trojan.shell/abtrojan` (18 malicious detections) has been observed repeatedly from June 21 through July 7, 2026**, suggesting a persistent, ongoing campaign reusing the same staging infrastructure and tooling over at least two weeks.
- **A secondary shell script (`setup.sh`, `783adb...`) with 28 malicious detections and the label `trojan.alevaul/shell` was first seen May 2025**, predating the other artifacts significantly and possibly representing a longer-lived or separately maintained loader; its presence in a Cowrie honeypot artifact name confirms it was captured in a honeypot context.
- **All artifacts were delivered via SFTP to the root account**, pointing to successful or simulated SSH credential compromise as the initial access vector (MITRE ATT&CK T1078 – Valid Accounts, T1059.004 – Unix Shell).
- **No IP or URL indicators returned external data**, leaving attribution of the delivery infrastructure unresolved from this dataset alone.

---

### Per-Indicator Attribution

**`197c74408e15bd1168105f564f96aace4fd4819961b724630bf5a6be4878daf8` — Shell dropper (`clean_sh`)**
Detected as malicious by 18/51+ VT engines; labeled `trojan.shell/abtrojan`. The naming pattern `20260707-135556_sftp__root_clean_sh` reveals it was delivered via SFTP to the root home directory, with multiple observed instances dating from June 21 to July 7, 2026. The recurring filename pattern across multiple dates indicates this script is being redeployed repeatedly — consistent with a cleanup or installer dropper that prepares the system before dropping the ELF payloads. First submitted to VT on approximately June 16, 2026 (epoch 1781800580). MalwareBazaar returned a 401 auth error (API key issue, not absence of record).

**`3625d068896953595e75df328676a08bc071977ac1ff95d44b745bbcb7018c6f` — ELF, ARM7 (`redtail_arm7`)**
Detected malicious by 34/62 VT engines; labeled `miner.usblfi26/abapplication`. The filename `redtail_arm7` explicitly names the **Redtail cryptominer** family, targeting 32-bit ARM devices (routers, IoT, embedded systems). First submitted approximately January 2026 (epoch 1763150103), meaning this binary has been in circulation for months. Delivered via SFTP to `/root/` alongside the `clean_sh` dropper.

**`dbb7ebb960dc0d5a480f97ddde3a227a2d83fcaca7d37ae672e6a0a6785631e9` — ELF, AArch64 (`redtail_arm8`)**
Detected malicious by 34/62 VT engines; labeled `trojan.r002c0dkq25/mirai5`. The filename `redtail_arm8` and alias `aarch64` confirm this is the 64-bit ARM (AArch64) variant, targeting modern ARM64 devices. The Mirai label alongside a Redtail filename suggests either dual-purpose functionality or AV label variance. First seen approximately January 2026, same timeframe as the ARM7 variant, indicating both were built and deployed together.

**`048e374baac36d8cf68dd32e48313ef8eb517d647548b1bf5f26d2d0e2e3cdc7` — ELF, i686 (`redtail_i686`)**
Highest detection rate of all ELF samples: 37/63 VT engines; labeled `trojan.mirai/usble726`. Targets 32-bit x86 Linux systems. Filename confirms the Redtail campaign's i686 variant. First submitted approximately January 2026; observed in honeypot as early as June 2, 2026. The x86 variant broadens the target scope beyond IoT to include legacy Linux servers and VMs.

**`59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5` — ELF, obfuscated names (`redtail` variant)**
Detected malicious by 34/60 VT engines; labeled `trojan.usblem26/abminer`. Unlike the other ELF payloads, this one uses obfuscated random-looking filenames (`.VzcXuH4lyK3hGN0XJ5GUU9ZvtR4B5zn2HmD`, `.NtthdpylE`) suggesting evasion of filename-based detection, in contrast to the explicitly named `redtail_*` binaries. This may represent a stealth variant or a different stage of the same deployment chain. First seen approximately January 2026.

**`783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59` — Shell script (`setup.sh`)**
Detected malicious by 28/61 VT engines; labeled `trojan.alevaul/shell`. First submitted May 2025 (epoch 1752534694), making it the oldest artifact in this set by roughly 8 months. The Cowrie honeypot artifact name (`cowrie_783adb...vir`) confirms prior capture in a honeypot environment, and the common name `setup.sh` is a generic installer. This script likely handles environment setup, persistence, or payload configuration. Its age relative to the other artifacts may indicate it is shared or recycled tooling used across multiple campaigns.

---

**No external data:** No IP indicators or URL indicators were present in the enrichment dataset (both `ips` and `urls` fields were empty).

---

### Triage Recommendation

| Indicator | Verdict | Justification |
|-----------|---------|---------------|
| `3625d...` (redtail_arm7) | **Likely commodity — deprioritize for IR, retain for threat intel** | Well-known Redtail cryptominer, ARM IoT variant, months in circulation, high VT detections; commodity campaign behavior |
| `dbb7e...` (redtail_arm8) | **Likely commodity — deprioritize for IR, retain for threat intel** | AArch64 Redtail/Mirai variant; same campaign and age as ARM7; no novel indicators |
| `048e3...` (redtail_i686) | **Likely commodity — deprioritize for IR, retain for threat intel** | Highest detection rate (37), x86 Mirai/Redtail; broadens target scope but remains known commodity malware |
| `59c29...` (obfuscated ELF) | **Worth manual review** | Obfuscated filenames departing from the consistent `redtail_*` naming convention may indicate a separate stage, stealth variant, or updated payload; warrants static/dynamic analysis to confirm capabilities and staging mechanism |
| `197c7...` (clean_sh dropper) | **Worth manual review** | Actively redeployed across a 16-day window (June 21–July 7, 2026); understanding its exact cleanup/install logic would clarify persistence mechanisms and whether it removes competing miners (T1562 — Impair Defenses) |
| `783adb...` (setup.sh) | **Worth manual review** | Oldest artifact (May 2025), previously captured in Cowrie; its relationship to the current Redtail campaign (shared tooling vs. separate threat actor) is unresolved and merits comparison against historical honeypot logs |

---

<details>
<summary>Raw OSINT data (click to expand)</summary>

```json
{
  "ips": {},
  "hashes": {
    "197c74408e15bd1168105f564f96aace4fd4819961b724630bf5a6be4878daf8": {
      "malwarebazaar": {
        "error": "auth/permission (401) — check API key"
      },
      "virustotal": {
        "malicious": 18,
        "suspicious": 0,
        "undetected": 33,
        "type_description": "Shell script",
        "meaningful_name": "20260707-135556_sftp__root_clean_sh",
        "names": [
          "20260707-135556_sftp__root_clean_sh",
          "20260625-002930_sftp__root_clean_sh",
          "197c74408e15bd1168105f564f96aace4fd4819961b724630bf5a6be4878daf8",
          "20260621-101439_sftp__root_clean_sh",
          "20260621-040905_sftp__root_clean_sh"
        ],
        "first_submission": 1781800580,
        "popular_label": "trojan.shell/abtrojan"
      }
    },
    "3625d068896953595e75df328676a08bc071977ac1ff95d44b745bbcb7018c6f": {
      "malwarebazaar": {
        "error": "auth/permission (401) — check API key"
      },
      "virustotal": {
        "malicious": 34,
        "suspicious": 0,
        "undetected": 28,
        "type_description": "ELF",
        "meaningful_name": "3625d068896953595e75df328676a08bc071977ac1ff95d44b745bbcb7018c6f.elf",
        "names": [
          "3625d068896953595e75df328676a08bc071977ac1ff95d44b745bbcb7018c6f.elf",
          "3625d068896953595e75df328676a08bc071977ac1ff95d44b745bbcb7018c6f",
          "20260625-002931_sftp__root_redtail_arm7",
          "20260621-040906_sftp__root_redtail_arm7",
          "20260614-220954_sftp__root_redtail_arm7"
        ],
        "first_submission": 1763150103,
        "popular_label": "miner.usblfi26/abapplication"
      }
    },
    "dbb7ebb960dc0d5a480f97ddde3a227a2d83fcaca7d37ae672e6a0a6785631e9": {
      "malwarebazaar": {
        "error": "auth/permission (401) — check API key"
      },
      "virustotal": {
        "malicious": 34,
        "suspicious": 0,
        "undetected": 28,
        "type_description": "ELF",
        "meaningful_name": "dbb7ebb960dc0d5a480f97ddde3a227a2d83fcaca7d37ae672e6a0a6785631e9.elf",
        "names": [
          "dbb7ebb960dc0d5a480f97ddde3a227a2d83fcaca7d37ae672e6a0a6785631e9.elf",
          "dbb7ebb960dc0d5a480f97ddde3a227a2d83fcaca7d37ae672e6a0a6785631e9",
          "20260621-101444_sftp__root_redtail_arm8",
          "20260621-040928_sftp__root_redtail_arm8",
          "aarch64"
        ],
        "first_submission": 1763150108,
        "popular_label": "trojan.r002c0dkq25/mirai5"
      }
    },
    "048e374baac36d8cf68dd32e48313ef8eb517d647548b1bf5f26d2d0e2e3cdc7": {
      "malwarebazaar": {
        "error": "auth/permission (401) — check API key"
      },
      "virustotal": {
        "malicious": 37,
        "suspicious": 0,
        "undetected": 26,
        "type_description": "ELF",
        "meaningful_name": "048e374baac36d8cf68dd32e48313ef8eb517d647548b1bf5f26d2d0e2e3cdc7.elf",
        "names": [
          "048e374baac36d8cf68dd32e48313ef8eb517d647548b1bf5f26d2d0e2e3cdc7.elf",
          "048e374baac36d8cf68dd32e48313ef8eb517d647548b1bf5f26d2d0e2e3cdc7",
          "i686",
          "20260612-134951_sftp__root_redtail_i686",
          "20260602-193452_sftp__root_redtail_i686"
        ],
        "first_submission": 1763150106,
        "popular_label": "trojan.mirai/usble726"
      }
    },
    "59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5": {
      "malwarebazaar": {
        "error": "auth/permission (401) — check API key"
      },
      "virustotal": {
        "malicious": 34,
        "suspicious": 0,
        "undetected": 26,
        "type_description": "ELF",
        "meaningful_name": ".VzcXuH4lyK3hGN0XJ5GUU9ZvtR4B5zn2HmD",
        "names": [
          ".VzcXuH4lyK3hGN0XJ5GUU9ZvtR4B5zn2HmD",
          "r01HZlR6KxyAZI7aPPpGEHcpyC",
          "59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5.elf",
          ".NtthdpylE",
          "59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5"
        ],
        "first_submission": 1763150104,
        "popular_label": "trojan.usblem26/abminer"
      }
    },
    "783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59": {
      "malwarebazaar": {
        "error": "auth/permission (401) — check API key"
      },
      "virustotal": {
        "malicious": 28,
        "suspicious": 0,
        "undetected": 33,
        "type_description": "Shell script",
        "meaningful_name": "783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59.txt",
        "names": [
          "783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59",
          "783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59.txt",
          "setup.sh",
          "783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59.sh",
          "cowrie_783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59.vir"
        ],
        "first_submission": 1752534694,
        "popular_label": "trojan.alevaul/shell"
      }
    }
  },
  "urls": {}
}
```

</details>
