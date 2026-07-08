---
title: "Third Attack Observation: RedTail Cryptominer Delivered over SSH"
date: 2026-07-08T09:00:00-05:00
draft: true
summary: "A SSH-2.0-Go actor at 130.12.180.51 brute forced HoneyPi, then ran a two-stage shell loader, implanted an authorized_keys entry for persistence, and dropped six architecture-specific RedTail payloads over SFTP. Same bundle seen from a second IP two weeks earlier points to shared tooling."
description: "Incident writeup of a RedTail cryptominer campaign against a DShield honeypot: default-credential SSH access, two-stage loader, SFTP payload delivery, MITRE ATT&CK mapping, and threat intel on the source infrastructure."
tags:
  - redtail
  - cryptominer
  - ssh-honeypot
  - dshield
  - cowrie
  - honeypi
  - sftp-payload-delivery
  - authorized-keys-persistence
  - mirai
  - threat-intel
  - mitre-attack
categories:
  - honeypot
---

## Initial Attack Observation

**Time and Date of Activity:** 2026-06-12 00:00 to 2026-07-08 12:00 UTC

The threat actor at 130[.]12[.]180[.]51 initially made contact with HoneyPi on 2026-06-12 during a SSH-2.0-Go sweep. Much like the previous credential sweep observation I reported, once the login credentials admin:admin were found to work on the 13th, it looks like regular automated logins occurred to ensure access was still available. Where this attack differed is the post login interaction. On the 30th, and at seemingly random times since (up to the time of this report), the same command sequence ran a two-stage shell loader, implanted an SSH key for persistence, and uploaded a set of six architecture-specific payloads over SFTP. The same six-file bundle was seen from a different IP (213[.]209[.]159[.]158) two weeks earlier, so it's likely this is some sort of shared tooling rather than a one-off actor.

## Relevant Logs, Files, or Emails

**Command chain:**

```bash
chmod +x clean.sh; sh clean.sh; rm -rf clean.sh;
chmod +x setup.sh; sh setup.sh; rm -rf setup.sh;
mkdir -p ~/.ssh; chattr -ia ~/.ssh/authorized_keys;
echo "ssh-rsa AAAAB3...AscVxegv66I5yu" >> ~/.ssh/authorized_keys
```

**Payloads:** six architecture-specific files delivered over SFTP to `/root/` (see the hash table below).

## Vulnerability, Exploit, CVE, and MITRE ATT&CK Mapping

As with the previous attack, the entry point is again the weak-auth posture and exposed management access. There isn't an underlying software vulnerability or exploit, so no CVE applies to this initial access. The attack used the remote service SSH ([T1021.004](https://attack.mitre.org/techniques/T1021/004/)) as the channel to launch a brute force / password guessing campaign ([T1110.001](https://attack.mitre.org/techniques/T1110/001/)) against HoneyPi. The attacker latched onto a known and documented default credential ([T1078.001](https://attack.mitre.org/techniques/T1078/001/)).

After the compromise, the attacker executed a shell loader ([T1059.004](https://attack.mitre.org/techniques/T1059/004/)), transferred tools over SFTP ([T1105](https://attack.mitre.org/techniques/T1105/)), and implanted an authorized_keys entry to establish persistence ([T1098.004](https://attack.mitre.org/techniques/T1098/004/)). They also stripped the file immutability with `chattr -ia` ([T1222](https://attack.mitre.org/techniques/T1222/)), and deleted the loader scripts to cover tracks ([T1070.004](https://attack.mitre.org/techniques/T1070/004/)). The *clean.sh* was likely used as a method to remove any existing malware tenants and cripple defenses ([T1562.001](https://attack.mitre.org/techniques/T1562/001/)).

The likely motivation is standing up cryptomining resources ([T1496](https://attack.mitre.org/techniques/T1496/)) based on the RedTail payloads identified below from the hash reporting. [RedTail is also documented](https://isc.sans.edu/diary/32936) being delivered through CVE-2024-4577 (PHP-CGI). Here the delivery path was SSH rather than web, but the payloads are similar and part of the same ecosystem.

## Goal of Attack, Successful / Unsuccessful

The goal of the attack was to stand up another resource for a RedTail cryptomining operation. The attack was as successful as HoneyPi would allow. Being that it's a DShield honeypot, rather than the payloads actually being executed they were stored, and there wasn't an actual persistent key written. Every stage of the actual attack was executed successfully though, and since it had more stages than the previously observed credential sweep campaign it made it a good candidate for further research.

## How Can Attacks Like This Be Prevented?

Since the initial attack vector was the same as the previous credential sweep, the baseline hardening steps still apply. Change default credentials, disable password auth in favor of keys, and lock down SSH access to known sources. That last one is one of the better mitigations, since the attacker establishes persistence specifically through authorized_keys. A couple of extras for this particular instance: monitoring `~/.ssh/authorized_keys` for unexpected entries and applying file integrity monitoring in some way to the `.ssh` directory, blocking outbound mining-pool traffic at the border firewall, and even alerting on `chattr` usage could all serve to either render the successful attack ineffective or notify a SOC of the compromise.

## Threat Intel on Attacker

The source IP 130[.]12[.]180[.]51 actually shows up under two separate entities, Omegatech LTD and Virtualine Technologies. I did some digging into why there was a discrepancy and went down a rabbit hole. I asked Claude to assist in my findings and then articulate the relationship between the organizations better than I could:

> The IP sits in legacy ARIN space (130.0.0.0/8) registered to Netiface LLC, a US shell in Louisville, KY, but it is announced in BGP by AS202412, Omegatech LTD, which open reporting ties to the bulletproof host Virtualine. That split is why reputation tools disagree on the operator: Omegatech and Virtualine are the same outfit under two names, while Netiface is only the paper registrant. The block itself looks abused rather than legitimately run. It carries the NetName PRIVATE-NETWORK on a publicly routed /22 and has three competing IRR route objects from three different ASNs (AS51396, AS202412, and AS214943), all created within weeks of each other in late 2025. Recently activated legacy space, mislabeled, with conflicting origins and an offshore announcer, is a textbook pattern for throwaway attack infrastructure, which lines up with everything else this host did.

As far as the AbuseIPDB numbers, 130[.]12[.]180[.]51 was reported 5,190 times and carries a 100% confidence of abuse. GreyNoise identifies this as a malicious IP, and Shodan interestingly enough identifies several vulnerabilities on the host, which could indicate a compromised system the attacker is using as attack infrastructure. Shodan reports the host exposing SSH (22), HTTP (80), and HTTPS (443) on an end-of-life software stack (nginx 1.18.0, OpenSSH 8.9p1, Ubuntu) and flags four CVEs on the host itself: CVE-2021-23017, CVE-2023-44487, CVE-2021-3618, and CVE-2025-23419.

All six payload hashes returned as malicious from VirusTotal. The four ELF binaries are the RedTail cryptominer, delivered as architecture-specific variants (ARM7, AArch64, i686, and an obfuscated-name build), and the two shell scripts are the loader (clean.sh) and installer (setup.sh). RedTail is a known XMRig-based Monero miner that ships per-architecture binaries and has been documented being delivered through CVE-2024-4577 among other vulnerabilities. VirusTotal first-submission dates place the ELF set at 2025-11-14, all within seconds of each other, indicating a single build; setup.sh is the oldest artifact at 2025-07-14, suggesting recycled loader tooling; and clean.sh dates to 2026-06-18. The VirusTotal filenames are DShield/Cowrie honeypot artifact names, so the samples were sourced from honeypots, and their embedded capture timestamps trace the campaign hitting sensors from at least 2026-06-02 through 2026-07-07. One of those captures, redtail_arm7 on 2026-06-14, lines up exactly with the 213[.]209[.]159[.]158 delivery of the same bundle I mentioned earlier that hit HoneyPi, which independently corroborates the shared-tooling link.

I have uploaded a copy of an [enrichment script](https://github.com/jsburnett/honeypi/blob/main/reporting/enrich.py) and [example report](https://github.com/jsburnett/honeypi/blob/main/examples/enrichment-130.12.180.51.md) that I have been using to add an automation layer to my threat intel. It streamlines the research instead of needing to copy/paste and navigate to each website.

| SHA-256 (file) | Family / role | VT | First submitted (VT) |
| --- | --- | --- | --- |
| 197c74…faf880 (clean.sh) | trojan.shell, loader/cleanup | 18/51 | 2026-06-18 |
| 783adb…e0d59 (setup.sh) | trojan.shell, installer | 28/61 | 2025-07-14 (oldest) |
| 3625d0…18c6f (redtail_arm7) | RedTail miner, ARM7 | 34/62 | 2025-11-14 |
| dbb7eb…5631e9 (redtail_arm8) | RedTail miner, AArch64 | 34/62 | 2025-11-14 |
| 048e37…e3cdc7 (redtail_i686) | RedTail miner, i686 | 37/63 | 2025-11-14 |
| 59c294…db91e5 (obfuscated) | RedTail miner, obf. names | 34/60 | 2025-11-14 |

## Indicators of Compromise

Unlike the earlier credential-validation sweep, this actor left a rich set of post-compromise artifacts. The primary indicators are the source IP, the SSH client banner, the default credentials used, the loader filenames, the persistence key, and the six payload hashes.

| Indicator | Context |
| --- | --- |
| 130[.]12[.]180[.]51 | Source IP. DE / Virtualine Technologies. Spamhaus DROP, AbuseIPDB 100%, GreyNoise malicious. |
| 213[.]209[.]159[.]158 | Separate source that delivered the identical six-file bundle on 2026-06-14 (shared tooling). |
| SSH-2.0-Go | Client banner presented by the actor across all sessions. |
| admin/admin, root/password, root/iloveyou | Default credentials that produced successful logins. |
| clean.sh, setup.sh | Two-stage loader filenames dropped via SFTP to /root/. |
| authorized_keys ending …AscVxegv66I5yu | SSH key implanted for persistence (distinct from the mdrfckr campaign key). |
| 6x SHA-256 (see table above) | RedTail cryptominer ELF set plus loader/installer scripts. |
