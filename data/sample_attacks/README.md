# CyberTrace Sample Attack Datasets

This directory contains **controlled synthetic security log datasets** designed specifically for developing, testing, and evaluating the **CyberTrace** incident reconstruction engine.

> ⚠️ **DISCLAIMER & ETHICAL NOTICE**
> - **All data is 100% synthetic.**
> - **No real individuals, credentials, or proprietary systems are represented.**
> - **All IP addresses belong strictly to private RFC 1918 ranges (`192.168.1.0/24`, `10.0.0.0/24`). No public IP addresses are present.**
> - **No real network penetration testing or malicious automation was used to produce these files.**

---

## 📋 Common CSV Schema

Every dataset adheres to the unified 14-field schema:

| Column | Type | Description | Example |
|---|---|---|---|
| `timestamp` | String | Event occurrence time (`YYYY-MM-DD HH:MM:SS`) | `2026-10-15 09:15:02` |
| `source` | String | Log source generator | `auth.log`, `firewall`, `audit.log`, `syslog` |
| `event_type` | String | Specific event category | `login_failed`, `port_scan_probe`, `privilege_change` |
| `source_ip` | String | Initiating host IP (RFC 1918 private) | `192.168.1.105` |
| `destination_ip`| String | Target host IP (RFC 1918 private) | `192.168.1.20` |
| `source_port` | String/Int| Port on the source host | `40012` |
| `destination_port`| String/Int| Port on the destination host | `22` |
| `username` | String | User identity associated with event | `admin`, `svc_admin`, `bchen` |
| `hostname` | String | Reporting system name | `srv-auth-01`, `srv-app-prod` |
| `process` | String | Executing daemon or binary | `sshd`, `bash`, `tar`, `curl` |
| `action` | String | Action state/outcome | `failure`, `success`, `allowed`, `elevated` |
| `severity` | String | Log severity level | `low`, `medium`, `high`, `critical` |
| `raw_message` | String | Raw simulated syslog/audit line | `Failed password for user admin...` |
| `event_id` | String | Unique identifier for the event | `BF-1025`, `CA-6042` |

> 📌 **Note:** No synthetic log record contains ground-truth labels like `attack_stage`. CyberTrace must deduce relationships and attack phases purely through deterministic correlation, graph algorithms, and rule matching.

---

## 🗂️ Dataset Descriptions

### 1. `brute_force.csv` (71 events)
* **Scenario:** Credential stuffing / brute-force password guessing.
* **Flow:** Normal morning user logins → 40 high-frequency failed password attempts from `192.168.1.105` against `srv-auth-01` (`192.168.1.20:22`) for user `admin` → successful login → trailing background events.
* **Testing Goal:** Validate detection of brute-force frequency thresholds and subsequent account compromise.

### 2. `port_scan.csv` (75 events)
* **Scenario:** Host and service discovery (Network Reconnaissance).
* **Flow:** Baseline firewall traffic → rapid succession of TCP connection attempts to 45 common service ports (SSH, HTTP, RDP, DB, etc.) from `192.168.1.50` against `192.168.1.10` → mixture of blocked and allowed firewall logs.
* **Testing Goal:** Test firewall parsing and scanning detection (one source probing many destination ports within seconds).

### 3. `compromised_login.csv` (53 events)
* **Scenario:** Suspicious account access from an abnormal subnet followed by interactive enumeration.
* **Flow:** Normal workstation access for user `mrodriguez` → failed logins from unusual subnet `10.0.0.120` → successful authentication → execution of reconnaissance commands (`whoami`, `cat /etc/passwd`, `cat ~/.ssh/id_rsa`).
* **Testing Goal:** Correlate anomalous source network addresses with post-authentication host actions.

### 4. `privilege_escalation.csv` (53 events)
* **Scenario:** Privilege alteration and root persistence.
* **Flow:** Standard database query operations by user `bchen` → enumeration of sudo privileges (`sudo -l`) → execution of unauthorized privilege escalation exploit → UID change to root (`0`) → modification of `/etc/shadow` and creation of a persistent backdoor user.
* **Testing Goal:** Detect privilege state transitions and link them back to prior non-privileged processes.

### 5. `data_exfiltration.csv` (55 events)
* **Scenario:** Sensitive file collection, compression, and high-volume data exfiltration.
* **Flow:** Normal file browsing → access to restricted confidential files (`customer_ssn_records.csv`, `patents_2026.pdf`) → creation of a compressed staging archive (`tar.gz`) → multiple high-volume outbound network streams (totaling ~700MB) to staging receiver `10.0.0.95:8443`.
* **Testing Goal:** Correlate unauthorized file reads with staging archive processes and high-volume egress network flows.

### 6. `combined_attack.csv` (178 events)
* **Scenario:** Full Multi-Stage Advanced Persistent Threat (APT) lifecycle.
* **Flow:** Interleaved with 100+ benign enterprise events across multiple services and hosts:
  1. **Credential Attack:** Attacker at `192.168.1.188` conducts failed login burst against target `srv-app-prod` (`192.168.1.12`).
  2. **Initial Access:** Attacker achieves successful SSH login for `svc_admin`.
  3. **Privilege Escalation:** Attacker enumerates sudo permissions and escalates UID to `root`.
  4. **Collection:** Attacker reads sensitive configuration and database dumps, packaging them into `/tmp/exfil_bundle.tar.gz`.
  5. **Exfiltration:** High-volume network egress streams over TLS to internal drop server `10.0.0.250:443`.
* **Testing Goal:** The master test for end-to-end incident correlation, graph building, root-cause identification, and MITRE mapping.

### 7. `normal_activity.csv` (130 events)
* **Scenario:** Benign baseline corporate network activity.
* **Flow:** Regular user logins, DNS lookups, intranet web browsing, database reporting queries, and file server document reading across office hours.
* **Testing Goal:** Benchmark detection engines against false positives; no alert or incident should be raised on this dataset.

---

## 🛠️ Regenerating the Datasets

To regenerate these synthetic datasets deterministically:
```bash
python data/sample_attacks/generate_datasets.py
```
