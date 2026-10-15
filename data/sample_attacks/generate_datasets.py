"""
Synthetic Security Log Dataset Generator for CyberTrace (Phase 2)
Generates controlled, realistic synthetic security log files conforming to the common schema.
All IP addresses are strictly private (RFC 1918). No public IPs, no real personal data.
"""

import os
import csv
import random
from datetime import datetime, timedelta

DATA_DIR = os.path.abspath(os.path.dirname(__file__))

SCHEMA_COLUMNS = [
    "timestamp",
    "source",
    "event_type",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "username",
    "hostname",
    "process",
    "action",
    "severity",
    "raw_message",
    "event_id",
]

def format_ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def make_event(
    event_id,
    dt,
    source="auth.log",
    event_type="login_success",
    source_ip="192.168.1.50",
    dest_ip="192.168.1.10",
    source_port=49152,
    dest_port=22,
    username="jdoe",
    hostname="srv-core-01",
    process="sshd",
    action="success",
    severity="low",
    raw_message="",
):
    return {
        "timestamp": format_ts(dt),
        "source": source,
        "event_type": event_type,
        "source_ip": source_ip or "",
        "destination_ip": dest_ip or "",
        "source_port": str(source_port) if source_port is not None else "",
        "destination_port": str(dest_port) if dest_port is not None else "",
        "username": username or "",
        "hostname": hostname or "",
        "process": process or "",
        "action": action or "",
        "severity": severity or "low",
        "raw_message": raw_message or "",
        "event_id": event_id,
    }


def generate_brute_force_dataset():
    """
    Scenario 1: Brute Force
    Target: ~70 events total (25 background benign + 40 brute force attempts + 1 success + 5 post-login benign)
    """
    events = []
    base_time = datetime(2026, 10, 15, 8, 30, 0)
    eid = 1000

    # 1. Normal morning background traffic
    benign_users = [("alice", "192.168.1.41"), ("bob", "192.168.1.42"), ("charlie", "192.168.1.43")]
    curr_time = base_time
    for i in range(20):
        curr_time += timedelta(seconds=random.randint(45, 120))
        u, ip = random.choice(benign_users)
        events.append(make_event(
            f"BF-{eid}", curr_time,
            source="auth.log", event_type="login_success",
            source_ip=ip, dest_ip="192.168.1.20",
            source_port=random.randint(50000, 60000), dest_port=22,
            username=u, hostname="srv-auth-01", process="sshd",
            action="success", severity="low",
            raw_message=f"Accepted publickey for {u} from {ip} port 52140 ssh2"
        ))
        eid += 1

    # 2. Brute Force attack begins from 192.168.1.105 targeting user 'admin'
    attacker_ip = "192.168.1.105"
    target_ip = "192.168.1.20"
    target_user = "admin"
    curr_time = datetime(2026, 10, 15, 9, 15, 0)

    for attempt in range(40):
        curr_time += timedelta(seconds=random.randint(3, 8))
        src_port = 40000 + attempt
        events.append(make_event(
            f"BF-{eid}", curr_time,
            source="auth.log", event_type="login_failed",
            source_ip=attacker_ip, dest_ip=target_ip,
            source_port=src_port, dest_port=22,
            username=target_user, hostname="srv-auth-01", process="sshd",
            action="failure", severity="medium",
            raw_message=f"Failed password for invalid user {target_user} from {attacker_ip} port {src_port} ssh2"
        ))
        eid += 1

    # 3. Successful login by attacker
    curr_time += timedelta(seconds=6)
    events.append(make_event(
        f"BF-{eid}", curr_time,
        source="auth.log", event_type="login_success",
        source_ip=attacker_ip, dest_ip=target_ip,
        source_port=40041, dest_port=22,
        username=target_user, hostname="srv-auth-01", process="sshd",
        action="success", severity="high",
        raw_message=f"Accepted password for {target_user} from {attacker_ip} port 40041 ssh2"
    ))
    eid += 1

    # 4. A few benign events continuing
    for i in range(10):
        curr_time += timedelta(seconds=random.randint(30, 90))
        u, ip = random.choice(benign_users)
        events.append(make_event(
            f"BF-{eid}", curr_time,
            source="syslog", event_type="web_access",
            source_ip=ip, dest_ip="192.168.1.10",
            source_port=random.randint(50000, 60000), dest_port=80,
            username=u, hostname="srv-web-01", process="nginx",
            action="allowed", severity="low",
            raw_message=f"HTTP GET /dashboard 200 OK user={u}"
        ))
        eid += 1

    return events


def generate_port_scan_dataset():
    """
    Scenario 2: Port Scan
    Target: ~75 events (20 background benign + 45 port scan probes + 10 background benign)
    """
    events = []
    base_time = datetime(2026, 10, 15, 10, 0, 0)
    eid = 2000

    # 1. Background normal traffic
    curr_time = base_time
    for i in range(15):
        curr_time += timedelta(seconds=random.randint(20, 60))
        events.append(make_event(
            f"PS-{eid}", curr_time,
            source="firewall", event_type="network_flow",
            source_ip="192.168.1.25", dest_ip="192.168.1.10",
            source_port=random.randint(49152, 65535), dest_port=443,
            username="", hostname="fw-core-01", process="kernel",
            action="allowed", severity="low",
            raw_message="FIREWALL PASS: proto=TCP src=192.168.1.25 dst=192.168.1.10:443"
        ))
        eid += 1

    # 2. Port scan activity from 192.168.1.50 targeting 192.168.1.10
    target_ports = [
        21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 135, 139, 143, 389, 443,
        445, 465, 587, 993, 995, 1080, 1433, 1521, 2049, 3306, 3389, 5432,
        5900, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 9300, 11211, 27017,
        28017, 50000, 50001, 50002, 50003, 50004, 50005
    ]
    curr_time = datetime(2026, 10, 15, 10, 15, 0)
    for p in target_ports:
        curr_time += timedelta(milliseconds=random.randint(200, 900))
        action = "allowed" if p in [22, 80, 443, 8080] else "blocked"
        events.append(make_event(
            f"PS-{eid}", curr_time,
            source="firewall", event_type="port_scan_probe",
            source_ip="192.168.1.50", dest_ip="192.168.1.10",
            source_port=random.randint(40000, 50000), dest_port=p,
            username="", hostname="fw-core-01", process="kernel",
            action=action, severity="medium" if action == "allowed" else "low",
            raw_message=f"FIREWALL {action.upper()}: SYN probe proto=TCP src=192.168.1.50 dst=192.168.1.10:{p}"
        ))
        eid += 1

    # 3. Post scan background traffic
    for i in range(15):
        curr_time += timedelta(seconds=random.randint(30, 80))
        events.append(make_event(
            f"PS-{eid}", curr_time,
            source="firewall", event_type="network_flow",
            source_ip="192.168.1.30", dest_ip="192.168.1.10",
            source_port=random.randint(49152, 65535), dest_port=80,
            username="", hostname="fw-core-01", process="kernel",
            action="allowed", severity="low",
            raw_message="FIREWALL PASS: proto=TCP src=192.168.1.30 dst=192.168.1.10:80"
        ))
        eid += 1

    return events


def generate_compromised_login_dataset():
    """
    Scenario 3: Compromised Login
    Target: ~65 events total
    """
    events = []
    base_time = datetime(2026, 10, 15, 11, 0, 0)
    eid = 3000

    # 1. Normal user activity from normal workstation 192.168.1.45
    curr_time = base_time
    for i in range(15):
        curr_time += timedelta(seconds=random.randint(60, 180))
        events.append(make_event(
            f"CL-{eid}", curr_time,
            source="auth.log", event_type="login_success",
            source_ip="192.168.1.45", dest_ip="192.168.1.60",
            source_port=random.randint(50000, 60000), dest_port=22,
            username="mrodriguez", hostname="srv-workstation-09", process="sshd",
            action="success", severity="low",
            raw_message="Session opened for user mrodriguez by (uid=1003)"
        ))
        eid += 1

    # 2. Suspicious access attempts from unusual internal subnet 10.0.0.120 (e.g. unauthorized VPN)
    curr_time = datetime(2026, 10, 15, 11, 45, 0)
    for i in range(5):
        curr_time += timedelta(seconds=random.randint(5, 15))
        events.append(make_event(
            f"CL-{eid}", curr_time,
            source="auth.log", event_type="login_failed",
            source_ip="10.0.0.120", dest_ip="192.168.1.60",
            source_port=random.randint(45000, 48000), dest_port=22,
            username="mrodriguez", hostname="srv-workstation-09", process="sshd",
            action="failure", severity="medium",
            raw_message="Failed password for mrodriguez from 10.0.0.120 port 45102 ssh2"
        ))
        eid += 1

    # 3. Successful login from unusual source IP
    curr_time += timedelta(seconds=12)
    events.append(make_event(
        f"CL-{eid}", curr_time,
        source="auth.log", event_type="login_success",
        source_ip="10.0.0.120", dest_ip="192.168.1.60",
        source_port=45110, dest_port=22,
        username="mrodriguez", hostname="srv-workstation-09", process="sshd",
        action="success", severity="high",
        raw_message="Accepted password for mrodriguez from 10.0.0.120 port 45110 ssh2 [UNUSUAL_GEO]"
    ))
    eid += 1

    # 4. Suspicious commands in that session
    suspicious_cmds = [
        ("whoami", "session_enum"),
        ("id", "session_enum"),
        ("cat /etc/passwd", "file_read"),
        ("netstat -antup", "network_recon"),
        ("find / -perm -4000 2>/dev/null", "privilege_recon"),
        ("cat ~/.ssh/id_rsa", "credential_access"),
        ("ls -la /var/log", "recon"),
    ]
    for cmd, etype in suspicious_cmds:
        curr_time += timedelta(seconds=random.randint(8, 25))
        events.append(make_event(
            f"CL-{eid}", curr_time,
            source="audit.log", event_type=etype,
            source_ip="10.0.0.120", dest_ip="192.168.1.60",
            source_port=45110, dest_port=22,
            username="mrodriguez", hostname="srv-workstation-09", process="bash",
            action="executed", severity="medium",
            raw_message=f"EXECVE: cmd='{cmd}' uid=1003(mrodriguez)"
        ))
        eid += 1

    # 5. Background noise of normal users continuing
    for i in range(25):
        curr_time += timedelta(seconds=random.randint(40, 100))
        events.append(make_event(
            f"CL-{eid}", curr_time,
            source="syslog", event_type="cron_job",
            source_ip="192.168.1.60", dest_ip="192.168.1.60",
            source_port=0, dest_port=0,
            username="root", hostname="srv-workstation-09", process="crond",
            action="success", severity="low",
            raw_message="CROND[1420]: (root) CMD (/usr/lib64/sa/sa1 1 1)"
        ))
        eid += 1

    return events


def generate_privilege_escalation_dataset():
    """
    Scenario 4: Privilege Escalation
    Target: ~70 events total
    """
    events = []
    base_time = datetime(2026, 10, 15, 13, 0, 0)
    eid = 4000

    # 1. Normal user activity on database server
    curr_time = base_time
    for i in range(20):
        curr_time += timedelta(seconds=random.randint(30, 90))
        events.append(make_event(
            f"PE-{eid}", curr_time,
            source="audit.log", event_type="db_query",
            source_ip="192.168.1.48", dest_ip="192.168.1.15",
            source_port=random.randint(50000, 60000), dest_port=5432,
            username="bchen", hostname="srv-db-01", process="postgres",
            action="query", severity="low",
            raw_message="SELECT * FROM inventory WHERE status='active'"
        ))
        eid += 1

    # 2. Suspicious command / privilege enumeration
    curr_time = datetime(2026, 10, 15, 13, 40, 0)
    commands = [
        ("sudo -l", "sudo_enum", "audit.log", "sudo", "executed", "medium", "sudo: bchen: list privileges"),
        ("cat /etc/sudoers.d/*", "config_read", "audit.log", "cat", "read", "medium", "read /etc/sudoers.d/custom"),
        ("sudo /usr/bin/find . -exec /bin/sh \\;", "privilege_escalation_attempt", "audit.log", "sudo", "elevate", "high", "sudo: bchen : TTY=pts/1 ; COMMAND=/usr/bin/find . -exec /bin/sh ;"),
    ]
    for cmd, etype, src, proc, act, sev, msg in commands:
        curr_time += timedelta(seconds=random.randint(10, 20))
        events.append(make_event(
            f"PE-{eid}", curr_time,
            source=src, event_type=etype,
            source_ip="192.168.1.48", dest_ip="192.168.1.15",
            source_port=52110, dest_port=22,
            username="bchen", hostname="srv-db-01", process=proc,
            action=act, severity=sev,
            raw_message=msg
        ))
        eid += 1

    # 3. Privilege Escalation Success: UID transitions to root
    curr_time += timedelta(seconds=5)
    events.append(make_event(
        f"PE-{eid}", curr_time,
        source="audit.log", event_type="privilege_change",
        source_ip="192.168.1.48", dest_ip="192.168.1.15",
        source_port=52110, dest_port=22,
        username="root", hostname="srv-db-01", process="sh",
        action="elevated", severity="critical",
        raw_message="Privilege change: uid changed from 1002(bchen) to 0(root)"
    ))
    eid += 1

    # 4. Privileged actions executed as root
    root_actions = [
        ("cat /etc/shadow", "sensitive_read", "shadow file read by root"),
        ("useradd -m -s /bin/bash sysback", "persistence", "new user sysback created"),
        ("usermod -aG sudo sysback", "persistence", "user sysback added to group sudo"),
        ("touch /root/.ssh/authorized_keys", "file_modify", "root authorized_keys modified"),
    ]
    for act_name, etype, msg in root_actions:
        curr_time += timedelta(seconds=random.randint(15, 30))
        events.append(make_event(
            f"PE-{eid}", curr_time,
            source="audit.log", event_type=etype,
            source_ip="192.168.1.48", dest_ip="192.168.1.15",
            source_port=52110, dest_port=22,
            username="root", hostname="srv-db-01", process="bash",
            action="executed", severity="high",
            raw_message=f"Root command executed: {msg}"
        ))
        eid += 1

    # 5. Background noise of system monitoring
    for i in range(25):
        curr_time += timedelta(seconds=random.randint(30, 80))
        events.append(make_event(
            f"PE-{eid}", curr_time,
            source="syslog", event_type="health_check",
            source_ip="192.168.1.15", dest_ip="192.168.1.15",
            source_port=0, dest_port=0,
            username="system", hostname="srv-db-01", process="systemd",
            action="status", severity="low",
            raw_message="systemd[1]: Started PostgreSQL Database Server."
        ))
        eid += 1

    return events


def generate_data_exfiltration_dataset():
    """
    Scenario 5: Data Exfiltration
    Target: ~70 events total
    """
    events = []
    base_time = datetime(2026, 10, 15, 14, 0, 0)
    eid = 5000

    # 1. Normal file server access
    curr_time = base_time
    for i in range(20):
        curr_time += timedelta(seconds=random.randint(40, 120))
        events.append(make_event(
            f"DX-{eid}", curr_time,
            source="file_audit", event_type="file_access",
            source_ip="192.168.1.70", dest_ip="192.168.1.25",
            source_port=random.randint(50000, 60000), dest_port=445,
            username="dpatel", hostname="srv-files-01", process="smbd",
            action="read", severity="low",
            raw_message="Read access granted to share /public/templates/meeting_notes.docx"
        ))
        eid += 1

    # 2. Sensitive file access
    curr_time = datetime(2026, 10, 15, 14, 45, 0)
    sensitive_files = [
        "/confidential/finance/q4_earnings_draft.xlsx",
        "/confidential/hr/employee_ssn_records.csv",
        "/confidential/intellectual_property/patents_2026.pdf",
        "/confidential/database_backups/customer_pii.sql",
    ]
    for sf in sensitive_files:
        curr_time += timedelta(seconds=random.randint(10, 25))
        events.append(make_event(
            f"DX-{eid}", curr_time,
            source="file_audit", event_type="sensitive_file_read",
            source_ip="192.168.1.70", dest_ip="192.168.1.25",
            source_port=random.randint(50000, 60000), dest_port=445,
            username="dpatel", hostname="srv-files-01", process="smbd",
            action="read", severity="medium",
            raw_message=f"Access granted to restricted share file {sf}"
        ))
        eid += 1

    # 3. Archiving / compressing files
    curr_time += timedelta(seconds=20)
    events.append(make_event(
        f"DX-{eid}", curr_time,
        source="audit.log", event_type="file_archive",
        source_ip="192.168.1.70", dest_ip="192.168.1.70",
        source_port=0, dest_port=0,
        username="dpatel", hostname="workstation-70", process="tar",
        action="created", severity="medium",
        raw_message="tar -czvf /tmp/staging_archive.tar.gz /mnt/shares/confidential/*"
    ))
    eid += 1

    # 4. Exfiltration: large outbound data transfer to internal staging/drop box 10.0.0.95
    curr_time += timedelta(seconds=35)
    for chunk in range(5):
        curr_time += timedelta(seconds=15)
        events.append(make_event(
            f"DX-{eid}", curr_time,
            source="firewall", event_type="large_outbound_transfer",
            source_ip="192.168.1.70", dest_ip="10.0.0.95",
            source_port=random.randint(55000, 56000), dest_port=8443,
            username="dpatel", hostname="fw-core-01", process="curl",
            action="allowed", severity="high",
            raw_message=f"FIREWALL PASS: High volume outbound stream proto=TCP bytes={random.randint(120000000, 150000000)} dst=10.0.0.95:8443"
        ))
        eid += 1

    # 5. Background normal network traffic
    for i in range(25):
        curr_time += timedelta(seconds=random.randint(30, 90))
        events.append(make_event(
            f"DX-{eid}", curr_time,
            source="firewall", event_type="network_flow",
            source_ip="192.168.1.33", dest_ip="192.168.1.10",
            source_port=random.randint(40000, 60000), dest_port=443,
            username="", hostname="fw-core-01", process="kernel",
            action="allowed", severity="low",
            raw_message="FIREWALL PASS: proto=TCP src=192.168.1.33 dst=192.168.1.10:443 bytes=1240"
        ))
        eid += 1

    return events


def generate_combined_attack_dataset():
    """
    Scenario 6: Combined Attack (The Master Multi-Stage Incident)
    Target: ~220-250 events total
    Combines:
      - 100+ background normal activities across multiple hosts/users
      - Attack stage 1: Repeated failed logins from 192.168.1.188 to 192.168.1.12
      - Attack stage 2: Successful login for svc_admin from 192.168.1.188
      - Attack stage 3: Suspicious shell session and privilege escalation
      - Attack stage 4: Sensitive file access & aggregation
      - Attack stage 5: Large outbound exfiltration to 10.0.0.250:443
    """
    events = []
    base_time = datetime(2026, 10, 16, 8, 0, 0)
    eid = 6000

    # Common entities in the attack
    attacker_ip = "192.168.1.188"
    victim_host = "srv-app-prod"
    victim_ip = "192.168.1.12"
    compromised_user = "svc_admin"
    exfil_dest_ip = "10.0.0.250"

    benign_pool = [
        ("dev_user1", "192.168.1.51", "srv-git-01", "192.168.1.14", 22, "git"),
        ("qa_tester", "192.168.1.52", "srv-app-prod", "192.168.1.12", 80, "nginx"),
        ("hr_clerk", "192.168.1.53", "srv-files-01", "192.168.1.25", 445, "smbd"),
        ("monitoring", "192.168.1.10", "srv-app-prod", "192.168.1.12", 9100, "node_exporter"),
        ("backup_svc", "192.168.1.15", "srv-backup", "192.168.1.99", 22, "rsync"),
    ]

    curr_time = base_time

    # Part A: Background traffic from 08:00 to 09:00 (50 events)
    for _ in range(50):
        curr_time += timedelta(seconds=random.randint(40, 110))
        u, src_ip, hname, dst_ip, dport, proc = random.choice(benign_pool)
        events.append(make_event(
            f"CA-{eid}", curr_time,
            source="auth.log" if dport == 22 else "syslog",
            event_type="routine_access",
            source_ip=src_ip, dest_ip=dst_ip,
            source_port=random.randint(40000, 60000), dest_port=dport,
            username=u, hostname=hname, process=proc,
            action="success" if dport == 22 else "allowed", severity="low",
            raw_message=f"Normal service connection from {src_ip} to {dst_ip}:{dport} ({proc})"
        ))
        eid += 1

    # Part B: Attack Stage 1 - Brute Force (09:10:00 to 09:14:00) (35 failed logins)
    curr_time = datetime(2026, 10, 16, 9, 10, 0)
    for i in range(35):
        curr_time += timedelta(seconds=random.randint(4, 9))
        sport = 41000 + i
        events.append(make_event(
            f"CA-{eid}", curr_time,
            source="auth.log", event_type="login_failed",
            source_ip=attacker_ip, dest_ip=victim_ip,
            source_port=sport, dest_port=22,
            username=compromised_user, hostname=victim_host, process="sshd",
            action="failure", severity="medium",
            raw_message=f"Failed password for user {compromised_user} from {attacker_ip} port {sport} ssh2"
        ))
        eid += 1

        # Interweave background event occasionally
        if i % 3 == 0:
            events.append(make_event(
                f"CA-{eid}", curr_time + timedelta(seconds=1),
                source="firewall", event_type="network_flow",
                source_ip="192.168.1.52", dest_ip="192.168.1.12",
                source_port=52340, dest_port=80,
                username="qa_tester", hostname="fw-core-01", process="nginx",
                action="allowed", severity="low",
                raw_message="FIREWALL PASS: HTTP GET /index.html 200 OK"
            ))
            eid += 1

    # Part C: Attack Stage 2 - Successful Compromised Login (09:15:02)
    curr_time += timedelta(seconds=15)
    events.append(make_event(
        f"CA-{eid}", curr_time,
        source="auth.log", event_type="login_success",
        source_ip=attacker_ip, dest_ip=victim_ip,
        source_port=41036, dest_port=22,
        username=compromised_user, hostname=victim_host, process="sshd",
        action="success", severity="high",
        raw_message=f"Accepted password for {compromised_user} from {attacker_ip} port 41036 ssh2"
    ))
    eid += 1

    # Interweave some benign events (10 events)
    for _ in range(10):
        curr_time += timedelta(seconds=random.randint(15, 30))
        u, src_ip, hname, dst_ip, dport, proc = random.choice(benign_pool)
        events.append(make_event(
            f"CA-{eid}", curr_time,
            source="syslog", event_type="routine_access",
            source_ip=src_ip, dest_ip=dst_ip,
            source_port=random.randint(40000, 60000), dest_port=dport,
            username=u, hostname=hname, process=proc,
            action="allowed", severity="low",
            raw_message=f"Normal background activity for user {u}"
        ))
        eid += 1

    # Part D: Attack Stage 3 - Privilege Escalation (09:22:00)
    curr_time = datetime(2026, 10, 16, 9, 22, 0)
    priv_commands = [
        ("sudo -l", "sudo_enum", "svc_admin", "audit.log", "sudo", "executed", "medium", "sudo: svc_admin: list allowed commands"),
        ("cat /etc/sudoers", "file_read", "svc_admin", "audit.log", "cat", "read", "medium", "read /etc/sudoers file"),
        ("sudo /usr/bin/bash", "privilege_escalation_attempt", "svc_admin", "audit.log", "sudo", "elevate", "high", "sudo /usr/bin/bash executed by svc_admin"),
        ("privilege change to root", "privilege_change", "root", "audit.log", "bash", "elevated", "critical", "Privilege transition: uid changed from 1005(svc_admin) to 0(root)"),
    ]
    for cmd, etype, user, src, proc, act, sev, msg in priv_commands:
        curr_time += timedelta(seconds=random.randint(10, 25))
        events.append(make_event(
            f"CA-{eid}", curr_time,
            source=src, event_type=etype,
            source_ip=attacker_ip, dest_ip=victim_ip,
            source_port=41036, dest_port=22,
            username=user, hostname=victim_host, process=proc,
            action=act, severity=sev,
            raw_message=msg
        ))
        eid += 1

    # Interweave background events (15 events)
    for _ in range(15):
        curr_time += timedelta(seconds=random.randint(20, 45))
        u, src_ip, hname, dst_ip, dport, proc = random.choice(benign_pool)
        events.append(make_event(
            f"CA-{eid}", curr_time,
            source="syslog", event_type="routine_access",
            source_ip=src_ip, dest_ip=dst_ip,
            source_port=random.randint(40000, 60000), dest_port=dport,
            username=u, hostname=hname, process=proc,
            action="allowed", severity="low",
            raw_message=f"Routine health probe on {hname}"
        ))
        eid += 1

    # Part E: Attack Stage 4 - Sensitive File Access & Collection (09:35:00)
    curr_time = datetime(2026, 10, 16, 9, 35, 0)
    files_to_read = [
        "/etc/shadow",
        "/var/www/html/config/database.php",
        "/opt/app/keys/jwt_private_key.pem",
        "/var/data/customer_accounts_export.csv",
    ]
    for f in files_to_read:
        curr_time += timedelta(seconds=random.randint(8, 20))
        events.append(make_event(
            f"CA-{eid}", curr_time,
            source="audit.log", event_type="sensitive_file_read",
            source_ip=attacker_ip, dest_ip=victim_ip,
            source_port=41036, dest_port=22,
            username="root", hostname=victim_host, process="cat",
            action="read", severity="high",
            raw_message=f"AUDIT_READ: root accessed sensitive file {f}"
        ))
        eid += 1

    # File Archive
    curr_time += timedelta(seconds=18)
    events.append(make_event(
        f"CA-{eid}", curr_time,
        source="audit.log", event_type="file_archive",
        source_ip=attacker_ip, dest_ip=victim_ip,
        source_port=41036, dest_port=22,
        username="root", hostname=victim_host, process="tar",
        action="created", severity="medium",
        raw_message="tar -czvf /tmp/exfil_bundle.tar.gz /var/data/customer_accounts_export.csv /opt/app/keys/"
    ))
    eid += 1

    # Part F: Attack Stage 5 - Large Outbound Transfer / Exfiltration (09:48:00)
    curr_time = datetime(2026, 10, 16, 9, 48, 0)
    for chunk in range(6):
        curr_time += timedelta(seconds=12)
        events.append(make_event(
            f"CA-{eid}", curr_time,
            source="firewall", event_type="large_outbound_transfer",
            source_ip=victim_ip, dest_ip=exfil_dest_ip,
            source_port=random.randint(52000, 53000), dest_port=443,
            username="root", hostname="fw-core-01", process="curl",
            action="allowed", severity="critical",
            raw_message=f"FIREWALL PASS: High volume outbound stream proto=TCP bytes={random.randint(200000000, 250000000)} dst={exfil_dest_ip}:443"
        ))
        eid += 1

    # Part G: Post-attack background traffic (40 events)
    for _ in range(40):
        curr_time += timedelta(seconds=random.randint(30, 90))
        u, src_ip, hname, dst_ip, dport, proc = random.choice(benign_pool)
        events.append(make_event(
            f"CA-{eid}", curr_time,
            source="syslog", event_type="routine_access",
            source_ip=src_ip, dest_ip=dst_ip,
            source_port=random.randint(40000, 60000), dest_port=dport,
            username=u, hostname=hname, process=proc,
            action="allowed", severity="low",
            raw_message=f"Standard background communication for {u} on {hname}"
        ))
        eid += 1

    # Sort all events chronologically so it's a realistic interleaved stream
    events.sort(key=lambda x: x["timestamp"])
    return events


def generate_normal_activity_dataset():
    """
    Normal Activity (Baseline) Dataset
    Target: ~120-150 pure benign events
    No attacks, no brute force, no unusual privileges, no large abnormal transfers.
    """
    events = []
    base_time = datetime(2026, 10, 17, 9, 0, 0)
    eid = 7000

    users_and_workstations = [
        ("arun", "192.168.1.101", "ws-finance-01"),
        ("priya", "192.168.1.102", "ws-hr-02"),
        ("vikram", "192.168.1.103", "ws-eng-03"),
        ("sneha", "192.168.1.104", "ws-eng-04"),
        ("admin_rohit", "192.168.1.105", "ws-it-01"),
    ]

    destinations = [
        ("192.168.1.10", 443, "srv-intranet", "web_access", "nginx", "allowed", "HTTP GET /portal 200 OK"),
        ("192.168.1.11", 53, "srv-dns-01", "dns_query", "named", "resolved", "DNS query A record mail.corp.local"),
        ("192.168.1.20", 22, "srv-bastion", "login_success", "sshd", "success", "Accepted publickey for admin_rohit"),
        ("192.168.1.25", 445, "srv-fileshare", "file_read", "smbd", "read", "Read document /general/company_policy.pdf"),
        ("192.168.1.15", 5432, "srv-reporting", "db_query", "postgres", "query", "SELECT report_id, status FROM daily_reports"),
    ]

    curr_time = base_time
    for i in range(130):
        curr_time += timedelta(seconds=random.randint(15, 60))
        u, src_ip, ws = random.choice(users_and_workstations)
        dst_ip, dport, dst_host, etype, proc, act, msg = random.choice(destinations)

        events.append(make_event(
            f"NORM-{eid}", curr_time,
            source="auth.log" if dport == 22 else ("firewall" if dport in [53, 443] else "syslog"),
            event_type=etype,
            source_ip=src_ip, dest_ip=dst_ip,
            source_port=random.randint(49152, 65535), dest_port=dport,
            username=u, hostname=ws, process=proc,
            action=act, severity="low",
            raw_message=f"{msg} (user={u})"
        ))
        eid += 1

    return events


def write_csv(filename, events):
    filepath = os.path.join(DATA_DIR, filename)
    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SCHEMA_COLUMNS)
        writer.writeheader()
        writer.writerows(events)
    print(f"Generated {filename}: {len(events)} rows")


def main():
    os.makedirs(DATA_DIR, exist_ok=True)

    print("Generating synthetic datasets...")
    write_csv("brute_force.csv", generate_brute_force_dataset())
    write_csv("port_scan.csv", generate_port_scan_dataset())
    write_csv("compromised_login.csv", generate_compromised_login_dataset())
    write_csv("privilege_escalation.csv", generate_privilege_escalation_dataset())
    write_csv("data_exfiltration.csv", generate_data_exfiltration_dataset())
    write_csv("combined_attack.csv", generate_combined_attack_dataset())
    write_csv("normal_activity.csv", generate_normal_activity_dataset())
    print("All datasets generated successfully!")

if __name__ == "__main__":
    main()
