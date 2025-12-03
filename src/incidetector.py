#!/usr/bin/env python3
"""
Made By Noah Grennan
incidetector.py - Incident Detection Tool (SIEM)
Cross-platform. Made for IT360
Outputs: raw_logs, snapshots, alerts.csv, alerts.json, report.json, report.html

Usage (recommended elevated):
  python3 incidetector.py
  python3 incidetector.py --days 7 --output ./evidence

Notes:
 - On Linux run with sudo to access system logs and journalctl.

"""

import os, sys, re, json, csv, shutil, subprocess, argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import platform
import hashlib

# optional third-party imports
try:
    import psutil
except Exception:
    psutil = None

# -------------------------
# Config
# -------------------------
DEFAULT_DAYS = 7
OUTPUT_BASE = "incidetector_output"
TIME_NOW = datetime.now(timezone.utc)

# detection rules: (compiled_regex, id, severity (1-10), human message)
DETECTION_RULES = [
    (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"), "failed_ssh", 8, "Failed SSH login"),
    (re.compile(r"authentication failure; .* rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)"), "auth_fail", 8, "Authentication failure (PAM)"),
    (re.compile(r"Failed login for user (?P<user>\S+)"), "failed_win_login", 8, "Failed Windows login"),
    (re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"), "success_ssh", 3, "Successful SSH login"),
    (re.compile(r"New user (?P<user>\S+)"), "new_user_generic", 9, "New user created"),
    (re.compile(r"useradd\["), "useradd", 9, "useradd executed"),
    (re.compile(r"adduser\["), "adduser", 9, "adduser executed"),
    (re.compile(r"sudo: .*COMMAND=(?P<cmd>.+)"), "sudo", 7, "Sudo command executed"),
    (re.compile(r"CRON\[[0-9]+\]: \((?P<user>.+?)\) CMD \((?P<cmd>.+)\)"), "cron_cmd", 5, "Cron job executed"),
    (re.compile(r"apt: .* install "), "apt_install", 6, "APT package install"),
    (re.compile(r"dpkg: installed (?P<pkg>\S+)"), "dpkg_installed", 6, "Package installed (dpkg)"),
    (re.compile(r"systemd\[\d+\]: Started (?P<svc>.+)"), "svc_started", 6, "Service started (systemd)"),
    (re.compile(r"kernel: .*panic", re.I), "kernel_panic", 10, "Kernel panic"),
    (re.compile(r"Out of memory", re.I), "oom", 10, "Out of memory"),
    (re.compile(r"usb .*: New USB device found", re.I), "usb_connect", 4, "USB device connected"),
    (re.compile(r"Mounted filesystem .* on /media", re.I), "media_mount", 4, "Media mounted"),
    (re.compile(r"An account failed to log on", re.I), "win_failed_login", 8, "Windows failed logon"),
    (re.compile(r"Audit Failure", re.I), "win_audit_failure", 7, "Windows Audit Failure"),
]

# critical files to hash (platform-specific)
CRITICAL_FILES = {
    "Linux": ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/ssh/sshd_config"],
    "Darwin": ["/etc/passwd", "/etc/hosts", "/etc/ssh/sshd_config"],
    "Windows": [r"C:\Windows\System32\drivers\etc\hosts"]
}

# log files to check by OS
LOG_PATHS = {
    "Linux": [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/kern.log",
        "/var/log/dpkg.log",
        "/var/log/apt/history.log"
    ],
    "Darwin": [
        "/var/log/system.log",
        "/var/log/kernel.log"
    ],
    "Windows": [
        # Windows will be collected via PowerShell Get-WinEvent or wevtutil
    ]
}

# -------------------------
# Helpers
# -------------------------
def now_utc_iso():
    return datetime.now(timezone.utc).isoformat()

def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def safe_read(path):
    try:
        return Path(path).read_text(errors="ignore")
    except Exception:
        # attempt sudo cat (Linux)
        try:
            p = subprocess.run(["sudo", "cat", path], capture_output=True, text=True, timeout=8)
            return p.stdout
        except Exception:
            return ""

def save_text(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(content)

# timestamp heuristic: parse "Dec  3 14:55:02" style
MONTHS = {m:i+1 for i,m in enumerate(["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"])}
TS_REGEX = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})")

def extract_ts(line):
    m = TS_REGEX.match(line)
    if not m:
        # fallback: find ISO-like timestamp
        iso = re.search(r"(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
        if iso:
            try:
                dt = datetime.fromisoformat(iso.group("iso"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                return None
        return None
    try:
        mon = MONTHS.get(m.group("mon"),1)
        day = int(m.group("day"))
        hour = int(m.group("hour")); minute = int(m.group("min")); sec = int(m.group("sec"))
        year = datetime.now().year
        return datetime(year, mon, day, hour, minute, sec, tzinfo=timezone.utc)
    except Exception:
        return None

# -------------------------
# Log collection by OS
# -------------------------
def collect_linux_logs(out_raw_dir, cutoff_iso):
    checked = []
    for p in LOG_PATHS.get("Linux", []):
        fp = Path(p)
        if fp.exists():
            content = safe_read(str(fp))
            save_text(out_raw_dir / fp.name, content)
            checked.append(str(fp))
    # journalctl
    try:
        res = subprocess.run(["journalctl", "--since", cutoff_iso, "--no-pager"], capture_output=True, text=True, timeout=20)
        if res.returncode == 0 and res.stdout:
            save_text(out_raw_dir / "journalctl.txt", res.stdout)
            checked.append("journalctl")
    except Exception:
        pass
    return checked

def collect_macos_logs(out_raw_dir, cutoff_iso):
    checked = []
    for p in LOG_PATHS.get("Darwin", []):
        fp = Path(p)
        if fp.exists():
            content = safe_read(str(fp))
            save_text(out_raw_dir / fp.name, content)
            checked.append(str(fp))
    # unified logging
    try:
        res = subprocess.run(["log", "show", "--style", "syslog", "--start", cutoff_iso], capture_output=True, text=True, timeout=25)
        if res.returncode == 0 and res.stdout:
            save_text(out_raw_dir / "log_show.txt", res.stdout)
            checked.append("log_show")
    except Exception:
        pass
    return checked

def collect_windows_logs(out_raw_dir, cutoff_iso):
    checked = []
    # Use PowerShell Get-WinEvent
    ps_cmds = [
        'Get-WinEvent -LogName Security -MaxEvents 2000 | Format-List | Out-String -Width 4096',
        'Get-WinEvent -LogName System -MaxEvents 1000 | Format-List | Out-String -Width 4096',
        'Get-WinEvent -LogName Application -MaxEvents 500 | Format-List | Out-String -Width 4096'
    ]
    for i, cmd in enumerate(ps_cmds):
        try:
            completed = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=30)
            if completed.returncode == 0 and completed.stdout:
                fn = out_raw_dir / f"windows_evt_{i}.txt"
                save_text(fn, completed.stdout)
                checked.append(f"windows_evt_{i}")
        except Exception:
            # fallback to wevtutil
            try:
                out = subprocess.run(["wevtutil", "qe", "Security", "/c:1000", "/f:text"], capture_output=True, text=True, timeout=30)
                if out.returncode == 0 and out.stdout:
                    save_text(out_raw_dir / "wevtutil_security.txt", out.stdout)
                    checked.append("wevtutil_security")
            except Exception:
                pass
    return checked

# -------------------------
# Snapshot collectors
# -------------------------
def collect_snapshot(out_snap_dir):
    out_snap_dir.mkdir(parents=True, exist_ok=True)
    snap = {}
    try:
        snap['hostname'] = platform.node()
        snap['platform'] = platform.platform()
        snap['time'] = now_utc_iso()
        # users (Linux/Mac)
        if psutil:
            try:
                snap['users'] = [u.name for u in psutil.users()]
            except Exception:
                snap['users'] = []
        else:
            # minimal fallback
            snap['users'] = []
        # processes
        if psutil:
            procs = []
            for p in psutil.process_iter(["pid","name","exe","cmdline","username"]):
                try:
                    info = p.info
                    procs.append(info)
                except Exception:
                    pass
            snap['processes_count'] = len(procs)
            save_text(out_snap_dir / "processes.json", json.dumps(procs, indent=2))
        else:
            # fallback using ps / tasklist
            try:
                if platform.system() == "Windows":
                    res = subprocess.run(["tasklist"], capture_output=True, text=True)
                    save_text(out_snap_dir / "tasklist.txt", res.stdout)
                else:
                    res = subprocess.run(["ps","aux"], capture_output=True, text=True)
                    save_text(out_snap_dir / "ps_aux.txt", res.stdout)
            except Exception:
                pass
        # network (psutil)
        if psutil:
            try:
                conns = []
                for c in psutil.net_connections(kind='inet'):
                    conns.append({
                        "fd": c.fd, "family": str(c.family), "type": str(c.type),
                        "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                        "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                        "status": c.status, "pid": c.pid
                    })
                save_text(out_snap_dir / "connections.json", json.dumps(conns, indent=2))
            except Exception:
                pass
        else:
            # fallback netstat/ss
            try:
                if shutil.which("ss"):
                    res = subprocess.run(["ss","-tupna"], capture_output=True, text=True)
                    save_text(out_snap_dir / "ss.txt", res.stdout)
                else:
                    res = subprocess.run(["netstat","-tupan"], capture_output=True, text=True)
                    save_text(out_snap_dir / "netstat.txt", res.stdout)
            except Exception:
                pass
    except Exception as e:
        print("[!] Snapshot error:", e)
    return

# -------------------------
# Detection engine
# -------------------------
def scan_text_for_alerts(text, source, cutoff_dt, alerts, raw_examples):
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        # skip empty
        if not line.strip():
            continue
        ts = extract_ts(line)
        if ts and ts < cutoff_dt:
            continue
        for regex, rid, sev, msg in DETECTION_RULES:
            m = regex.search(line)
            if m:
                details = m.groupdict() if hasattr(m, "groupdict") else {}
                alert = {
                    "rule_id": rid,
                    "severity": sev,
                    "message": msg,
                    "source": source,
                    "line_number": i,
                    "raw_line": line.strip(),
                    "details": details,
                    "timestamp": ts.isoformat() if ts else None
                }
                alerts.append(alert)
                raw_examples.append({"source": source, "line_number": i, "line": line.strip()})
    return

# -------------------------
# Report generation
# -------------------------
HTML_TEMPLATE = """
<html>
<head>
<title>Incident Detection Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #f5f5f5;
}}
h1 {{
    background: #333;
    color: white;
    padding: 10px;
    text-align: center;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
}}
th, td {{
    border: 1px solid #ccc;
    padding: 8px;
}}
th {{
    background: #444;
    color: white;
}}
</style>
</head>
<body>
<h1>Incident Detection Report</h1>

<p><b>Collected At:</b> {collected}</p>
<p><b>Incident Types:</b> {types}</p>
<p><b>Total Alerts:</b> {total}</p>

<h2>Alerts</h2>
<table>
<tr><th>Type</th><th>Details</th><th>Timestamp</th></tr>
{rows}
</table>

<h2>Log Excerpts</h2>
<pre>
{examples}
</pre>

</body>
</html>
"""


def generate_html_report(report, out_html):
    # build summary rows
    rows_html = ""
    for item in report.get("alert_summary", []):
        ex = item["examples"][0]["raw_line"] if item["examples"] else ""
        rows_html += f"<tr><td>{item['rule_id']}</td><td>{item['severity']}</td><td>{item['count']}</td><td>{ex}</td></tr>\n"
    examples_text = "\n".join([f"{r['source']}:{r['line']}" for r in report.get("raw_examples", [])[:200]])
    html = HTML_TEMPLATE.format(collected=report.get("collected_at"), types=len(report.get("alert_summary",[])), total=report.get("alert_count",0), rows=rows_html, examples=examples_text)
    save_text(out_html, html)
    return

# -------------------------
# Orchestration & CLI
# -------------------------
def run_incident_detector(output_dir: Path, days=DEFAULT_DAYS):
    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days)
    cutoff_iso = cutoff_dt.isoformat()
    out_raw = output_dir / "raw_logs"
    out_snap = output_dir / "snapshots"
    out_raw.mkdir(parents=True, exist_ok=True)
    out_snap.mkdir(parents=True, exist_ok=True)

    system = platform.system()
    checked = []
    alerts = []
    raw_examples = []

    print("[*] Collecting logs for OS:", system)
    if system == "Linux":
        checked = collect_linux_logs(out_raw, cutoff_iso)
    elif system == "Darwin":
        checked = collect_macos_logs(out_raw, cutoff_iso)
    elif system == "Windows":
        checked = collect_windows_logs(out_raw, cutoff_iso)
    else:
        print("[!] Unsupported OS:", system)

    # scan all raw logs
    for f in out_raw.iterdir():
        try:
            txt = f.read_text(errors="ignore")
            scan_text_for_alerts(txt, str(f.name), cutoff_dt, alerts, raw_examples)
        except Exception:
            pass

    # collect snapshot
    print("[*] Collecting snapshot (processes, network)...")
    collect_snapshot(out_snap)

    # hash critical files
    print("[*] Hashing critical files...")
    file_hashes = []
    cfiles = CRITICAL_FILES.get(system, [])
    for cf in cfiles:
        if Path(cf).exists():
            h = sha256(cf)
            file_hashes.append({"path": cf, "sha256": h})
        else:
            file_hashes.append({"path": cf, "sha256": None, "missing": True})

    # aggregate alerts by rule
    agg = {}
    for a in alerts:
        k = a["rule_id"]
        entry = agg.setdefault(k, {"rule_id": k, "message": a["message"], "severity": a["severity"], "count": 0, "examples": []})
        entry["count"] += 1
        if len(entry["examples"]) < 5:
            entry["examples"].append({"timestamp": a.get("timestamp"), "raw_line": a["raw_line"], "source": a["source"]})
    agg_list = sorted(list(agg.values()), key=lambda x: (x["severity"]*x["count"]), reverse=True)

    # build report object
    report = {
        "collected_at": now_utc_iso(),
        "os": system,
        "days": days,
        "checked_logs": checked,
        "alert_count": len(alerts),
        "alert_summary": agg_list,
        "raw_examples": raw_examples,
        "file_hashes": file_hashes
    }

    # save outputs
    save_text(output_dir / "alerts.json", json.dumps(alerts, indent=2))
    save_text(output_dir / "raw_examples.json", json.dumps(raw_examples, indent=2))
    save_text(output_dir / "report.json", json.dumps(report, indent=2))

    # save CSV summary
    csv_path = output_dir / "alerts.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow(["rule_id", "severity", "message", "count", "example"])
        for it in agg_list:
            ex = it["examples"][0]["raw_line"] if it["examples"] else ""
            writer.writerow([it["rule_id"], it["severity"], it["message"], it["count"], ex])

    # generate HTML overview
    generate_html_report(report, output_dir / "report.html")

    print(f"[+] Done. outputs in: {output_dir}")
    print(f"[+] Summary: {len(agg_list)} alert types, {len(alerts)} total matches")
    return report

def parse_args():
    p = argparse.ArgumentParser(description="IncidentDetector - Host-level incident detection toolkit")
    p.add_argument("--days", type=int, default=7, help="How many days back to analyze (default 7)")
    p.add_argument("--output", default=OUTPUT_BASE, help="Output folder")
    return p.parse_args()

def main():
    args = parse_args()
    out = Path(args.output).resolve()
    if out.exists():
        out = Path(str(out) + "_" + datetime.now().strftime("%Y%m%d%H%M%S"))
    out.mkdir(parents=True, exist_ok=True)
    print("[*] IncidentDetector starting")
    print(f"[*] Output -> {out}")
    run_incident_detector(out, days=args.days)

if __name__ == "__main__":
    main()
