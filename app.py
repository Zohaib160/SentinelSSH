import re
import sqlite3
import subprocess
from datetime import datetime
from collections import defaultdict
import requests
from flask import Flask, render_template_string

app = Flask(__name__)
DB_PATH = "security_events.db"
LOG_FILE = "test_auth.log"
THRESHOLD = 5          # Max failed attempts allowed
WINDOW_SECONDS = 60    # Time window in seconds
DRY_RUN = True         # Set False on Linux root VM to execute real iptables commands

# Regex pattern to extract Timestamp, Username, and Source IP from Linux sshd logs
SSH_FAIL_REGEX = re.compile(
    r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                target_user TEXT,
                attempts INTEGER,
                country TEXT,
                isp TEXT,
                firewall_rule TEXT,
                blocked_at TEXT
            )
        """)

def get_geoip(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp", timeout=3).json()
        if res.get("status") == "success":
            return res.get("country", "Unknown"), res.get("isp", "Unknown")
    except Exception:
        pass
    return "Unknown", "Unknown"

def enforce_firewall_block(ip):
    rule = f"iptables -A INPUT -s {ip} -p tcp --dport 22 -j DROP"
    if not DRY_RUN:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", "22", "-j", "DROP"], check=False)
    return rule

def analyze_logs():
    attempts_by_ip = defaultdict(list)
    last_user_by_ip = {}

    with open(LOG_FILE, "r") as f:
        for line in f:
            match = SSH_FAIL_REGEX.search(line)
            if match:
                ts_str, user, ip = match.groups()
                # Parse syslog timestamp (assuming current year)
                ts = datetime.strptime(f"{datetime.now().year} {ts_str}", "%Y %b %d %H:%M:%S")
                attempts_by_ip[ip].append(ts)
                last_user_by_ip[ip] = user

    with sqlite3.connect(DB_PATH) as conn:
        for ip, timestamps in attempts_by_ip.items():
            timestamps.sort()
            # Sliding window check for brute-force velocity
            for i in range(len(timestamps)):
                window = [t for t in timestamps[i:] if (t - timestamps[i]).total_seconds() <= WINDOW_SECONDS]
                if len(window) >= THRESHOLD:
                    existing = conn.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
                    if not existing:
                        country, isp = get_geoip(ip)
                        rule = enforce_firewall_block(ip)
                        conn.execute(
                            "INSERT INTO blocked_ips VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (ip, last_user_by_ip[ip], len(timestamps), country, isp, rule, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                        )
                    break

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SentinelSSH.exe - Network Security Monitor</title>
    <!-- Built-in 16x16 Win95 Pixel Shield Favicon (Or replace href with: /static/favicon.png) -->
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' shape-rendering='crispEdges'><path fill='%23000080' d='M2 1h12v7c0 4-6 7-6 7S2 12 2 8V1z'/><path fill='%23c0c0c0' d='M3 2h10v6c0 3-5 5.5-5 5.5S3 11 3 8V2z'/><path fill='%23ff0000' d='M8 3h4v5H8zM4 8h4v4H4z'/></svg>">
    <style>
        * { box-sizing: border-box; border-radius: 0 !important; }
        body {
            background-color: #d4d0c8;
            color: #000000;
            font-family: "Tahoma", "MS Sans Serif", "Geneva", sans-serif;
            font-size: 12px;
            margin: 0;
            padding: 28px 16px;
        }
        .window {
            background-color: #c0c0c0;
            border-top: 2px solid #ffffff;
            border-left: 2px solid #ffffff;
            border-right: 2px solid #404040;
            border-bottom: 2px solid #404040;
            box-shadow: 1px 1px 0px #000000;
            width: 96%;
            max-width: 1360px;
            margin: 0 auto;
            padding: 4px;
        }
        .title-bar {
            background: #000080;
            color: #ffffff;
            font-weight: bold;
            font-size: 12px;
            padding: 5px 8px;
            margin-bottom: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            letter-spacing: 0.3px;
        }
        .win-controls { display: flex; gap: 2px; }
        .win-btn {
            background: #c0c0c0;
            color: #000000;
            font-weight: bold;
            font-size: 10px;
            width: 16px;
            height: 14px;
            text-align: center;
            line-height: 11px;
            border-top: 1px solid #ffffff;
            border-left: 1px solid #ffffff;
            border-right: 1px solid #404040;
            border-bottom: 1px solid #404040;
            cursor: default;
        }
        .toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 6px 10px;
            margin: 0 2px 8px 2px;
            background: #c0c0c0;
            border-top: 1px solid #808080;
            border-left: 1px solid #808080;
            border-right: 1px solid #ffffff;
            border-bottom: 1px solid #ffffff;
        }
        .btn-95 {
            background: #c0c0c0;
            color: #000000;
            font-family: inherit;
            font-size: 11px;
            padding: 3px 12px;
            border-top: 2px solid #ffffff;
            border-left: 2px solid #ffffff;
            border-right: 2px solid #404040;
            border-bottom: 2px solid #404040;
            text-decoration: none;
        }
        .btn-95:active {
            border-top: 2px solid #404040;
            border-left: 2px solid #404040;
            border-right: 2px solid #ffffff;
            border-bottom: 2px solid #ffffff;
        }
        .table-well {
            background: #ffffff;
            border-top: 2px solid #404040;
            border-left: 2px solid #404040;
            border-right: 2px solid #ffffff;
            border-bottom: 2px solid #ffffff;
            margin: 0 2px 8px 2px;
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
        }
        th {
            background: #c0c0c0;
            color: #000000;
            font-weight: bold;
            text-align: left;
            padding: 6px 10px;
            white-space: nowrap;
            border-top: 1px solid #ffffff;
            border-left: 1px solid #ffffff;
            border-right: 1px solid #808080;
            border-bottom: 1px solid #808080;
        }
        td {
            padding: 8px 10px;
            border-right: 1px dotted #c0c0c0;
            border-bottom: 1px solid #e0e0e0;
            color: #000000;
            white-space: nowrap;
        }
        tr:hover td {
            background: #000080;
            color: #ffffff;
        }
        tr:hover code, tr:hover .badge {
            background: #ffffff;
            color: #000080;
            border-color: #ffffff;
        }
        code {
            display: inline-block;
            white-space: nowrap;
            font-family: "Courier New", Courier, monospace;
            font-size: 11px;
            background: #f4f4f0;
            border: 1px solid #808080;
            padding: 2px 6px;
            color: #000000;
        }
        .badge {
            display: inline-block;
            background: #ff0000;
            color: #ffffff;
            font-weight: bold;
            font-size: 10px;
            padding: 1px 6px;
            border: 1px solid #000000;
            letter-spacing: 0.5px;
        }
        .status-bar {
            display: flex;
            gap: 4px;
            margin: 4px 2px 2px 2px;
        }
        .status-pane {
            border-top: 1px solid #808080;
            border-left: 1px solid #808080;
            border-right: 1px solid #ffffff;
            border-bottom: 1px solid #ffffff;
            padding: 4px 8px;
            font-size: 11px;
            flex: 1;
        }
    </style>
</head>
<body>
    <div class="window">
        <div class="title-bar">
            <span>SentinelSSH.exe — Automated Intrusion Detection &amp; Firewall Daemon</span>
            <div class="win-controls">
                <div class="win-btn">_</div>
                <div class="win-btn">□</div>
                <div class="win-btn">X</div>
            </div>
        </div>
        <div class="toolbar">
            <div>
                <strong>Active Policy:</strong> Sliding-Window Brute-Force Filter
                (Max {{ threshold }} failed logins / {{ window }}s window)
            </div>
            <a href="/" class="btn-95">Refresh Log Stream</a>
        </div>
        <div class="table-well">
            <table>
                <tr>
                    <th>Status</th>
                    <th>Source IP</th>
                    <th>Target Account</th>
                    <th>Failures</th>
                    <th>GeoIP Origin / ISP</th>
                    <th>Enforced iptables Rule</th>
                    <th>Logged Timestamp</th>
                </tr>
                {% for row in rows %}
                <tr>
                    <td><span class="badge">DROP</span></td>
                    <td><strong>{{ row[0] }}</strong></td>
                    <td>{{ row[1] }}</td>
                    <td>{{ row[2] }}</td>
                    <td>{{ row[3] }} ({{ row[4] }})</td>
                    <td><code>{{ row[5] }}</code></td>
                    <td>{{ row[6] }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        <div class="status-bar">
            <div class="status-pane">Daemon Status: ONLINE (Monitoring /var/log/auth.log)</div>
            <div class="status-pane">Quarantined Hosts: {{ rows|length }}</div>
            <div class="status-pane">Engine: SQLite3 + iptables</div>
        </div>
    </div>
</body>
</html>
"""

@app.route("/")
def dashboard():
    analyze_logs()
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    return render_template_string(HTML_TEMPLATE, rows=rows, threshold=THRESHOLD, window=WINDOW_SECONDS)

if __name__ == "__main__":
    init_db()
    analyze_logs()
    print("[+] SentinelSSH Active — View SOC Dashboard at http://127.0.0.1:5000")
    app.run(port=5000)