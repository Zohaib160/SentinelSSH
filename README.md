# SentinelSSH — Automated Linux Intrusion Detection & Firewall Daemon

**SentinelSSH** is a lightweight Python security daemon and retro Win95-styled Security Operations Center (SOC) dashboard that parses Linux /var/log/auth.log streams in real time, detects SSH brute-force velocity using a sliding time-window algorithm, enriches attacker telemetry via GeoIP REST APIs, and enforces automated iptables DROP rules.

## Key Features
- **Sliding-Window Brute-Force Engine:** Detects high-velocity credential stuffing and dictionary attacks (default: 5+ failed attempts within 60 seconds) while ignoring isolated user typos.
- **Automated Firewall Mitigation:** Generates and enforces host-level iptables drop rules (iptables -A INPUT -s <IP> -p tcp --dport 22 -j DROP).
- **GeoIP Threat Intelligence:** Queries IP-API to enrich malicious IPs with country of origin and ISP metadata.
- **Persistent SQLite Audit Logging:** Logs quarantined hosts, targeted user accounts, failure counts, and timestamps into a local SQLite3 database.
- **Win95 Retro SOC Web Interface:** Lightweight Flask dashboard styled as a classic Windows 95 system monitor.

## Quick Start
1. Create a virtual environment: python3 -m venv venv
2. Activate it: source venv/bin/activate
3. Install dependencies: pip install -r requirements.txt
4. Run the daemon & dashboard: python3 app.py
5. Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.
