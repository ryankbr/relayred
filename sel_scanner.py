"""
cyber power relay vulnerability scanner
prepared for siemens and the istar lab

this script
• fingerprints the relay (model / fw)
• tries elevation acc → 2ac → cal (with rich ui boxes)
• checks default ftp creds
• looks up cves in nvdcve‑1.1‑recent.json

dependencies:
    pip install telnetlib3 rich
"""

import sys
import os
import asyncio
import re
import telnetlib3
import ftplib
import json
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich.text import Text

# global flags
relay_ip = None
TEST_MODE = False
console = Console()

# --- banner ---------------------------------------------------------------
def print_welcome():
    print("=" * 50)
    print("cyber power relay vulnerability scanner")
    print("prepared for siemens and the istar lab")
    print("=" * 50)

# --- run one telnet command ----------------------------------------------
async def telnet_command(ip, cmd, port=23):
    reader, writer = await telnetlib3.open_connection(ip, port)
    writer.write(cmd + "\r\n")
    await writer.drain()
    await asyncio.sleep(0.8)              # short wait
    out = await reader.read(4096)
    writer.close()
    return out

# --- fingerprint model / fw / fid ----------------------------------------
def telnet_fingerprint(ip):
    if TEST_MODE:
        fake = {
            "MODEL": {"value": "SEL351"},
            "FW":    {"value": "2.0"},
            "FID":   {"value": "SEL-787-R110-V1-Z002001-D20190508"},
        }
        print("using simulated telnet fingerprint:")
        for k, v in fake.items():
            print(f"  {k}: {v['value']}")
        return fake

    try:
        raw = asyncio.run(telnet_command(ip, "id"))
        pat = re.compile(r'"([^=]+)=([^"]+)"\s*,\s*"[^"]*"')
        parsed = {}
        print("telnet fingerprint result:")
        for ln in raw.splitlines():
            m = pat.search(ln)
            if m:
                parsed[m.group(1)] = {"value": m.group(2)}
                print(f"  {m.group(1)}: {m.group(2)}")
        return parsed
    except Exception as e:
        print(f"error fingerprinting: {e}")
        return {}

# --- helper: rich box renderer -------------------------------------------
def build_boxes(status_map, labels):
    table = Table.grid(padding=(1, 2))
    boxes = []
    for name in labels:
        state = status_map[name]
        color = {
            "pending": "yellow",
            "success": "green",
            "failed":  "red",
            "skipped": "grey50"
        }[state]
        txt = Text(f"{name}\n{state}", justify="center", style="bold white")
        boxes.append(Panel(txt, width=14, style=color))
    table.add_row(*boxes)
    return table

# --- elevation acc -> 2ac -> cal with rich ui -----------------------------
async def check_elevation(ip):
    creds = [("ACC", "OTTER"), ("2AC", "TAIL"), ("CAL", "CLARKE")]
    status = {name: "pending" for name, _ in creds}
    labels = [n for n, _ in creds]

    print("\nchecking elevation credentials:")

    # test mode: just show all success
    if TEST_MODE:
        for n in labels:
            status[n] = "success"
        console.print(build_boxes(status, labels))
        return

    # live update of three boxes only
    with Live(build_boxes(status, labels), refresh_per_second=4, console=console) as live:
        reader, writer = await telnetlib3.open_connection(ip, 23)

        for idx, (name, pwd) in enumerate(creds):
            # simulate blinking
            await asyncio.sleep(0.3)

            # send role
            writer.write(name.lower() + "\r\n")
            await writer.drain()
            await asyncio.sleep(0.5)

            # send password
            writer.write(pwd + "\r\n")
            await writer.drain()
            await asyncio.sleep(0.8)

            resp = await reader.read(1024)

            # determine success or fail
            if "TRNSFRMR" in resp:
                status[name] = "success"
            else:
                status[name] = "failed"
                # mark later levels as skipped
                for later, _ in creds[idx+1:]:
                    status[later] = "skipped"
                break

            # update live display
            live.update(build_boxes(status, labels))

        writer.close()
        # final update
        live.update(build_boxes(status, labels))

# --- ftp login test -------------------------------------------------------
def ftp_check(ip):
    if TEST_MODE:
        print(f"\nsimulated ftp login success for {ip}")
        return
    try:
        with ftplib.FTP(ip) as ftp:
            ftp.login("FTPUSER", "TAIL")
            print(f"\nftp login success for {ip}")
    except:
        print(f"\nftp login failed for {ip}")

# --- nvd cve feed loader -------------------------------------------------
def load_cve_db():
    fn = "nvdcve-1.1-recent.json"
    if not os.path.isfile(fn):
        print(f"{fn} missing – download from nvd feeds")
        return None
    try:
        with open(fn, encoding="utf-8") as f:
            data = json.load(f)
        print("loaded cve database")
        return data
    except PermissionError:
        os.chmod(fn, 0o644)
        with open(fn, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"error loading cve db: {e}")
        return None

# --- find and save cves ---------------------------------------------------
def find_cves(db, model):
    hits = []
    for item in db.get("CVE_Items", []):
        for d in item["cve"]["description"]["description_data"]:
            if model.lower() in d["value"].lower():
                hits.append(item)
                break
    return hits

def save_cves(hits):
    with open("cve_report.txt", "w", encoding="utf-8") as f:
        for h in hits:
            cid = h["cve"]["CVE_data_meta"]["ID"]
            desc = h["cve"]["description"]["description_data"][0]["value"]
            f.write(f"{cid}\n{desc}\n{'-'*40}\n")
    print("cve report saved to cve_report.txt")

# --- main ----------------------------------------------------------------
def main():
    global relay_ip, TEST_MODE
    if len(sys.argv) < 2:
        print("usage: python sel_scanner.py <relay_ip> [test|demo model ver]")
        sys.exit(1)

    relay_ip = sys.argv[1]
    TEST_MODE = any(a.lower() == "test" for a in sys.argv)

    print_welcome()

    # demo override
    if relay_ip.lower() == "demo" and len(sys.argv) >= 4:
        model, version = sys.argv[2], sys.argv[3]
        print(f"\ndemo mode: model={model}, version={version}")
    else:
        print(f"\nscanning relay at {relay_ip}\n")
        fp = telnet_fingerprint(relay_ip)
        model = fp.get("MODEL", {}).get("value")
        version = fp.get("FW", {}).get("value")
        if not version and "FID" in fp:
            fid = fp["FID"]["value"]
            vmatch = re.search(r"(R\d+-V\d+)", fid)
            version = vmatch.group(1) if vmatch else None
            if not model:
                mm = re.match(r"(SEL-\d+)", fid)
                model = mm.group(1) if mm else None
        print(f"model: {model or 'n/a'}  |  version: {version or 'n/a'}")

    # elevation test with rich ui
    asyncio.run(check_elevation(relay_ip))

    # cve lookup
    if model:
        db = load_cve_db()
        if db:
            hits = find_cves(db, model)
            print(f"\n{len(hits)} cves found for {model}")
            for h in hits[:5]:
                print(" ", h["cve"]["CVE_data_meta"]["ID"])
            if hits:
                save_cves(hits)
    else:
        print("no model; skipping cve scan")

    # ftp test
    ftp_check(relay_ip)

if __name__ == "__main__":
    main()
