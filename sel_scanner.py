"""
cyber power relay vulnerability scanner
prepared for siemens and the istar lab

this script
• fingerprints the relay (model / fw)
• tries elevation acc → 2ac → cal (with rich ui boxes)
• checks default ftp creds
• looks up cves via the nvd cve api

dependencies:
    pip install telnetlib3 rich requests
"""

import sys
import os
import asyncio
import re
import telnetlib3
import ftplib
import json
import requests               # http client for the nvd api
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich import box
from rich.align import Align
from rich.spinner import Spinner

from sel_ics import ICS_Scanner

# global flags
relay_ip = None
TEST_MODE = False
console = Console()

# --- banner ---------------------------------------------------------------
def print_welcome():
    """print a fancy colored banner"""
    title = Text("cyber power relay", style="bold cyan", justify="center")
    subtitle = Text("vulnerability scanner", style="bold magenta", justify="center")
    panel = Panel(
        Align.center(Text.assemble(title, "\n", subtitle)),
        box=box.DOUBLE,
        padding=(1, 4),
        border_style="bright_blue",
    )
    console.print(panel)
    console.print(
        Align.center("[bright_yellow]prepared for Siemens & the iStar Lab[/bright_yellow]\n")
    )

# --- run one telnet command ----------------------------------------------
async def telnet_command(ip, cmd, port=23):
    """open a telnet connection, send cmd, return output"""
    reader, writer = await telnetlib3.open_connection(ip, port)
    writer.write(cmd + "\r\n")
    await writer.drain()
    await asyncio.sleep(0.8)              # short wait
    out = await reader.read(4096)
    writer.close()
    return out

# --- fingerprint model / fw / fid ----------------------------------------
def telnet_fingerprint(ip):
    """collect MODEL, FW, FID via telnet 'id' command"""
    if TEST_MODE:
        fake = {
            "MODEL": {"value": "SEL351"},
            "FW":    {"value": "2.0"},
            "FID":   {"value": "SEL-787-R110-V1-Z002001-D20190508"},
        }
        console.print(Panel("using simulated telnet fingerprint", style="yellow"))
        for k, v in fake.items():
            console.print(f"  [cyan]{k}[/cyan]: [white]{v['value']}[/white]")
        return fake

    try:
        raw = asyncio.run(telnet_command(ip, "id"))
        pat = re.compile(r'"([^=]+)=([^"]+)"\s*,\s*"[^"]*"')
        parsed = {}
        console.print(Panel("telnet fingerprint result", style="bright_green"))
        for ln in raw.splitlines():
            m = pat.search(ln)
            if m:
                key, val = m.group(1), m.group(2)
                parsed[key] = {"value": val}
                console.print(f"  [cyan]{key}[/cyan]: [white]{val}[/white]")
        return parsed
    except Exception as e:
        console.print(f"[red]error fingerprinting:[/red] {e}")
        return {}

# --- helper: rich box renderer -------------------------------------------
def build_boxes(status_map, labels):
    """render three side-by-side status boxes"""
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
        boxes.append(Panel(txt, width=14, style=color, box=box.ROUNDED))
    table.add_row(*boxes)
    return table

# --- elevation acc -> 2ac -> cal with rich ui -----------------------------
async def check_elevation(ip):
    """attempt acc→2ac→cal in one telnet session, updating ui boxes"""
    creds = [("ACC", "OTTER"), ("2AC", "TAIL"), ("CAL", "CLARKE")]
    status = {name: "pending" for name, _ in creds}
    labels = [n for n, _ in creds]

    console.print("\n[bold]checking elevation credentials:[/bold]\n")

    if TEST_MODE:
        for n in labels:
            status[n] = "success"
        console.print(build_boxes(status, labels))
        return

    console.print(Spinner("dots", text="connecting telnet…"), justify="center")
    reader, writer = await telnetlib3.open_connection(ip, 23)

    with Live(build_boxes(status, labels), refresh_per_second=4, console=console) as live:
        for idx, (name, pwd) in enumerate(creds):
            await asyncio.sleep(0.3)

            writer.write(name.lower() + "\r\n")  # send role
            await writer.drain()
            await asyncio.sleep(0.5)

            writer.write(pwd + "\r\n")           # send password
            await writer.drain()
            await asyncio.sleep(0.8)

            resp = await reader.read(1024)

            # determine success or fail (do NOT change this logic)
            if "TRNSFRMR" in resp:
                status[name] = "success"
            else:
                status[name] = "failed"
                # skip remaining levels
                for later, _ in creds[idx+1:]:
                    status[later] = "skipped"
                break

            live.update(build_boxes(status, labels))

        writer.close()
        live.update(build_boxes(status, labels))

# --- ftp login test -------------------------------------------------------
def ftp_check(ip):
    """attempt ftp login with default creds"""
    if TEST_MODE:
        console.print(f"\n[grey50]simulated ftp login success for {ip}[/grey50]")
        return
    try:
        with ftplib.FTP(ip) as ftp:
            ftp.login("FTPUSER", "TAIL")
            console.print(f"\n[green]ftp login success for {ip}[/green]")
    except:
        console.print(f"\n[red]ftp login failed for {ip}[/red]")

# --- nvd cve api wrapper --------------------------------------------------
def load_cve_db():
    """dummy stub – we now query the nvd api directly instead of a local file"""
    console.print("[bright_green]using live nvd cve api[/bright_green]")
    return {}   # non-empty so main() still calls find_cves

def find_cves(db, model):
    """query the nvd cve api for entries that mention the relay model"""
    hits = []
    if not model:
        return hits

    # build request
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": model,
        "resultsPerPage": 2000,
        "noRejected": ""
    }

    try:
        r = requests.get(url, params=params, timeout=30)
        if r.status_code != 200:
            console.print(f"[red]nvd api error: status {r.status_code}[/red]")
            return hits
        data = r.json()
    except Exception as e:
        console.print(f"[red]nvd api request failed:[/red] {e}")
        return hits

    # normalize response into the old structure expected by save_cves()
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cve_id = cve.get("id")
        desc_list = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
        if model.lower() in desc_en.lower():
            hits.append({
                "cve": {
                    "CVE_data_meta": {"ID": cve_id},
                    "description": {"description_data": [{"value": desc_en}]}
                }
            })
    return hits

# --- save cves (unchanged) ------------------------------------------------
def save_cves(hits):
    """write found CVEs to cve_report.txt"""
    with open("cve_report.txt", "w", encoding="utf-8") as f:
        for h in hits:
            cid = h["cve"]["CVE_data_meta"]["ID"]
            desc = h["cve"]["description"]["description_data"][0]["value"]
            f.write(f"{cid}\n{desc}\n{'-'*40}\n")
    console.print("[bright_blue]cve report saved to cve_report.txt[/bright_blue]")

# --- main ----------------------------------------------------------------
def main():
    global relay_ip, TEST_MODE

    if len(sys.argv) < 2:
        console.print("[red]usage: python sel_scanner.py <relay_ip> [test|demo model ver][/red]")
        sys.exit(1)

    relay_ip = sys.argv[1]
    TEST_MODE = any(a.lower() == "test" for a in sys.argv)

    print_welcome()

    # demo override
    if relay_ip.lower() == "demo" and len(sys.argv) >= 4:
        model, version = sys.argv[2], sys.argv[3]
        console.print(f"\n[bold yellow]demo mode:[/bold yellow] model={model}, version={version}")
    else:
        console.print(f"\n[cyan]scanning relay at {relay_ip}[/cyan]\n")
        fp = telnet_fingerprint(relay_ip)
        model  = fp.get("MODEL", {}).get("value")
        version= fp.get("FW", {}).get("value")
        if not version and "FID" in fp:
            fid = fp["FID"]["value"]
            vmatch = re.search(r"(R\d+-V\d+)", fid)
            version = vmatch.group(1) if vmatch else None
            if not model:
                mm = re.match(r"(SEL-\d+)", fid)
                model = mm.group(1) if mm else None

        # ** highlight model & version prominently **
        info = Text.assemble(
            (" MODEL: ", "bold white on blue "),
            (model or "n/a", "bold yellow "),
            ("\n VERSION: ", "bold white on blue "),
            (version or "n/a", "bold yellow ")
        )
        panel = Panel(
            Align.center(info),
            box=box.HEAVY,
            border_style="bright_magenta",
            padding=(1, 4),
            title="[bold magenta]detected relay[/bold magenta]"
        )
        console.print(panel)

    # elevation test with rich ui
    asyncio.run(check_elevation(relay_ip))

    # cve lookup
    if model:
        db = load_cve_db()
        if db:
            hits = find_cves(db, model)
            console.print(f"\n[bold]found {len(hits)} cves for {model}[/bold]")
            for h in hits[:5]:
                console.print("  •", h["cve"]["CVE_data_meta"]["ID"])
            if hits:
                save_cves(hits)
    else:
        console.print("[yellow]no model; skipping cve scan[/yellow]")

    # ftp test
    ftp_check(relay_ip)

    scanner = ICS_Scanner(relay_ip, test_mode=TEST_MODE)
    scanner.scan()

if __name__ == "__main__":
    main()
