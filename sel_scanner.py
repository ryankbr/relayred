import sys
import os
import asyncio
import re
import telnetlib3
import ftplib
import json

# global variables
relay_ip = None
TEST_MODE = False

# --- print a welcome banner to terminal ---
def print_welcome():
    print("=" * 50)
    print("cyber power relay vulnerability scanner")
    print("prepared for siemens and the istar lab")
    print("=" * 50)

# --- run a telnet command to the relay and return its output ---
async def telnet_command(ip, port=23, command=""):
    # opens telnet connection and sends a command
    reader, writer = await telnetlib3.open_connection(ip, port)
    writer.write(command + "\r\n")  # write the command
    await writer.drain()            # flush it out
    await asyncio.sleep(1)          # wait for response
    output = await reader.read(4096)  # read up to 4kb
    writer.close()
    return output

# --- request fingerprint info from the relay and parse it ---
def telnet_fingerprint(ip):
    if TEST_MODE:
        # simulate fingerprint response in test mode
        data = {
            "MODEL": {"value": "SEL351"}, 
            "FW": {"value": "2.0"}, 
            "FID": {"value": "SEL-787-R110-V1-Z002001-D20190508"}
        }
        print("using simulated telnet fingerprint:")
        for k, v in data.items():
            print(f"  {k}: {v['value']}")
        return data

    try:
        # run actual telnet "id" command
        raw = asyncio.run(telnet_command(ip, 23, "id"))
        pattern = re.compile(r'"([^=]+)=([^"]+)"\s*,\s*"([^"]+)"')
        parsed = {}
        print("telnet fingerprint result:")
        for line in raw.splitlines():
            m = pattern.search(line)
            if m:
                key, value = m.group(1), m.group(2)
                parsed[key] = {"value": value}
                print(f"  {key}: {value}")
        return parsed
    except Exception as e:
        print(f"error fingerprinting: {e}")
        return {}

# --- try privilege elevation using default passwords for acc, 2ac, cal ---
def check_elevation(ip):
    # this async function sends the elevation level and waits for password prompt
    async def try_login(cmd, pwd):
        try:
            reader, writer = await telnetlib3.open_connection(ip, 23)
            writer.write(cmd + "\r\n")  # send the elevation level (e.g., acc)
            await writer.drain()
            await asyncio.sleep(0.4)   # wait briefly for password prompt
            writer.write(pwd + "\r\n") # send the password
            await writer.drain()
            await asyncio.sleep(0.4)   # wait for confirmation output
            out = await reader.read(4096)
            writer.close()
            # success if output contains ok or welcome
            return "ok" in out.lower() or "welcome" in out.lower()
        except Exception:
            return False

    # list of default roles and corresponding passwords
    creds = [("ACC", "OTTER"), ("2AC", "TAIL"), ("CAL", "CLARKE")]
    print("\nchecking elevation credentials:")

    for user, pwd in creds:
        if TEST_MODE:
            # simulate a successful login
            print(f"  {user}: simulated success")
            continue
        # run the login attempt and report success/failure
        result = asyncio.run(try_login(user.lower(), pwd))
        status = "success" if result else "failed"
        print(f"  {user}: {status}")

# --- test ftp login using default credentials ---
def test_ftp(ip):
    if TEST_MODE:
        print(f"\nsimulated ftp login success for {ip}")
        return
    try:
        with ftplib.FTP(ip) as ftp:
            ftp.login(user="FTPUSER", passwd="TAIL")
            print(f"\nftp login success for {ip}")
    except:
        print(f"\nftp login failed for {ip}")

# --- load the nvd cve json database file ---
def load_cve_db():
    fn = "nvdcve-1.1-recent.json"
    if not os.path.exists(fn):
        print(f"{fn} missing; download from NVD feeds")
        return None
    try:
        with open(fn, "r", encoding="utf-8") as f:
            data = json.load(f)
        print("loaded CVE database")
        return data
    except PermissionError:
        # fix file permissions and try again
        os.chmod(fn, 0o644)
        try:
            with open(fn, "r", encoding="utf-8") as f:
                data = json.load(f)
            print("loaded CVE database after chmod")
            return data
        except:
            pass
    except:
        pass
    return None

# --- search cve entries that match the relay model ---
def search_cves(db, model):
    hits = []
    for item in db.get("CVE_Items", []):
        for d in item["cve"]["description"]["description_data"]:
            if model.lower() in d["value"].lower():
                hits.append(item)
                break
    return hits

# --- save matching cves to a simple text file ---
def save_report(hits):
    with open("cve_report.txt", "w", encoding="utf-8") as f:
        for it in hits:
            cid = it["cve"]["CVE_data_meta"]["ID"]
            desc = it["cve"]["description"]["description_data"][0]["value"]
            f.write(f"{cid}\n{desc}\n{'-'*40}\n")
    print("cve report saved to cve_report.txt")

# --- main entry point ---
def main():
    global relay_ip, TEST_MODE

    # check args and activate test mode
    if len(sys.argv) < 2:
        print("usage: python sel_scanner.py <relay_ip> [test|demo model version]")
        sys.exit(1)

    relay_ip = sys.argv[1]
    if any(a.lower() == "test" for a in sys.argv):
        TEST_MODE = True

    print_welcome()

    model = None
    version = None

    # handle demo mode where model/version are passed directly
    if relay_ip.lower() == "demo" and len(sys.argv) >= 4:
        model = sys.argv[2]
        version = sys.argv[3]
        print(f"\nrunning demo with model={model}, version={version}")
    else:
        print(f"\nscanning relay at ip: {relay_ip}\n")
        data = telnet_fingerprint(relay_ip)
        model = data.get("MODEL", {}).get("value")
        version = data.get("FW", {}).get("value")

        # try to extract model/version from FID if needed
        if not version and "FID" in data:
            fid = data["FID"]["value"]
            vm = re.search(r"(R\d+-V\d+)", fid)
            if vm:
                version = vm.group(1)
            if not model:
                mm = re.match(r"(SEL-\d+)", fid)
                if mm:
                    model = mm.group(1)

        print(f"\nextracted model: {model or 'none'}")
        print(f"extracted version: {version or 'none'}")

    # check acc, 2ac, cal credentials
    check_elevation(relay_ip)

    # lookup vulnerabilities based on model name
    if model:
        db = load_cve_db()
        if db:
            hits = search_cves(db, model)
            print(f"\nfound {len(hits)} CVEs for {model}:")
            for it in hits:
                cid = it["cve"]["CVE_data_meta"]["ID"]
                desc = it["cve"]["description"]["description_data"][0]["value"]
                print(f"  {cid}: {desc}")
            if hits:
                save_report(hits)
        else:
            print("\nno CVE database loaded")
    else:
        print("\nskipping CVE scan (no model)")

    # check ftp login
    test_ftp(relay_ip)

# run main function
if __name__ == "__main__":
    main()
