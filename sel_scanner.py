import sys
import os
import asyncio
import re
import telnetlib3
import ftplib
import requests
import json
import io

# global variables
relay_ip = None
TEST_MODE = False

def print_welcome():
    print("=" * 50)
    print("cyber power relay vulnerability scanner")
    print("prepared for siemens and the istar lab")
    print("=" * 50)

# --- telnet fingerprint functions ---
async def telnet_command(ip, port=23, command="id"):
    reader, writer = await telnetlib3.open_connection(ip, port)
    writer.write(command + "\r\n")
    await writer.drain()
    await asyncio.sleep(1)  # wait for response to accumulate
    output = await reader.read(4096)
    writer.close()
    return output

def parse_output(output):
    parsed_dict = {}
    pattern = re.compile(r'"([^=]+)=([^"]+)"\s*,\s*"([^"]+)"')
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            key = match.group(1)
            value = match.group(2)
            extra = match.group(3)
            parsed_dict[key] = {"value": value, "extra": extra}
    return parsed_dict

async def run_telnet_fingerprint(ip):
    output = await telnet_command(ip, 23, "id")
    return parse_output(output)

def telnet_fingerprint(ip):
    if TEST_MODE:
        simulated_data = {
            "MODEL": {"value": "SEL351", "extra": "simulated"},
            "FW": {"value": "2.0", "extra": "simulated"},
            "FID": {"value": "SEL-787-R110-V1-Z002001-D20190508", "extra": "simulated"}
        }
        print("using simulated telnet fingerprint data:")
        for key, value in simulated_data.items():
            print(f"  {key}: {value}")
        return simulated_data
    else:
        try:
            result = asyncio.run(run_telnet_fingerprint(ip))
            print("telnet fingerprint result:")
            for key, value in result.items():
                print(f"  {key}: {value}")
            return result
        except Exception as e:
            print(f"error running telnet fingerprint: {e}")
            return {}

# --- ftp test ---
def test_ftp_connection(ip, username="FTPUSER", password="TAIL"):
    if TEST_MODE:
        print(f"simulated ftp test: [SUCCESS] connected to ftp server at {ip} using default creds")
    else:
        try:
            with ftplib.FTP(ip) as ftp:
                ftp.login(user=username, passwd=password)
                print(f"[SUCCESS] connected and logged in to ftp server at {ip}")
        except Exception as e:
            print(f"[FAILURE] could not connect to ftp server at {ip}")
            print(f"reason: {e}")

# --- cve database functions ---
def fetch_cve_database():
    json_filename = "nvdcve-1.1-recent.json"
    if not os.path.exists(json_filename):
        print(f"{json_filename} not found. Please download it from:")
        print("https://nvd.nist.gov/vuln/data-feeds#JSON_FEED")
        return None
    try:
        with open(json_filename, "r", encoding="utf-8") as f:
            cve_data = json.load(f)
        print("loaded cve database.")
        return cve_data
    except PermissionError as pe:
        print(f"error loading cve database: {pe}. attempting to fix permissions...")
        try:
            os.chmod(json_filename, 0o644)
            with open(json_filename, "r", encoding="utf-8") as f:
                cve_data = json.load(f)
            print("loaded cve database after permission fix.")
            return cve_data
        except Exception as e:
            print(f"failed to load cve database after permission fix: {e}")
            return None
    except Exception as e:
        print(f"error loading cve database: {e}")
        return None

def search_cves(cve_data, model):
    results = []
    if not cve_data or "CVE_Items" not in cve_data:
         return results
    for item in cve_data["CVE_Items"]:
        try:
            descriptions = item["cve"]["description"]["description_data"]
            for d in descriptions:
                if model.lower() in d["value"].lower():
                    results.append(item)
                    break
        except Exception:
            continue
    return results

def save_cve_report(cve_results, filename="cve_report.txt"):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            for item in cve_results:
                try:
                    cve_id = item["cve"]["CVE_data_meta"]["ID"]
                    descriptions = item["cve"]["description"]["description_data"]
                    short_desc = descriptions[0]["value"] if descriptions else "no description"
                    f.write(f"{cve_id}\n{short_desc}\n{'-'*40}\n")
                except Exception:
                    continue
        print(f"cve report saved to {filename}")
    except Exception as e:
        print(f"failed to save cve report: {e}")

# --- main logic ---
def main():
    global relay_ip, TEST_MODE
    if len(sys.argv) < 2:
        print("usage: python sel_scanner.py <relay_ip> [test|demo model version]")
        sys.exit(1)

    relay_ip = sys.argv[1].strip()
    # if any arg equals "test", we run in test mode
    if any(arg.lower() == "test" for arg in sys.argv):
        TEST_MODE = True

    print_welcome()

    model = None
    version = None

    # --- demo mode: if relay_ip is "demo", use manual model and version ---
    if relay_ip.lower() == "demo" and len(sys.argv) >= 4:
        model = sys.argv[2]
        version = sys.argv[3]
        print(f"\nrunning in demo mode with model: {model}, version: {version}")
    else:
        print(f"\nscanning relay at ip: {relay_ip}\n")
        fingerprint_data = telnet_fingerprint(relay_ip)
        
        # extract model and version information
        if "MODEL" in fingerprint_data:
            model = fingerprint_data["MODEL"]["value"]
        if "FW" in fingerprint_data:
            version = fingerprint_data["FW"]["value"]
        if not version and "FID" in fingerprint_data:
            fid = fingerprint_data["FID"]["value"]
            ver_match = re.match(r"SEL-\d+-([R\d\-V\d]+)", fid)
            if ver_match:
                version = ver_match.group(1)
            if not model:
                model_match = re.match(r"(SEL-\d+)", fid)
                if model_match:
                    model = model_match.group(1)

        if model:
            print(f"extracted model: {model}")
        else:
            print("model info not found.")
        if version:
            print(f"extracted version: {version}")
        else:
            print("firmware version not found.")

    # --- CVE scan ---
    if model:
        cve_data = fetch_cve_database()
        if cve_data:
            cv_results = search_cves(cve_data, model)
            if cv_results:
                print(f"\nfound {len(cv_results)} vulnerabilities for model '{model}':")
                for item in cv_results:
                    try:
                        cve_id = item["cve"]["CVE_data_meta"]["ID"]
                        descriptions = item["cve"]["description"]["description_data"]
                        short_desc = descriptions[0]["value"] if descriptions else "no description"
                        print(f"  {cve_id}: {short_desc}")
                    except Exception:
                        continue
                save_cve_report(cv_results)
            else:
                print(f"\nno vulnerabilities found for model '{model}'.")
        else:
            print("\nfailed to load cve database.")
    else:
        print("\nskipping CVE check — no model info.")

    print("")
    test_ftp_connection(relay_ip)

if __name__ == "__main__":
    main()
