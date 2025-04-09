import sys
import os
import asyncio
import re
import telnetlib3
import ftplib
import requests
import json
import io
from zipfile import ZipFile

# global variables
relay_ip = None
TEST_MODE = False

def print_welcome():
    # print header
    print("=" * 50)
    print("cyber power relay vulnerability scanner")
    print("prepared for siemens and the istar lab")
    print("=" * 50)

# --- telnet fingerprint functions ---
async def telnet_command(ip, port=23, command="id"):
    # connect to ip and port using telnet; send command and wait for response
    reader, writer = await telnetlib3.open_connection(ip, port)
    writer.write(command + "\r\n")
    await writer.drain()
    await asyncio.sleep(1)  # wait for response to accumulate
    output = await reader.read(4096)
    writer.close()
    return output

def parse_output(output):
    # parse each line in the format "KEY=VALUE","EXTRA" into a dict
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
    # if in test mode, return simulated fingerprint data; else, run real telnet session
    if TEST_MODE:
        simulated_data = {
            "MODEL": {"value": "SEL351", "extra": "simulated"},
            "FW": {"value": "2.0", "extra": "simulated"}
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

# --- ftp connection test ---
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
    """
    Load the CVE database from a local file named "cvelistV5-main.zip".
    If the file isn't found, download it from the online source into the same directory.
    """
    zip_filename = "cvelistV5-main.zip"
    if not os.path.exists(zip_filename):
        print("cve database zip not found locally. downloading...")
        url = "https://www.cve.org/Downloads/main.zip"
        try:
            r = requests.get(url)
            if r.status_code == 200:
                with open(zip_filename, "wb") as f:
                    f.write(r.content)
                print("downloaded cve database.")
            else:
                print("failed to download cve database.")
                return None
        except Exception as e:
            print(f"error downloading cve database: {e}")
            return None
    # extract and load json
    try:
        with open(zip_filename, "rb") as f:
            zip_data = f.read()
        with ZipFile(io.BytesIO(zip_data)) as zf:
            json_filename = None
            for name in zf.namelist():
                if name.lower().endswith(".json"):
                    json_filename = name
                    break
            if not json_filename:
                print("no json file found in cve zip.")
                return None
            json_bytes = zf.read(json_filename)
            cve_data = json.loads(json_bytes)
            print("loaded cve database.")
            return cve_data
    except Exception as e:
        print(f"error processing cve database: {e}")
        return None

def search_cves(cve_data, model):
    # search the cve_data for any vulnerability mentioning the model (case-insensitive)
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
    # save a simple text report of CVE IDs and descriptions
    try:
        with open(filename, "w", encoding="utf-8") as f:
            for item in cve_results:
                try:
                    cve_id = item["cve"]["CVE_data_meta"]["ID"]
                    descriptions = item["cve"]["description"]["description_data"]
                    desc = "\n".join([d["value"] for d in descriptions])
                    f.write(f"{cve_id}\n{desc}\n{'-'*40}\n")
                except Exception:
                    continue
        print(f"cve report saved to {filename}")
    except Exception as e:
        print(f"failed to save cve report: {e}")

# --- main sequence ---
def main():
    global relay_ip, TEST_MODE
    # require at least one argument: the relay ip, optional second argument "test"
    if len(sys.argv) < 2:
        print("usage: python sel_scanner.py <relay_ip> [test]")
        sys.exit(1)
    relay_ip = sys.argv[1].strip()
    if len(sys.argv) >= 3 and sys.argv[2].lower() == "test":
        TEST_MODE = True

    print_welcome()
    print(f"scanning relay at ip: {relay_ip}\n")
    
    # run telnet fingerprint and get parsed data
    fingerprint_data = telnet_fingerprint(relay_ip)
    
    # extract model from fingerprint data; assume key "MODEL"
    model = None
    if "MODEL" in fingerprint_data:
        model = fingerprint_data["MODEL"]["value"]
        print(f"\nextracted model: {model}")
    else:
        print("\nmodel info not found in telnet fingerprint.")
    
    # pull cve database and search for vulnerabilities related to the model
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
        print("\nskipping vulnerability check (no model info).")
    
    # test ftp connection with default credentials
    print("")
    test_ftp_connection(relay_ip)

if __name__ == "__main__":
    main()
