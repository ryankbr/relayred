# 🔐 Cyber Power Relay Vulnerability Scanner 🔌

> **Built for Siemens & the iStar Lab**  
> ⚡ Python • 🛡️ Security • 🔬 Lab-Ready

A one‑stop CLI tool to:  
1. 🔍 Fingerprint SEL relays over Telnet  
2. 🧠 Lookup CVEs from the NVD feed  
3. 🔒 Test default FTP credentials  
4. 🎨 Show interactive, blinking “ACC → 2AC → CAL” access‑level boxes  

---

## 🎉 Features

- **Telnet Fingerprint**  
  • Extracts MODEL, FW, FID, plus bootloader info  
- **Privilege Elevation UI**  
  • Animated Rich boxes for ACC → 2AC → CAL  
  • Real‑time color updates:  
  &nbsp;&nbsp;– 🟡 pending • 🟢 success • 🔴 failed • ⚪ skipped  
- **CVE Lookup**  
  • Scans `nvdcve-1.1-recent.json` for your model  
  • Saves `cve_report.txt` with ID + description  
- **FTP Default‑Creds Check**  
  • Automatically tests `FTPUSER/TAIL` on port 21  
- **Demo & Test Modes**  
  • `test`: no network calls, simulated data  
  • `demo`: manually supply MODEL + VERSION  

---

## 🚀 Installation

bash
git clone https://github.com/ryankbr/relayred.git
cd relayred
pip install telnetlib3 rich
# download the CVE feed:
# 1. go to https://nvd.nist.gov/vuln/data-feeds#JSON_FEED  
# 2. grab “nvdcve-1.1-recent.json” and drop it here

🧑‍💻 Usage
1. Real Relay Scan
bash
Copy
Edit
python sel_scanner.py 192.168.0.10
2. Simulated Test Mode
bash
Copy
Edit
python sel_scanner.py 127.0.0.1 test
3. Manual Demo Mode
bash
Copy
Edit
python sel_scanner.py demo SEL-787 R110-V1
# add “test” at end to simulate elevation & FTP too
📁 Project Layout
graphql
Copy
Edit
relayred/
├── sel_scanner.py           # main CLI scanner
├── sel_fingerprint.py       # telnet “id” parser
├── sel_ftp.py               # ftp default‑creds tester
├── nvdcve-1.1-recent.json   # NVD CVE feed (download manually)
└── .gitignore
🌈 Example Output
text
Copy
Edit
🇨🇭 scanning relay at 10.190.42.105

📡 telnet fingerprint result:
  MODEL          SEL-787
  FW             1.10
  FID            SEL-787-R110-V1-Z...
  BOOTLDR        R303-V0
  PARTNO         0787EX1AA0BA...

🔐 checking elevation credentials:
[ACC] 🟢  [2AC] 🟡  [CAL] ⚪   ← live‑updating boxes

✅ ACC: success
❌ 2AC: failed → CAL skipped

📡 loaded cve database
🔍 found 2 CVEs for SEL-787:
  • CVE-2023-1234: buffer overflow in power logic  
  • CVE-2022-5678: auth bypass in web interface  
✔️ cve_report.txt saved

🔌 ftp login success for 10.190.42.105
🙌 Contributors
Relay Red Team
Erin Cana · Ty Lavergne · Damian Lall · Ryan Kabir · Samuel Mueller

⚠️ Disclaimer
For research & lab use only.
Please do not scan devices you do not own or have permission to test.
