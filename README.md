# 🔐 Cyber Power Relay Vulnerability Scanner

**Developed for Siemens & the iStar Lab**  
Scan SEL relays via Telnet, check for known vulnerabilities using the NVD CVE feed, and test default FTP credentials — all from one CLI tool.  

> ⚡ Built with 💻 Python • 🛡️ Security-Focused • 🔬 Testable

---

## 🚀 Features

- 🔍 **Telnet Fingerprint Extraction** (MODEL, FW, FID)
- 🧠 **CVE Lookup** via `nvdcve-1.1-recent.json`
- 🔒 **Default Credential Check** (FTPUSER / TAIL)
- ⚙️ **Test Mode** – Simulates everything
- 🧪 **Demo Mode** – Manually specify model/version

---

## 🧑‍💻 How to Use

### ▶️ Real Device
```bash
python sel_scanner.py 192.168.0.10
```

### 🧪 Simulated Test Mode
(no network interaction — all fake)
```bash
python sel_scanner.py 127.0.0.1 test
```

### 🧰 Manual Demo Mode
(specify model + version manually)
```bash
python sel_scanner.py demo SEL-787 R110-V1 test
```

---

## 📁 Project Structure

| File                    | Purpose                                     |
|-------------------------|---------------------------------------------|
| `sel_scanner.py`        | Main CLI scanner                            |
| `sel_fingerprint.py`    | Telnet command / fingerprint parser         |
| `sel_ftp.py`            | FTP login checker                           |
| `nvdcve-1.1-recent.json`| NVD CVE feed (downloaded separately)        |
| `.gitignore`            | Clean repo setup                            |

---

## 📦 CVE Feed

Download `nvdcve-1.1-recent.json` from the [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED) and place it in the root folder of this project.

---

## 📄 Example Output

```text
scanning relay at ip: 127.0.0.1
using simulated telnet fingerprint data:
  MODEL: SEL351
  FW: 2.0
  FID: SEL-787-R110-V1...

found 3 vulnerabilities for model 'SEL351':
  CVE-2023-XXXX: buffer overflow in relay firmware
  ...
```

---

## 🙌 Contributors

Made with caffeine and curiosity by the **Relay Red Team**  
🎓 Erin Cana, Ty Lavergne, Damian Lall, Ryan Kabir, Samuel Mueller

---

## 🛡️ Disclaimer

This tool is for research, education, and internal lab testing only.  
Do not scan devices you do not own or have explicit permission to test.
