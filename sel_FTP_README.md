# FTP Brute-Force Scanner — Command-Line Reference

This script allows you to test and brute-force login credentials to an FTP server.
It includes support for simulated testing, fast mode scanning, and a rich UI spinner for visual feedback.

---

## Script Overview

**File name:** `sel_ftp.py`  
**Purpose:** Test or brute-force FTP logins using a wordlist, with simulated test mode, fast mode, and optional fancy UI

---

## Command Structure

```bash
python sel_ftp.py <relay_ip> [options]
```

| Positional | Description |
|------------|-------------|
| `relay_ip` | IP address of the FTP server, or `demo` in `--test` mode |

---

## Optional Flags

| Flag | Description |
|------|-------------|
| `--username <user>` | FTP username (default: `FTPUSER`) |
| `--password <pass>` | FTP password. If correct, skips brute-force |
| `--ftpwordlist <file>` | Path to password list for brute-force |
| `--test` | Simulates login instead of making real connections |
| `--fast` | Runs brute-force without spinner/table UI (just progress bar) |

---

## ✅ Recommended Test Commands

### ✅ Simulate success with correct credentials
```bash
python sel_ftp.py demo --username FTPUSER --password naruto --test
```

### ✅ Simulate failed login, then brute-force until "naruto"
```bash
python sel_ftp.py demo --username admin --password wrongpass --ftpwordlist wordlist.txt --test
```

### ✅ Brute-force only (no password provided)
```bash
python sel_ftp.py demo --ftpwordlist wordlist.txt --test
```

### ✅ Fast brute-force test (no spinner/table)
```bash
python sel_ftp.py demo --ftpwordlist wordlist.txt --test --fast
```

---

## ✅ Real FTP Scan Commands

### 🔐 Try default user/pass only
```bash
python sel_ftp.py 192.168.0.100
```

### 🔐 Use custom credentials (no brute-force)
```bash
python sel_ftp.py 192.168.0.100 --username admin --password hunter2
```

### 🔐 Brute-force if default fails
```bash
python sel_ftp.py 192.168.0.100 --ftpwordlist wordlist.txt
```

### 🔐 Fast brute-force scan
```bash
python sel_ftp.py 192.168.0.100 --ftpwordlist wordlist.txt --fast
```

---

## Common Errors & Their Meanings

| Error | Meaning | Fix |
|-------|---------|-----|
| `getaddrinfo failed` | You're using `"demo"` outside of `--test` mode | Always use `--test` with `"demo"` |
| `No wordlist provided in test mode` | You didn’t give `--ftpwordlist` | Add `--ftpwordlist wordlist.txt` |
| `[FAILED] user:pass - 530 Login authentication failed` | Wrong credentials | Try another one or fall back to brute-force |
| `Could not connect to FTP server` | Server down or IP wrong | Check network, hostname, or use test mode |

---

## Example `wordlist.txt` File

```txt
123456
admin
letmein
password
hunter2
naruto
```

Put it in the same folder as `sel_ftp.py` and refer to it like:
```bash
--ftpwordlist wordlist.txt
```