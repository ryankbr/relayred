import ftplib

def test_ftp_connection(ip, username, password):
    try:
        with ftplib.FTP(ip) as ftp:
            ftp.login(user=username, passwd=password)
            print(f"[SUCCESS] Connected and logged in to FTP server at {ip}")
    except Exception as e:
        print(f"[FAILURE] Could not connect to FTP server at {ip}")
        print(f"Reason: {e}")

# Example usage
ip_address = "10.190.42.105"
username = "FTPUSER"
password = "TAIL"

test_ftp_connection(ip_address, username, password)
