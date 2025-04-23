from rich.console import Console, Group
from rich.table import Table
from rich.live import Live
from rich.spinner import Spinner
from tqdm import tqdm
import ftplib
import time
import sys
import argparse

console = Console()
TEST_MODE = False

# Attempt a single FTP login
def try_ftp_login(ip, username, password):
    try:
        with ftplib.FTP(ip) as ftp:
            ftp.login(user=username, passwd=password)
            console.print(f"[bold green][SUCCESS][/bold green] Logged in with [cyan]{username}:{password}[/cyan]")
            return True
    except ftplib.error_perm as e:
        console.print(f"[red][FAILED][/red] {username}:{password} - {e}")
        return False
    except Exception as e:
        console.print(f"[bold red][FAILURE][/bold red] Could not connect to FTP server at {ip}")
        console.print(f"Reason: {e}")
        return False

# Brute-force UI integration
def brute_force_ftp(ip, username, wordlist_path, fast_mode=False):
    try:
        with open(wordlist_path, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        console.print(f"[bold red][ERROR][/bold red] Failed to load wordlist: {e}")
        return

    if fast_mode:
        for password in tqdm(passwords, desc="Brute-forcing", unit="pw"):
            if TEST_MODE and password == "naruto":
                console.print(f"[bold green][SIMULATED SUCCESS][/bold green] Login with [cyan]{username}:{password}[/cyan]")
                found_password = password
                break
            if try_ftp_login(ip, username, password):
                console.print(f"\n[bold green]✅ Login Successful[/bold green]")
                console.print(f"[bold green]→ Credentials: [cyan]{username}:{password}[/cyan][/bold green]\n")
                return
        console.print(f"\n[bold red]❌ No valid FTP credentials found.[/bold red]\n")
        return

    spinner = Spinner("dots", text="Trying passwords...")
    found_password = None

    with Live(spinner, refresh_per_second=12, transient=True) as live:
        for i, password in enumerate(
            tqdm(passwords, desc="Brute-forcing", unit="pw",
                 bar_format="{l_bar}{bar} | {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
                 ncols=80, ascii=" █")
        ):
            table = Table(title="Brute-Force Status")
            table.add_column("Status", justify="left")
            table.add_row(f"[bold blue]Attempt {i+1} of {len(passwords)}[/bold blue]")
            table.add_row(f"[white]Trying password:[/] [cyan]{password}[/cyan]")

            group = Group(spinner, table)
            live.update(group)

            time.sleep(0.1)

            if TEST_MODE and password == "naruto":
                console.print(f"\n[bold green][SIMULATED SUCCESS][/bold green] Login with [cyan]{username}:{password}[/cyan]")
                found_password = password
                break

            if try_ftp_login(ip, username, password):
                found_password = password
                break

    if found_password:
        console.print(f"\n[bold green]✅ Login Successful[/bold green]")
        console.print(f"[bold green]→ Credentials: [cyan]{username}:{found_password}[/cyan][/bold green]\n")
    else:
        console.print(f"\n[bold red]❌ No valid FTP credentials found.[/bold red]\n")

# FTP auth test handler
def run_ftp_auth_test(ip, username="FTPUSER", password="TAIL", wordlist_path=None, fast_mode=False):
    if TEST_MODE:
        console.print(f"[bold yellow][TEST MODE][/bold yellow] Simulated FTP test running...")
        if username == "FTPUSER" and password == "naruto":
            console.print(f"[bold green][SIMULATED SUCCESS][/bold green] Login with [cyan]{username}:{password}[/cyan]")
            return
        else:
            console.print(f"[bold red][SIMULATED FAILED][/bold red] {username}:{password} incorrect. Proceeding to brute-force test...")
            if wordlist_path:
                brute_force_ftp(ip, username, wordlist_path, fast_mode)
            else:
                console.print(f"[bold red]No wordlist provided in test mode.[/bold red]")
        return

    console.print(f"[bold yellow][INFO][/bold yellow] Testing FTP login with default credentials...\n")
    if not try_ftp_login(ip, username, password):
        if wordlist_path:
            console.print(f"[bold yellow][INFO][/bold yellow] Default login failed. Starting brute-force with wordlist.")
            brute_force_ftp(ip, username, wordlist_path, fast_mode)
        else:
            console.print(f"[bold red]No valid credentials and no wordlist provided. Skipping brute-force.[/bold red]")

# Main logic with argparse
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber Relay Scanner with FTP Auth")
    parser.add_argument("relay_ip", help="Relay IP address or 'demo'")
    parser.add_argument("--username", help="FTP username", default="FTPUSER")
    parser.add_argument("--password", help="FTP password (skip brute-force if provided)")
    parser.add_argument("--ftpwordlist", help="Optional FTP wordlist to use if login fails")
    parser.add_argument("--test", action="store_true", help="Enable test mode")
    parser.add_argument("--fast", action="store_true", help="Fast mode: skip fancy UI during brute-force")

    args = parser.parse_args()
    relay_ip = args.relay_ip
    TEST_MODE = args.test

    run_ftp_auth_test(
        ip=relay_ip,
        username=args.username,
        password=args.password if args.password else "TAIL",
        wordlist_path=args.ftpwordlist,
        fast_mode=args.fast
    )
