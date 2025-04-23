import time
from rich import print
from rich.console import Console, Group
from rich.table import Table
from rich.live import Live
from rich.spinner import Spinner
from tqdm import tqdm

console = Console()

# Simulated login logic (replace with real FTP logic)
def simulate_login(username, password):
    if password == "hunter2":
        console.print(f"[bold green][SUCCESS][/bold green] Logged in with [cyan]{username}:{password}[/cyan]")
        return True
    else:
        console.print(f"[red][FAILED][/red] {username}:{password} - 530 Login authentication failed")
        return False

# Brute-force demo with live password visibility
def simulate_brute_force(username, password_list):
    console.print(f"\n[bold yellow][INFO][/bold yellow] Starting brute-force with {len(password_list)} passwords...\n")

    spinner = Spinner("dots", text="Trying passwords...")
    found_password = None

    with Live(spinner, refresh_per_second=12, transient=True) as live:
        for i, password in enumerate(
            tqdm(password_list, desc="Brute-forcing", unit="pw",
                 bar_format="{l_bar}{bar} | {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
                 ncols=80,
                 ascii=" █")
        ):
            # Build a fresh table for each update
            table = Table(title="Brute-Force Status")
            table.add_column("Status", justify="left")

            table.add_row(f"[bold blue]Attempt {i+1} of {len(password_list)}[/bold blue]")
            table.add_row(f"[white]Trying password:[/] [cyan]{password}[/cyan]")

            # Group spinner + table
            group = Group(spinner, table)
            live.update(group)

            time.sleep(0.1)  # Simulated network delay
            if simulate_login(username, password):
                found_password = password
                break

    # Final result
    if found_password:
        console.print(f"\n[bold green]✅ Login Successful[/bold green]")
        console.print(f"[bold green]→ Credentials: [cyan]{username}:{found_password}[/cyan][/bold green]\n")
    else:
        console.print("\n[bold red]❌ No valid credentials found.[/bold red]\n")

# Demo runner
if __name__ == "__main__":
    console.print("[bold blue]🚀 Stylish FTP UI Test Starting...[/bold blue]\n")

    username = "testuser"
    default_password = "wrongpass"

    console.print("[bold yellow][INFO][/bold yellow] Trying default credentials first...\n")
    if not simulate_login(username, default_password):
        passwords = ["123456", "password", "letmein", "hunter2", "admin"]
        simulate_brute_force(username, passwords)

    console.print("[bold green]✅ UI test complete.[/bold green]")
