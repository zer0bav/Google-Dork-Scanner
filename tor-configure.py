#!/usr/bin/env python3
import os
import json
import csv
from collections import Counter, defaultdict
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import sys
import asyncio
import time
import shutil
import re
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from stem import process
from stem.util import term
import socks
import socket

console = Console()

# a global variable to store the socks port number
socks_port_found = None
# regex to capture the port number from Tor's output
port_regex = re.compile(r"Socks listener listening on port (\d+)\.")

def check_stem_installed():
    """checks if the 'stem' library is installed."""
    try:
        import stem
    except ImportError:
        return False
    return True

async def launch_tor_proxy():
    """
    launches a new tor process and creates a proxy.
    returns the proxy address if successful, otherwise None.
    """
    global socks_port_found

    if not check_stem_installed():
        console.print(Panel.fit(
            "[red]error: 'stem' library is not installed.[/red]\n"
            "[yellow]run this command to install:[/yellow]\n"
            "[green]pip install stem[/green]",
            title="[bold red]stem Library Missing[/bold red]"
        ))
        return None

    try:
        from stem import process
        from stem.util import term
    except ImportError:
        console.print(f"[red][!] 'stem' library is required but not installed. please run 'pip install stem'.[/red]")
        return None

    def tor_init_msg_handler(line):
        """function to process tor output and find the socks port."""
        global socks_port_found
        print(term.format(line, term.Color.BLUE))
        match = port_regex.search(line)
        if match:
            socks_port_found = int(match.group(1))

    try:
        console.print("[yellow][*] starting tor proxy...[/yellow]")
        # launch a new tor process and use a custom handler to process its output.
        tor_process = process.launch_tor_with_config(
            config = {
                'SocksPort': 'auto'
            },
            init_msg_handler = tor_init_msg_handler
        )
        
        # wait until the port number is found in the output.
        while socks_port_found is None:
            await asyncio.sleep(0.5)
            
        proxy_address = f"socks5://127.0.0.1:{socks_port_found}"
        console.print(f"[green][✓] tor proxy successfully started on {proxy_address}.[/green]")
        console.print("[yellow][*] the proxy will remain active as long as this window is open.[/yellow]")
        
        return tor_process
    
    except Exception as e:
        console.print(f"[red][!] an error occurred while starting tor: {e}[/red]")
        
        # provide tor installation instructions based on the operating system and distribution.
        console.print("\n[yellow]this error indicates that the tor program is not installed on your system.[/yellow]")
        console.print("[cyan]install tor using the appropriate command below for your operating system:[/cyan]")
        
        # check linux distribution
        if sys.platform.startswith('linux'):
            if shutil.which('apt-get'):
                console.print(f"  [green]for debian/ubuntu:[/green] [white]sudo apt-get install tor[/white]")
            elif shutil.which('pacman'):
                console.print(f"  [green]for arch linux:[/green] [white]sudo pacman -S tor[/white]")
            elif shutil.which('dnf'):
                console.print(f"  [green]for fedora:[/green] [white]sudo dnf install tor[/white]")
            else:
                console.print(f"  [green]for linux:[/green] [white]please use your distribution's package manager to install the 'tor' package.[/white]")
        elif sys.platform == 'darwin':
            console.print(f"  [green]for macos:[/green] [white]brew install tor[/white] [dim](homebrew must be installed)[/dim]")
        elif sys.platform == 'win32':
            console.print(f"  [green]for windows:[/green] [white]download and install tor from the official website: https://www.torproject.org/download/[/white]")
        
        return None

async def main():
    """main function to launch the tor proxy."""
    tor_proc = await launch_tor_proxy()
    
    # if the tor process was successfully started, keep the script running.
    if tor_proc:
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        except KeyboardInterrupt:
            console.print("\n[yellow][*] stopped by user.[/yellow]")
        finally:
            tor_proc.kill() # terminate the tor process on exit.

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        console.print(f"[red][!] an error occurred while running the main function: {e}[/red]")
