import argparse
import asyncio
import json
import csv
import os
import re
import time
import aiohttp
import socks
import socket
from urllib.parse import quote_plus
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# default configuration
DEFAULT_CONCURRENCY = 6
DEFAULT_DELAY = 1.5
# updated user-agent to mimic a real browser
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
# added more headers to better mimic a real browser request
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,application/signed-exchange;v=b3;q=0.9",
    "Accept-Language": "en-US,en;q=0.9,tr;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive"
}
DUCKDUCKGO_HTML = "https://html.duckduckgo.com/html/"

console = Console()

# loads dorks from a json file
def load_dorks(path="dorks.json"):
    """
    Loads dork lists from a JSON file.
    """
    if not os.path.exists(path):
        console.print(f"[red][!] dorks file '{path}' not found. please create it and add dorks.[/red]")
        return {}
    
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    normalized = {}
    for k, v in data.items():
        if isinstance(v, list):
            if len(v) == 1 and isinstance(v[0], dict):
                normalized[k] = v[0]
            else:
                normalized[k] = {"description": "", "risk": "unknown", "dorks": v}
        else:
            normalized[k] = v
    return normalized

# checks if the category is sensitive
def is_sensitive_category(cat_meta):
    """
    Checks if a category is marked as sensitive.
    """
    return cat_meta.get("sensitive", False) or cat_meta.get("risk", "") in ["high", "critical"]

# creates a safe filename
def safe_filename(name):
    """
    Sanitizes a string to create a safe filename.
    """
    return re.sub(r"[^a-zA-Z0-9_-]", "_", name)

# google custom search api query
async def google_cse_search(session, api_key, cx, q, num=10):
    """
    Performs a search using the Google Custom Search API.
    """
    url = "https://www.googleapis.com/customsearch/v1"
    params = {"key": api_key, "cx": cx, "q": q, "num": min(num, 10)}
    try:
        async with session.get(url, params=params, timeout=30) as resp:
            if resp.status != 200:
                text = await resp.text()
                if resp.status == 400:
                    error_message = json.loads(text).get("error", {}).get("message", "unknown api error.")
                    raise RuntimeError(f"google cse api error ({resp.status}): {error_message}")
                raise RuntimeError(f"google cse api returned an unexpected status code: {resp.status} - {text[:200]}")
            
            return await resp.json()
    except aiohttp.ClientError as e:
        raise RuntimeError(f"network error: {e}")

# duckduckgo html scraping - no retries on forbidden
async def duckduckgo_search(session, q, num=10):
    """
    Scrapes DuckDuckGo's HTML page for search results.
    If a 403 Forbidden error is encountered, it stops immediately.
    """
    url = DUCKDUCKGO_HTML + "?q=" + quote_plus(q)
    
    try:
        async with session.get(url, headers=HEADERS, timeout=30) as resp:
            # Check for 403 Forbidden status code
            if resp.status == 403:
                console.print(f"[red][!] Network error: 403 Forbidden. DuckDuckGo may be blocking automated requests.[/red]")
                return [] # Return an empty list immediately

            resp.raise_for_status()  # raise for other HTTP errors
            text = await resp.text()
    except aiohttp.ClientError as e:
        console.print(f"[red][!] Network error: {e}[/red]")
        return [] # Return an empty list on other network errors
            
    soup = BeautifulSoup(text, "html.parser")
    links = []
    
    # Attempt 1: Look for the 'result__url' class, as seen in the user's screenshot.
    for a_tag in soup.find_all("a", class_="result__url", href=True):
        link = a_tag["href"]
        if link.startswith("http") and link not in links:
            links.append(link)
    
    if links:
        console.print(f"[green][✓] Found {len(links)} links using 'result__url' method.[/green]")
        return links[:num]
    
    # Attempt 2: A more general search for links within result containers.
    for result_div in soup.find_all("div", class_="result"):
        a_tag = result_div.find("a", href=True)
        if a_tag and a_tag.get("href"):
            link = a_tag["href"]
            if link.startswith("http") and link not in links:
                links.append(link)
    
    if links:
        console.print(f"[green][✓] Found {len(links)} links using 'result' container method.[/green]")
        return links[:num]
    
    console.print(f"[yellow][!] No results found on the page.[/yellow]")
    return []

# fetches page content and metadata
async def fetch_page(session, url, timeout=30):
    """
    Fetches the content of a given URL and extracts metadata.
    """
    headers = {"User-Agent": USER_AGENT}
    try:
        async with session.get(url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
            resp.raise_for_status()
            text = await resp.text(errors="ignore")
            title = None
            try:
                soup = BeautifulSoup(text, "html.parser")
                if soup.title:
                    title = soup.title.string.strip()
            except Exception:
                title = None
            return {"url": str(resp.url), "status": resp.status, "title": title, "content_snippet": text[:2000]}
    except Exception as e:
        return {"url": url, "status": "error", "error": str(e) or "unknown error"}

# regex for sensitive content detection
SENSITIVE_REGEX = re.compile(
    r"(password|passwd|pwd|aws_access_key_id|aws_secret_access_key|private key|BEGIN PRIVATE KEY|api_key|access_token)", re.I
)

def find_sensitive_in_text(text):
    """
    Checks for sensitive keywords in a given text string.
    """
    return bool(text and SENSITIVE_REGEX.search(text))

# create a TCP connector with socks proxy support
def create_socks_connector(host, port, ssl_verify):
    """
    Creates an aiohttp.TCPConnector that uses a SOCKS proxy.
    """
    conn = aiohttp.TCPConnector(ssl=ssl_verify)

    # Wrap the connect method to use socks proxy
    async def connect(req, *args, **kwargs):
        sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        sock.set_proxy(socks.SOCKS5, host, port)
        await asyncio.get_event_loop().sock_connect(sock, (req.url.host, req.url.port))
        
        # Manually create a new connector with the established socket
        conn_with_sock = aiohttp.TCPConnector(ssl=ssl_verify)
        
        # Override the request's connection to use our new socket
        req.conn = aiohttp.TCPConnector(ssl=ssl_verify)
        req.conn._socket = sock
        return await conn_with_sock.connect(req, *args, **kwargs)

    # Monkey patch the connector's _connect method
    conn._connect = connect
    return conn


# main scanner class
class Scanner:
    """
    Main class for running the dork scanning process.
    """
    def __init__(self, args, dorks):
        self.args = args
        self.dorks = dorks
        self.sem = asyncio.Semaphore(args.concurrency)
        self.results = []
        self.seen_urls = set()
        self.start_time = time.time()
        self._ensure_output_files()

    def _ensure_output_files(self):
        """
        Ensures the output files and directories exist.
        """
        outdir = self.args.output_dir
        jsonl_path = os.path.join(outdir, "results.jsonl")
        csv_path = os.path.join(outdir, "results.csv")
        
        if not os.path.exists(jsonl_path):
            try:
                with open(jsonl_path, "w", encoding="utf-8") as f:
                    pass
                console.print(f"[green][✓] jsonl file '{jsonl_path}' created.[/green]")
            except Exception as e:
                console.print(f"[red][!] error creating jsonl file: {e}[/red]")
        
        header = ["timestamp","category","dork","query","url","status","title","sensitive_hint","error"]
        if not os.path.exists(csv_path):
            try:
                with open(csv_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(header)
                console.print(f"[green][✓] csv file '{csv_path}' created with headers.[/green]")
            except Exception as e:
                console.print(f"[red][!] error creating csv file: {e}[/red]")

    async def run(self):
        """
        Runs the main dork scanning logic.
        """
        # Use a ProxyConnector from aiohttp_socks if the --tor flag is set
        if self.args.tor:
            try:
                connector = create_socks_connector("127.0.0.1", self.args.tor_port, not self.args.ignore_ssl)
                console.print(f"[yellow][*] using tor proxy at 127.0.0.1:{self.args.tor_port}.[/yellow]")
            except Exception as e:
                console.print(f"[red][!] Error creating ProxyConnector: {e}. Please check your aiohttp_socks installation and proxy settings.[/red]")
                return
        else:
            connector = aiohttp.TCPConnector(ssl=not self.args.ignore_ssl)

        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            categories = [self.args.category] if self.args.category else list(self.dorks.keys())
            
            if not categories:
                console.print("[red][!] no dorks found. please check your dorks.json file.[/red]")
                return

            for cat in categories:
                if cat not in self.dorks:
                    console.print(f"[red][!] category '{cat}' not found, skipping.[/red]")
                    continue
                meta = self.dorks[cat]
                if is_sensitive_category(meta) and not self.args.allow_sensitive:
                    console.print(f"[yellow][!] sensitive category '{cat}' skipped. use --allow-sensitive to enable.[/yellow]")
                    continue
                dork_list = meta.get("dorks", [])
                
                if not dork_list:
                    console.print(f"[yellow][!] category '{cat}' has an empty dork list, skipping.[/yellow]")
                    continue

                console.print(f"[green][+] running category '{cat}' ({len(dork_list)} dorks).[/green]")
                for dork in dork_list:
                    query = f"site:{self.args.target} {dork}" if self.args.target else dork
                    await asyncio.sleep(self.args.delay)
                    await self._run_single_dork(session, cat, dork, query)

    async def _run_single_dork(self, session, category, dork, query):
        """
        Executes a single dork query and processes the results.
        """
        async with self.sem:
            console.print(f"[cyan][dork][/cyan] {dork}  -> [white]{query}[/white]")
            
            all_hits = []
            
            # Check for Google API key and CX code
            if self.args.google_api_key and self.args.google_cx:
                try:
                    console.print(f"[yellow][*] trying google cse api...[/yellow]")
                    cse = await google_cse_search(session, self.args.google_api_key, self.args.google_cx, query, num=self.args.num)
                    if cse and "items" in cse:
                        all_hits.extend([it.get("link") for it in cse["items"] if it.get("link")])
                    if not all_hits:
                        console.print(f"[yellow][!] google cse returned no results, falling back to duckduckgo.[/yellow]")
                except Exception as e:
                    console.print(f"[red][!] google cse error: {e} - falling back to duckduckgo.[/red]")
            
            # Fallback to DuckDuckGo if no Google API hits or if credentials are not provided
            if not all_hits or not self.args.google_api_key:
                try:
                    console.print(f"[yellow][*] trying duckduckgo search...[/yellow]")
                    duckduckgo_hits = await duckduckgo_search(session, query, num=100)
                    all_hits.extend(duckduckgo_hits)
                except Exception as e:
                    console.print(f"[red][!] duckduckgo error: {str(e) or 'unknown error'}[/red]")
            
            if not all_hits:
                 console.print(f"[yellow][!] no results found for the query from the search engine: {query}[/yellow]")
                 return

            console.print(f"[green][✓] Found {len(all_hits)} total links. Processing up to {self.args.num}.[/green]")

            # Filter for new, unseen URLs
            new_hits = [u for u in all_hits if u not in self.seen_urls]
            self.seen_urls.update(new_hits)
            
            # Process only the number of new hits requested by the user
            hits_to_process = new_hits[:self.args.num]

            if hits_to_process:
                for url in hits_to_process:
                    record = {"timestamp": time.time(), "category": category, "dork": dork, "query": query, "url": url}
                    if self.args.snapshot:
                        snap = await fetch_page(session, url)
                        record.update(snap)
                        if find_sensitive_in_text(record.get("content_snippet", "")):
                            record["sensitive_hint"] = True
                    self.results.append(record)
                    self._dump_record(record)
            else:
                 console.print(f"[yellow][!] no new results found for the query: {query}[/yellow]")

            await asyncio.sleep(0.2)

    def _dump_record(self, record):
        """
        Appends a record to the output files.
        """
        outdir = self.args.output_dir
        jsonl_path = os.path.join(outdir, "results.jsonl")
        csv_path = os.path.join(outdir, "results.csv")
        
        try:
            with open(jsonl_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            console.print(f"[green][✓] jsonl entry added: {record['url']}[/green]")
        except Exception as e:
            console.print(f"[red][!] error writing to jsonl ({jsonl_path}): {e}[/red]")
            
        header = ["timestamp","category","dork","query","url","status","title","sensitive_hint","error"]
        write_header = not os.path.exists(csv_path)
        try:
            with open(csv_path, "a", newline="", encoding="utf-8") as cf:
                writer = csv.writer(cf)
                if write_header:
                    writer.writerow(header)
                row = [record.get(h) for h in header]
                writer.writerow(row)
            console.print(f"[green][✓] csv entry added: {record['url']}[/green]")
        except Exception as e:
            console.print(f"[red][!] error writing to csv ({csv_path}): {e}[/red]")


# cli parser
def parse_args():
    """
    Parses command-line arguments.
    """
    p = argparse.ArgumentParser(description="gds.py — google dork scanner (ethical use only)")
    p.add_argument("-c", "--category", help="category to run (e.g., files).")
    p.add_argument("-t", "--target", help="target specific domain (e.g., example.com).")
    p.add_argument("-n", "--num", type=int, default=5, help="number of results per dork")
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    p.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="delay between queries in seconds")
    p.add_argument("--google-api-key", dest="google_api_key", help="google api key")
    p.add_argument("--google-cx", dest="google_cx", help="google custom search cx code")
    p.add_argument("--allow-sensitive", action="store_true", help="allow sensitive categories")
    p.add_argument("--snapshot", action="store_true", help="save html snapshots")
    p.add_argument("--output-dir", default="gds_output", help="output directory")
    p.add_argument("--ignore-ssl", action="store_true", help="disable ssl verification")
    p.add_argument("--dorks-file", default="dorks.json", help="path to dorks json file.")
    p.add_argument("--tor", action="store_true", help="route traffic through tor.")
    p.add_argument("--tor-port", type=int, default=9050, help="tor socks proxy port (default: 9050).")
    return p.parse_args()

# banner
def print_banner():
    """
    Prints the ASCII banner.
    """
    banner = Text("""
██╗███╗   ██╗████████╗██████╗  ██████╗ ██╗   ██╗███████╗██████╗ ████████╗
██║████╗  ██║╚══██╔══╝██╔══██╗██╔═══██╗██║   ██║██╔════╝██╔══██╗╚══██╔══╝
██║██╔██╗ ██║   ██║   ██████╔╝██║   ██║██║   ██║█████╗  ██████╔╝   ██║   
██║██║╚██╗██║   ██║   ██╔══██╗██║   ██║██║   ██║██╔══╝  ██╔══██╗   ██║   
██║██║ ╚████║   ██║   ██    ██╚██████╔╝╚██████╔╝███████╗██║  ██║   ██║   
╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═════╝  ╚═════╝  ╚═════╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   
""", style="bold magenta")
    console.print(banner)
    console.print(Panel.fit(" [cyan]google dork scanner[/cyan] - created by [bold red]zer0bav[/bold red] ", border_style="bright_blue"))
    console.print(Text("author: zer0bav", style="dim white"))

# help table
def print_help_table():
    """
    Prints the available parameters in a formatted table.
    """
    table = Table(title="available parameters", show_header=True, header_style="bold green")
    table.add_column("parameter", style="cyan", no_wrap=True)
    table.add_column("description", style="white")
    table.add_row("-c, --category", "category to run.")
    table.add_row("-t", "--target", "run on a specific domain.")
    table.add_row("-n", "--num", "number of results per dork.")
    table.add_row("--concurrency", "number of simultaneous requests.")
    table.add_row("--delay", "delay between queries in seconds.")
    table.add_row("--google-api-key", "google api key (optional).")
    table.add_row("--google-cx", "google custom search cx code.")
    table.add_row("--allow-sensitive", "allow sensitive categories.")
    table.add_row("--snapshot", "save html snapshots")
    table.add_row("--output-dir", "output directory.")
    table.add_row("--ignore-ssl", "disable ssl verification.")
    table.add_row("--dorks-file", "path to dorks json file.")
    table.add_row("--tor", "route traffic through tor.")
    table.add_row("--tor-port", "tor socks proxy port (default: 9050).")
    console.print(table)

# main function
def main():
    """
    The entry point for the scanner.
    """
    args = parse_args()
    print_banner()
    print_help_table()

    outdir = args.output_dir
    try:
        os.makedirs(outdir, exist_ok=True)
        console.print(f"[yellow][*] output directory check: '{outdir}' created or already exists.[/yellow]")
    except Exception as e:
        console.print(f"[red][!] error creating output directory '{outdir}': {e}[/red]")
        return 

    dorks = load_dorks(args.dorks_file)
    
    if not dorks:
        console.print("[red][!] dorks not loaded. exiting.[/red]")
        return

    scanner = Scanner(args, dorks)
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        console.print("[red][!] interrupted by user.[/red]")
    finally:
        console.print(f"[green][+] done. results saved to: {args.output_dir}[/green]")
        console.print(f"    - jsonl: {os.path.join(args.output_dir,'results.jsonl')}")
        console.print(f"    - csv:  {os.path.join(args.output_dir,'results.csv')}")

if __name__ == "__main__":
    main()
