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

console = Console()

def load_jsonl(path):
    """
    loads dork scan results from a .jsonl file.
    """
    results = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                results.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
    return results

def load_csv(path):
    """
    loads dork scan results from a .csv file.
    """
    results = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append(row)
    return results

def analyze(results):
    """
    analyzes the dork scan results and prints summaries.
    """
    stats = defaultdict(int)
    category_counter = Counter()
    sensitive_counter = 0
    domain_counter = Counter()

    # process all results to gather summary statistics
    for r in results:
        stats["total_results"] += 1
        cat = r.get("category", "unknown").lower()
        category_counter[cat] += 1
        if r.get("sensitive_hint") in [True, "True"]:
            sensitive_counter += 1
        url = r.get("url")
        if url:
            domain = urlparse(url).netloc.lower()
            domain_counter[domain] += 1

    # print summary statistics using rich panels
    console.print(Panel(f"[bold green]total results: {stats['total_results']}[/bold green]\n"
                        f"[bold red]sensitive data: {sensitive_counter}[/bold red]\n", title="general statistics"))

    table = Table(title="results by category")
    table.add_column("category", style="cyan")
    table.add_column("count", style="green")
    for cat, count in category_counter.most_common():
        table.add_row(cat, str(count))
    console.print(table)

    table2 = Table(title="top domains (top 10)")
    table2.add_column("domain", style="magenta")
    table2.add_column("count", style="yellow")
    for dom, count in domain_counter.most_common(10):
        table2.add_row(dom, str(count))
    console.print(table2)

    # print detailed results list
    console.print(Panel.fit("[bold cyan]detailed results list[/bold cyan]"))
    detailed_table = Table(show_header=True, header_style="bold bright_blue")
    detailed_table.add_column("category", style="cyan")
    detailed_table.add_column("dork", style="magenta")
    detailed_table.add_column("url", style="green")
    
    for r in results:
        category = r.get("category", "unknown")
        dork = r.get("dork", "unknown")
        url = r.get("url", "no url")
        
        # add a hint for sensitive data if it exists
        if r.get("sensitive_hint"):
            url = f"[bold red]sensitive data: {url}[/bold red]"
            
        detailed_table.add_row(category, dork, url)
        
    console.print(detailed_table)


def main():
    """
    main entry point for the analysis script.
    """
    console.print(Panel("[bold cyan]gds analysis script[/bold cyan]"))
    jsonl_path = "gds_output/results.jsonl"
    csv_path = "gds_output/results.csv"

    results = []
    if os.path.exists(jsonl_path):
        console.print(f"[green]jsonl file loaded: {jsonl_path}[/green]")
        results = load_jsonl(jsonl_path)
    elif os.path.exists(csv_path):
        console.print(f"[green]csv file loaded: {csv_path}[/green]")
        results = load_csv(csv_path)
    else:
        console.print("[red]results file not found![/red]")
        return

    if not results:
        console.print("[yellow]file is empty or invalid.[/yellow]")
        return

    analyze(results)

if __name__ == "__main__":
    main()
