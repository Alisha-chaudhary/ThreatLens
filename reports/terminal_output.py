import os
from rich.console     import Console
from rich.panel       import Panel
from rich.table       import Table
from rich.progress    import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt      import Prompt
from rich.columns     import Columns
from rich.text        import Text
from rich.rule        import Rule
from rich.align       import Align
from rich import box

console = Console()

# ── Severity colour map ───────────────────────────────────────────────────────
SEV_STYLE = {
    "Critical": "bold red",
    "High"    : "bold yellow",
    "Medium"  : "bold orange3",
    "Low"     : "bold green",
    "Info"    : "bold blue",
}


# ─────────────────────────────────────────────────────────────────────────────
def print_banner():
    banner = Text()
    banner.append("""
  _____ _                    _   _
 |_   _| |__  _ __ ___  __ _| |_| |    ___ _ __  ___
   | | | '_ \\| '__/ _ \\/ _` | __| |   / _ \\ '_ \\/ __|
   | | | | | | | |  __/ (_| | |_| |__|  __/ | | \\__ \\
   |_| |_| |_|_|  \\___|\\__,_|\\__|_____\\___|_| |_|___/
""", style="bold green")
    banner.append("\n   Threat Intelligence & Vulnerability Scanner", 
                  style="dim white")
    banner.append("\n   For authorised use only\n", style="dim red")

    console.print(Align.center(banner))
    console.print(Rule(style="green"))


# ─────────────────────────────────────────────────────────────────────────────
def print_scan_start(target: str, target_type: str):
    console.print()
    console.print(Panel(
        f"[bold white]Target :[/] [cyan]{target}[/]\n"
        f"[bold white]Type   :[/] [cyan]{target_type}[/]",
        title="[bold green]Scan Initiated[/]",
        border_style="green",
        expand=False
    ))
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
def live_progress(tasks_status: dict):
    """
    Shows a live progress panel while scans run.
    tasks_status = { "nmap": "running", "osint": "done", ... }
    """
    STATUS_ICON = {
        "running": "[yellow]⟳ running[/]",
        "done"   : "[green]✔ done[/]",
        "error"  : "[red]✘ error[/]",
        "waiting": "[dim]◌ waiting[/]",
    }
    table = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    table.add_column("Module", style="bold white")
    table.add_column("Status")

    for name, status in tasks_status.items():
        table.add_row(name, STATUS_ICON.get(status, status))

    console.print(Panel(table,
                        title="[bold cyan]Parallel Scans[/]",
                        border_style="cyan"))

# ─────────────────────────────────────────────────────────────────────────────
def print_summary(target: str, risk: dict, osint: dict, scan: dict):
    score    = risk.get("score", 0)
    severity = risk.get("overall_severity", "Low")
    counts   = risk.get("severity_counts", {})
    findings = risk.get("findings", [])

    console.print()
    console.print(Rule("[bold cyan]Scan Complete[/]", style="cyan"))
    console.print()

    # ── Score panel ───────────────────────────────────────────────────────────
    sev_style = SEV_STYLE.get(severity, "white")
    score_text = Text()
    score_text.append(f"  {score}/100", style=f"bold {sev_style} ")
    score_text.append(f"  [{severity}]", style=sev_style)

    console.print(Panel(
        score_text,
        title="[bold white]Overall Risk Score[/]",
        border_style=sev_style.replace("bold ", ""),
        expand=False,
        padding=(1, 4)
    ))
    console.print()

    # ── Severity breakdown bar chart ─────────────────────────────────────────
    breakdown = Table(
        title="Finding Breakdown",
        box=box.ROUNDED,
        border_style="dim white",
        show_lines=False,
        title_style="bold cyan"
    )
    breakdown.add_column("Severity",  style="bold white", width=12)
    breakdown.add_column("Count",     justify="right",    width=6)
    breakdown.add_column("Bar",                           width=30)

    BAR_COLOURS = {
        "Critical": "red",
        "High"    : "yellow",
        "Medium"  : "orange3",
        "Low"     : "green",
        "Info"    : "blue",
    }
    for sev, colour in BAR_COLOURS.items():
        count = counts.get(sev, 0)
        bar   = Text("█" * min(count * 3, 30), style=colour)
        breakdown.add_row(
            Text(sev, style=f"bold {colour}"),
            str(count),
            bar
        )
    console.print(breakdown)
    console.print()

    # ── Stats row ─────────────────────────────────────────────────────────────
    stats = Table(box=box.SIMPLE_HEAD, border_style="dim",
                  show_header=False, padding=(0, 3))
    stats.add_column("Label", style="dim white")
    stats.add_column("Value", style="bold cyan")
    stats.add_row("Emails found",    str(osint.get("email_count",    0)))
    stats.add_row("Subdomains",      str(osint.get("subdomain_count",0)))
    stats.add_row("Open ports",      str(scan.get("port_count",      0)))
    stats.add_row("Total findings",  str(risk.get("finding_count",   0)))
    console.print(stats)
    console.print()

    # ── Open ports table ──────────────────────────────────────────────────────
    open_ports = scan.get("open_ports", [])
    if open_ports:
        ports_table = Table(
            title="Open Ports",
            box=box.ROUNDED,
            border_style="dim white",
            title_style="bold cyan"
        )
        ports_table.add_column("Port",     style="bold cyan",  width=8)
        ports_table.add_column("Protocol", style="white",      width=10)
        ports_table.add_column("Service",  style="green",      width=14)
        ports_table.add_column("Version",  style="dim white")

        for p in open_ports:
            ports_table.add_row(
                str(p.get("port",     "")),
                p.get("protocol",     ""),
                p.get("service",      ""),
                p.get("version",  "") or p.get("product", "") or "—"
            )
        console.print(ports_table)
        console.print()

    # ── Top findings table ────────────────────────────────────────────────────
    if findings:
        findings_table = Table(
            title="Findings & Recommendations",
            box=box.ROUNDED,
            border_style="dim white",
            title_style="bold cyan",
            show_lines=True
        )
        findings_table.add_column("Severity",       width=10)
        findings_table.add_column("Issue",          width=32)
        findings_table.add_column("Source",         width=14)
        findings_table.add_column("Recommendation", width=36)

        for f in findings:
            sev   = f.get("severity", "Info")
            style = SEV_STYLE.get(sev, "white")
            findings_table.add_row(
                Text(sev, style=style),
                f.get("title",          ""),
                f.get("source",         ""),
                f.get("recommendation", ""),
            )
        console.print(findings_table)
        console.print()

    # ── Download prompt ───────────────────────────────────────────────────────
    _download_prompt()


# ─────────────────────────────────────────────────────────────────────────────
def _download_prompt():
    """
    Asks the user which format to download after the scan.
    """
    console.print(Rule("[bold white]Export Report[/]", style="dim white"))
    console.print()
    console.print("  [bold white]Available formats:[/]")
    console.print("  [cyan][1][/]  PDF  — output/report.pdf")
    console.print("  [cyan][2][/]  HTML — output/report.html")
    console.print("  [cyan][3][/]  JSON — output/raw_results.json")
    console.print("  [cyan][4][/]  All of the above")
    console.print("  [cyan][5][/]  Skip")
    console.print()

    choice = Prompt.ask(
        "  [bold green]Select format[/]",
        choices=["1", "2", "3", "4", "5"],
        default="4"
    )

    actions = {
        "1": ["output/report.pdf"],
        "2": ["output/report.html"],
        "3": ["output/raw_results.json"],
        "4": ["output/report.pdf",
               "output/report.html",
               "output/raw_results.json"],
        "5": [],
    }

    files = actions.get(choice, [])

    if not files:
        console.print("\n  [dim]Skipped export.[/]\n")
        return

    console.print()
    for filepath in files:
        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            console.print(
                f"  [green]✔[/]  [bold white]{filepath}[/]  "
                f"[dim]({size:,} bytes)[/]"
            )
        else:
            console.print(
                f"  [red]✘[/]  {filepath}  [dim](not found)[/]"
            )

    console.print()
    console.print(Panel(
        "[dim]Files are saved in the [bold white]output/[/] folder "
        "in your project directory.\n"
        "You can copy them from there to send to clients.[/]",
        border_style="dim",
        expand=False
    ))
    console.print()

