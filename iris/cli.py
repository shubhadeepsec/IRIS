import asyncio
import ipaddress
import os
from typing import Optional
import typer
from rich.console import Console
from rich.columns import Columns
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.styles import Style

from iris.collectors.domain import DomainCollector
from iris.collectors.email import EmailCollector
from iris.collectors.network import NetworkCollector
from iris.collectors.code import CodeCollector
from iris import exporters
from iris.db import cache
from iris import config

__version__ = "0.1.0"

app = typer.Typer(
    name="iris",
    help="Unified OSINT intelligence platform.",
    no_args_is_help=False,
)
console = Console()


def print_banner():
    logo = Text()
    logo.append("               ▄▄               \n", style="bold #d7a8ff")
    logo.append("              ████              \n", style="bold #c380ff")
    logo.append("             ██████             \n", style="bold #a855f7")
    logo.append("            ████████            \n", style="bold #a855f7")
    logo.append("           ██████████           \n", style="bold #a855f7")
    logo.append("▄▄▄▄▄▄▄▄▄▄████████████▄▄▄▄▄▄▄▄▄▄\n", style="bold #9333ea")
    logo.append("████████████████████████████████\n", style="bold #9333ea")
    logo.append("▀▀▀▀▀▀▀▀▀██████████████▀▀▀▀▀▀▀▀▀\n", style="bold #7e22ce")
    logo.append("              ████              \n", style="bold #6b21a8")
    logo.append("             ██████             \n", style="bold #6b21a8")
    logo.append("              ████              \n", style="bold #581c87")
    logo.append("               ▀▀               ", style="bold #581c87")

    info = Text()
    info.append("\n\n\nIRIS OSINT Platform ", style="bold white")
    info.append(f"v{__version__}\n", style="dim")
    info.append("See everything. Know everyone.\n", style="dim")
    info.append("Type [bold cyan]?[/bold cyan] for help, [bold cyan]quit[/bold cyan] to exit.", style="dim")

    console.print("\n")
    console.print(Columns([logo, info], padding=(0, 2)))
    console.print("\n")


def _detect_collector(target: str, force_type: Optional[str] = None):
    """Detect the correct collector based on target type."""
    if force_type == "code":
        return CodeCollector()
    try:
        ipaddress.ip_address(target)
        return NetworkCollector()
    except ValueError:
        pass
    if "@" in target:
        return EmailCollector()
    return DomainCollector()


async def _run_collection(target: str, collector) -> Optional[dict]:
    """Run collection and close session in the same event loop."""
    try:
        return await collector.collect(target)
    finally:
        await collector.close()


def _print_domain_results(data: dict) -> None:
    """Print domain results in grouped sections."""
    console.print()

    # --- WHOIS Section ---
    whois_table = Table(box=None, show_header=False, padding=(0, 2))
    whois_table.add_column("Key", style="bold #00ff88", width=18)
    whois_table.add_column("Value", style="white")
    for k in ["Domain", "Registrar", "Created", "Expires", "Status"]:
        if k in data:
            whois_table.add_row(f"  {k}", str(data[k]))
    console.print(Panel(whois_table, title="[bold #a855f7]WHOIS[/bold #a855f7]", border_style="#3b1a7a"))

    # --- DNS Section ---
    dns_table = Table(box=None, show_header=False, padding=(0, 2))
    dns_table.add_column("Key", style="bold #00ff88", width=18)
    dns_table.add_column("Value", style="white")
    for k in ["A Records", "MX Records", "NS Records", "TXT Records", "SPF", "DMARC"]:
        if k in data and data[k] and data[k] != "None":
            dns_table.add_row(f"  {k}", str(data[k])[:160])
    console.print(Panel(dns_table, title="[bold #a855f7]DNS[/bold #a855f7]", border_style="#3b1a7a"))

    # --- SSL Section ---
    ssl_table = Table(box=None, show_header=False, padding=(0, 2))
    ssl_table.add_column("Key", style="bold #00ff88", width=18)
    ssl_table.add_column("Value", style="white")
    for k in ["SSL Issuer", "SSL Expires", "SSL Alt Names"]:
        if k in data and data[k] and data[k] != "Unknown":
            ssl_table.add_row(f"  {k}", str(data[k])[:160])
    console.print(Panel(ssl_table, title="[bold #a855f7]SSL / TLS[/bold #a855f7]", border_style="#3b1a7a"))

    # --- Subdomains Section ---
    raw = data.get("_raw", {})
    subdomains = raw.get("subdomains", [])
    if subdomains:
        sub_table = Table(box=None, show_header=False, padding=(0, 2))
        sub_table.add_column("Subdomain", style="#c4b5fd")
        for sub in subdomains[:30]:
            sub_table.add_row(f"  {sub}")
        title = f"[bold #a855f7]Subdomains[/bold #a855f7] [dim]({len(subdomains)} found)[/dim]"
        if len(subdomains) > 30:
            title += " [dim]— showing first 30[/dim]"
        console.print(Panel(sub_table, title=title, border_style="#3b1a7a"))

    console.print()


def _print_generic_results(data: dict) -> None:
    """Print results as a flat table for email/network collectors."""
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Attribute", style="bold #00ff88", width=20)
    table.add_column("Value", style="white")
    for k, v in data.items():
        if k != "_raw":
            val_str = str(v)
            table.add_row(f"  ● {k}", val_str[:160] + ("..." if len(val_str) > 160 else ""))
    console.print()
    console.print(Panel(table, title="[bold #a855f7]Results[/bold #a855f7]", border_style="#3b1a7a"))
    console.print()


def run_profile(target: str, export: str = "none", force_type: Optional[str] = None) -> None:
    collector = _detect_collector(target, force_type=force_type)

    try:
        with console.status(f"[dim]Gathering intelligence on [bold cyan]{target}[/bold cyan]...[/dim]", spinner="dots"):
            data = asyncio.run(_run_collection(target, collector))

        # Print sectioned or generic output
        if isinstance(collector, DomainCollector):
            _print_domain_results(data)
        else:
            _print_generic_results(data)

        if export != "none":
            filename = f"iris_{target.replace('.', '_').replace('@', '_at_')}.{export}"
            if export == "json":
                exporters.json_export(data, filename)
            elif export == "html":
                exporters.html_export(data, filename)
            elif export == "csv":
                exporters.csv_export(data, filename)
            console.print(f"  [dim]✓ Export saved → {filename}[/dim]\n")

    except Exception as e:
        console.print(f"\n  [red]✗ Error: {e}[/red]\n")


def _print_history() -> None:
    """Show recently queried targets from the cache."""
    from iris.db.models import Domain, Email
    from iris.db.cache import get_session
    session = get_session()
    try:
        domains = session.query(Domain).order_by(Domain.updated_at.desc()).limit(10).all()
        emails = session.query(Email).order_by(Email.created_at.desc()).limit(10).all()

        if not domains and not emails:
            console.print("\n  [dim]No history yet. Profile a target first.[/dim]\n")
            return

        table = Table(box=None, show_header=True, padding=(0, 2))
        table.add_column("Type", style="dim", width=10)
        table.add_column("Target", style="bold #c4b5fd", width=35)
        table.add_column("Last Queried", style="dim")

        for d in domains:
            ts = d.updated_at.strftime("%Y-%m-%d %H:%M") if d.updated_at else "—"
            table.add_row("domain", d.domain, ts)
        for e in emails:
            ts = e.created_at.strftime("%Y-%m-%d %H:%M") if e.created_at else "—"
            table.add_row("email", e.email, ts)

        console.print()
        console.print(Panel(table, title="[bold #a855f7]History[/bold #a855f7]", border_style="#3b1a7a"))
        console.print()
    finally:
        session.close()


shell_style = Style.from_dict({
    'prompt': 'bold #ffffff',
    'bottom-toolbar': 'bg:#1e1e1e #888888',
})


def interactive_shell():
    print_banner()

    session = PromptSession(style=shell_style)
    export_mode = "none"

    def get_bottom_toolbar():
        export_text = f"Export: {export_mode.upper()} (/export to cycle)"
        return FormattedText([
            ('class:bottom-toolbar', f'  IRIS {__version__}   |   {export_text}   |   ? for help')
        ])

    while True:
        try:
            console.print(Rule(style="dim #3b1a7a"))
            text = session.prompt('› ', bottom_toolbar=get_bottom_toolbar).strip()

            if not text:
                continue

            cmd = text.lower()

            if cmd in ["exit", "quit", "/quit"]:
                console.print("\n  [dim]Goodbye.[/dim]\n")
                break

            if cmd in ["clear", "cls", "/clear"]:
                console.clear()
                print_banner()
                continue

            if cmd == "?":
                help_table = Table(box=None, show_header=False, padding=(0, 2))
                help_table.add_column("Command", style="bold cyan", width=20)
                help_table.add_column("Description", style="white")
                help_table.add_row("  <target>", "Profile a domain, IP, or email")
                help_table.add_row("  /code <target>", "Search GitHub for a domain/org name")
                help_table.add_row("  /config set <KEY>=<VAL>", "Set an API key (e.g. HIBP_API_KEY=123)")
                help_table.add_row("  /status", "Check configured API keys")
                help_table.add_row("  /export", "Cycle export mode: none → html → json → csv")
                help_table.add_row("  /history", "Show recently profiled targets")
                help_table.add_row("  clear", "Clear the terminal")
                help_table.add_row("  quit", "Exit IRIS")
                console.print()
                console.print(Panel(help_table, title="[bold #a855f7]Commands[/bold #a855f7]", border_style="#3b1a7a"))
                console.print()
                continue

            if cmd == "/export":
                modes = ["none", "html", "json", "csv"]
                idx = modes.index(export_mode)
                export_mode = modes[(idx + 1) % len(modes)]
                console.print(f"\n  [dim]● Export mode → [bold]{export_mode.upper()}[/bold][/dim]\n")
                continue

            if cmd == "/history":
                _print_history()
                continue

            if cmd == "/status":
                keys = config.load_config()
                if not keys:
                    console.print("\n  [dim]No API keys configured.[/dim]\n")
                else:
                    console.print("\n  [bold #a855f7]Configured API Keys:[/bold #a855f7]")
                    for k in keys:
                        console.print(f"  ● [bold cyan]{k}[/bold cyan] = [dim]...{keys[k][-4:]}[/dim]")
                console.print()
                continue

            if text.startswith("/config set "):
                parts = text[12:].split("=", 1)
                if len(parts) == 2:
                    k, v = parts[0].strip().upper(), parts[1].strip()
                    config.set_api_key(k, v)
                    console.print(f"\n  [dim]✓ Saved {k}[/dim]\n")
                else:
                    console.print("\n  [red]✗ Usage: /config set KEY=VALUE[/red]\n")
                continue

            if cmd.startswith("/code "):
                run_profile(text[6:].strip(), export_mode, force_type="code")
                continue

            run_profile(text, export_mode)

        except KeyboardInterrupt:
            continue
        except EOFError:
            break


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version and exit.", is_eager=True),
):
    if version:
        console.print(f"IRIS v{__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        cache.init_db()
        interactive_shell()


@app.command()
def profile(
    target: str = typer.Argument(..., help="Domain, email, or IP to profile"),
    export: str = typer.Option("none", help="Export format: json|html|csv"),
):
    """Profile a target across all OSINT sources."""
    cache.init_db()
    print_banner()
    run_profile(target, export)


if __name__ == "__main__":
    app()
