import asyncio
import typer
from rich.console import Console
from rich.panel import Panel

from iris.collectors.domain import DomainCollector
from iris.collectors.email import EmailCollector
from iris.collectors.network import NetworkCollector
from iris import exporters
from iris.db import cache

app = typer.Typer(
    name="iris",
    help="Unified OSINT intelligence platform. See everything. Know everyone.",
    no_args_is_help=False,
)
console = Console()

BANNER = """[bold cyan]
╔═══════════════════════════════════════════════════════════════╗
║                        ⚡ IRIS ⚡                             ║
║           Unified OSINT Intelligence Platform                ║
║                                                               ║
║         See everything. Know everyone.                       ║
╚═══════════════════════════════════════════════════════════════╝
[/bold cyan]"""

@app.callback(invoke_without_command=True)
def root(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        console.print(BANNER)
        # Initialize DB
        cache.init_db()
        # Launch TUI
        try:
            from iris.tui import IrisApp
            app_tui = IrisApp()
            app_tui.run()
        except ImportError:
            console.print("[red]Error loading TUI. Make sure Textual is installed.[/red]")

@app.command()
def profile(
    target: str = typer.Argument(..., help="Domain, email, or IP to profile"),
    export: str = typer.Option("json", help="Export format: json|html|csv"),
):
    """Profile a target across all OSINT sources."""
    cache.init_db()
    console.print(BANNER)
    console.print(f"\n[cyan]🔍 Gathering intelligence on {target}...\n[/cyan]")
    
    # Determine target type and instantiate collector
    if "@" in target:
        collector = EmailCollector()
    elif target.replace(".", "").isdigit():
        collector = NetworkCollector()
    else:
        collector = DomainCollector()
    
    # Collect data
    try:
        data = asyncio.run(collector.collect(target))
        
        # Display summary in console
        console.print(Panel(f"Results for {target}", style="bold green"))
        for k, v in data.items():
            if k != "_raw":
                console.print(f"[bold cyan]{k}:[/bold cyan] {v}")

        # Export
        filename = f"iris_{target.replace('.', '_').replace('@', '_at_')}.{export}"
        if export == "json":
            exporters.json_export(data, filename)
        elif export == "html":
            exporters.html_export(data, filename)
        elif export == "csv":
            exporters.csv_export(data, filename)
        else:
            console.print(f"[red]Unsupported export format: {export}[/red]")
            return
            
        console.print(f"\n[green]✅ Export saved to {filename}[/green]\n")
    finally:
        asyncio.run(collector.close())

if __name__ == "__main__":
    app()
