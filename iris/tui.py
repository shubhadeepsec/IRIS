from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Header, Footer, Input, Static
from textual import work
from rich.table import Table
import asyncio

from iris.collectors.domain import DomainCollector
from iris.collectors.email import EmailCollector
from iris.collectors.network import NetworkCollector
from iris import exporters

class IrisApp(App):
    """Main IRIS TUI Application"""
    
    CSS = """
    /* Neon cyan on dark background */
    Screen {
        background: #0a0e27;
        color: #ffffff;
    }

    Header {
        background: #002244;
        color: #00d9ff;
        text-style: bold;
    }
    
    Footer {
        background: #002244;
        color: #00d9ff;
    }

    #main {
        padding: 1 2;
    }

    #banner {
        text-align: center;
        margin-bottom: 1;
        color: #00d9ff;
        text-style: bold;
    }

    #target_input {
        border: solid #00d9ff;
        background: #0a0e27;
        color: #00ff88;
        margin-bottom: 1;
    }

    #results {
        border: solid #00d9ff;
        background: #050814;
        padding: 1;
        height: 1fr;
    }

    .success {
        color: #00ff88;
    }

    .warning {
        color: #ffb000;
    }

    .error {
        color: #ff5555;
    }
    """
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("e", "export", "Export HTML"),
    ]

    def __init__(self):
        super().__init__()
        self.last_data = None
        self.last_target = None
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="main"):
            yield Static("⚡ IRIS v0.1.0 — Unified OSINT Intelligence Platform", id="banner")
            yield Input(id="target_input", placeholder="Enter domain, email, or IP to profile...")
            yield Static("[dim]Waiting for input...[/dim]", id="results")
        yield Footer()
    
    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle user input."""
        target = event.value
        self.query_one("#target_input").value = ""
        self.query_one("#results").update("[yellow]⏳ Gathering intelligence...[/yellow]")
        self.gather_intelligence(target)
    
    @work
    async def gather_intelligence(self, target: str) -> None:
        """Gather OSINT data on target."""
        self.last_target = target
        
        # Determine collector type
        if "@" in target:
            collector = EmailCollector()
        elif target.replace(".", "").isdigit():
            collector = NetworkCollector()
        else:
            collector = DomainCollector()
        
        try:
            data = await collector.collect(target)
            self.last_data = data
            
            # Format results
            table = Table(title=f"Intelligence: {target}", title_style="bold #00d9ff", border_style="#00d9ff")
            table.add_column("Type", style="bold #00ff88")
            table.add_column("Value", style="white")
            
            for key, value in data.items():
                if key != "_raw":
                    table.add_row(key, str(value)[:100] + ("..." if len(str(value)) > 100 else ""))
            
            # Post back to main thread
            self.call_from_thread(self.update_results, table)
        except Exception as e:
            self.call_from_thread(self.update_results, f"[red]Error gathering data: {e}[/red]")
        finally:
            await collector.close()

    def update_results(self, renderable):
        self.query_one("#results").update(renderable)
    
    def action_export(self) -> None:
        """Export results to HTML."""
        if self.last_data and self.last_target:
            filename = f"iris_{self.last_target.replace('.', '_').replace('@', '_at_')}.html"
            exporters.html_export(self.last_data, filename)
            self.notify(f"Exported to {filename}", title="Export Success")
        else:
            self.notify("No data to export. Search a target first.", title="Export Failed", severity="warning")

if __name__ == "__main__":
    app = IrisApp()
    app.run()
