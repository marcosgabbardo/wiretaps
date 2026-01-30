"""
Terminal UI Dashboard for wiretaps.

Real-time monitoring of LLM API traffic with PII detection alerts.
"""

import asyncio
from datetime import datetime

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Static

from wiretaps.storage import LogEntry, Storage


class StatsPanel(Static):
    """Display aggregate statistics."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.storage = Storage()

    def compose(self) -> ComposeResult:
        yield Static(id="stats-content")

    def on_mount(self) -> None:
        self.update_stats()

    def update_stats(self) -> None:
        stats = self.storage.get_stats()
        content = self.query_one("#stats-content", Static)
        
        pii_pct = stats["pii_percentage"]
        pii_color = "red" if pii_pct > 10 else "yellow" if pii_pct > 0 else "green"
        
        text = Text()
        text.append("📊 ", style="bold")
        text.append(f"Requests: {stats['total_requests']:,}  ", style="cyan")
        text.append(f"Tokens: {stats['total_tokens']:,}  ", style="blue")
        text.append(f"PII Alerts: {stats['requests_with_pii']}", style=pii_color)
        text.append(f" ({pii_pct:.1f}%)  ", style=pii_color)
        text.append(f"Errors: {stats['errors']}", style="red" if stats['errors'] > 0 else "dim")
        
        content.update(text)


class RequestTable(DataTable):
    """Table showing recent requests."""

    BINDINGS = [
        Binding("enter", "select_row", "View Details"),
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.storage = Storage()
        self.cursor_type = "row"
        self.zebra_stripes = True

    def on_mount(self) -> None:
        self.add_columns("Time", "Method", "Endpoint", "Status", "Tokens", "PII")
        self.refresh_data()

    def refresh_data(self, pii_only: bool = False) -> None:
        """Refresh table with latest data."""
        self.clear()
        entries = self.storage.get_logs(limit=100, pii_only=pii_only)
        
        for entry in entries:
            time_str = entry.timestamp.strftime("%H:%M:%S")
            
            # Status color
            if entry.status >= 500:
                status = Text(str(entry.status), style="red bold")
            elif entry.status >= 400:
                status = Text(str(entry.status), style="yellow")
            else:
                status = Text(str(entry.status), style="green")
            
            # PII indicator
            if entry.pii_types:
                pii = Text(f"⚠️ {len(entry.pii_types)}", style="red bold")
            else:
                pii = Text("✓", style="green dim")
            
            # Truncate endpoint
            endpoint = entry.endpoint[:40] + "..." if len(entry.endpoint) > 40 else entry.endpoint
            
            self.add_row(
                time_str,
                entry.method,
                endpoint,
                status,
                f"{entry.tokens:,}",
                pii,
                key=str(entry.id),
            )


class DetailPanel(Static):
    """Panel showing request/response details."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.storage = Storage()

    def show_entry(self, entry_id: int) -> None:
        """Display details for a specific entry."""
        entries = self.storage.get_logs(limit=1000)
        entry = next((e for e in entries if e.id == entry_id), None)
        
        if not entry:
            self.update("Entry not found")
            return
        
        text = Text()
        
        # Header
        text.append(f"\n{'─' * 60}\n", style="dim")
        text.append(f"📝 Request #{entry.id}\n", style="bold cyan")
        text.append(f"{'─' * 60}\n\n", style="dim")
        
        # Metadata
        text.append("Time: ", style="bold")
        text.append(f"{entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
        text.append("Endpoint: ", style="bold")
        text.append(f"{entry.method} {entry.endpoint}\n")
        text.append("Status: ", style="bold")
        status_style = "green" if entry.status < 400 else "red"
        text.append(f"{entry.status}\n", style=status_style)
        text.append("Tokens: ", style="bold")
        text.append(f"{entry.tokens:,}\n")
        text.append("Duration: ", style="bold")
        text.append(f"{entry.duration_ms}ms\n")
        
        # PII Alert
        if entry.pii_types:
            text.append("\n⚠️  PII DETECTED: ", style="red bold")
            text.append(", ".join(entry.pii_types) + "\n", style="red")
        
        # Request body (truncated)
        text.append(f"\n{'─' * 30} REQUEST {'─' * 30}\n", style="dim")
        req_preview = entry.request_body[:1000]
        if len(entry.request_body) > 1000:
            req_preview += f"\n... [{len(entry.request_body) - 1000} more chars]"
        text.append(req_preview + "\n", style="dim white")
        
        # Response body (truncated)
        text.append(f"\n{'─' * 30} RESPONSE {'─' * 29}\n", style="dim")
        resp_preview = entry.response_body[:1000]
        if len(entry.response_body) > 1000:
            resp_preview += f"\n... [{len(entry.response_body) - 1000} more chars]"
        text.append(resp_preview + "\n", style="dim white")
        
        if entry.error:
            text.append(f"\n❌ Error: {entry.error}\n", style="red")
        
        self.update(text)


class WiretapsDashboard(App):
    """Main dashboard application."""

    CSS = """
    Screen {
        layout: grid;
        grid-size: 2 3;
        grid-columns: 2fr 1fr;
        grid-rows: auto 1fr auto;
    }
    
    #stats-panel {
        column-span: 2;
        height: 3;
        background: $surface;
        padding: 0 1;
    }
    
    #request-table {
        height: 100%;
        border: solid $primary;
    }
    
    #detail-panel {
        height: 100%;
        border: solid $secondary;
        overflow-y: auto;
        padding: 0 1;
    }
    
    #footer-bar {
        column-span: 2;
        height: 1;
        background: $surface;
        color: $text;
    }
    
    DataTable {
        height: 100%;
    }
    
    DataTable > .datatable--cursor {
        background: $accent;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("p", "toggle_pii", "PII Only"),
        Binding("c", "clear_detail", "Clear"),
    ]

    TITLE = "wiretaps"
    SUB_TITLE = "LLM Traffic Monitor"

    pii_only = reactive(False)

    def compose(self) -> ComposeResult:
        yield Header()
        yield StatsPanel(id="stats-panel")
        yield RequestTable(id="request-table")
        yield DetailPanel(id="detail-panel")
        yield Footer()

    def on_mount(self) -> None:
        """Start auto-refresh on mount."""
        self.auto_refresh()

    @work(exclusive=True)
    async def auto_refresh(self) -> None:
        """Periodically refresh data."""
        while True:
            await asyncio.sleep(2)
            self.refresh_all()

    def refresh_all(self) -> None:
        """Refresh all panels."""
        stats = self.query_one(StatsPanel)
        stats.update_stats()
        
        table = self.query_one(RequestTable)
        table.refresh_data(pii_only=self.pii_only)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection."""
        if event.row_key:
            entry_id = int(event.row_key.value)
            detail = self.query_one(DetailPanel)
            detail.show_entry(entry_id)

    def action_refresh(self) -> None:
        """Manual refresh."""
        self.refresh_all()
        self.notify("Refreshed!")

    def action_toggle_pii(self) -> None:
        """Toggle PII-only filter."""
        self.pii_only = not self.pii_only
        self.refresh_all()
        status = "ON" if self.pii_only else "OFF"
        self.notify(f"PII filter: {status}")

    def action_clear_detail(self) -> None:
        """Clear detail panel."""
        detail = self.query_one(DetailPanel)
        detail.update("")


def run_dashboard() -> None:
    """Run the dashboard application."""
    app = WiretapsDashboard()
    app.run()


if __name__ == "__main__":
    run_dashboard()
