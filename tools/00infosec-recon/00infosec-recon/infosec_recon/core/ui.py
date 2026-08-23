from __future__ import annotations

import sys

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from .. import BRAND, TAGLINE, __version__

THEME = Theme({
    "primary": "bold #00f0ff",
    "accent": "bold #c084fc",
    "warn": "bold #ffaa00",
    "ok": "bold #00ff88",
    "err": "bold #ff0044",
    "muted": "#7d8590",
    "critical": "bold #ff3366",
    "high": "bold #ffaa00",
    "host": "#00f0ff",
    "label": "bold #f0f6fc",
})

BANNER = (
    ("     ██████╗  ██████╗ ", "██╗███╗   ██╗███████╗ ██████╗ ███████╗███████╗ ██████╗"),
    ("    ██╔═████╗██╔═████╗", "██║████╗  ██║██╔════╝██╔═══██╗██╔════╝██╔════╝██╔════╝"),
    ("    ██║██╔██║██║██╔██║", "██║██╔██╗ ██║█████╗  ██║   ██║███████╗█████╗  ██║     "),
    ("    ████╔╝██║████╔╝██║", "██║██║╚██╗██║██╔══╝  ██║   ██║╚════██║██╔══╝  ██║     "),
    ("    ╚██████╔╝╚██████╔╝", "██║██║ ╚████║██║     ╚██████╔╝███████║███████╗╚██████╗"),
    ("     ╚═════╝  ╚═════╝ ", "╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚══════╝╚══════╝ ╚═════╝"),
)


class UI:
    def __init__(self, no_banner: bool = False, stderr: bool = False):
        import sys as _sys
        self.console = Console(
            theme=THEME, highlight=False, force_terminal=True,
            legacy_windows=False, color_system="truecolor",
            file=_sys.stderr if stderr else None,
        )
        if not no_banner:
            self.print_banner()

    def print_banner(self):
        art = Text("\n")
        for zeroes, infosec in BANNER:
            art.append(zeroes, style="bold #ff0000")
            art.append(infosec + "\n", style="bold #ffffff")
        art.append("         R E C O N  ::  U N I F I E D  F R A M E W O R K",
                   style="muted")
        self.console.print(art)
        self.console.print(f"  [muted]{BRAND} v{__version__}[/muted] [accent]:: {TAGLINE}[/accent]")
        self.console.print()

    def status_panel(self, rows: list[tuple[str, str]]) -> Panel:
        tbl = Table.grid(padding=(0, 2))
        tbl.add_column(style="muted", justify="right")
        tbl.add_column(style="label")
        for k, v in rows:
            tbl.add_row(k, str(v))
        return Panel(tbl, title="[primary]/ preflight /[/primary]", border_style="primary")

    @staticmethod
    def live_dashboard(results: dict, ctx) -> Group:
        done = sum(1 for r in results.values() if r.status == "done")
        run = sum(1 for r in results.values() if r.status == "running")
        errs = sum(1 for r in results.values() if r.status == "err")
        total = len(results)

        def card(label, value, style):
            t = Text()
            t.append(f"{value}\n", style=f"bold {style}")
            t.append(label, style="muted")
            return Panel(t, border_style=style, padding=(0, 1))

        cards = Group(
            *(x for x in [
                card("DONE", f"{done}/{total}", "ok"),
                card("RUN", str(run), "warn" if run else "muted"),
                card("ERR", str(errs), "err" if errs else "muted"),
                card("FINDINGS", str(len(ctx.findings)), "accent"),
                card("ELAPSED", f"{ctx.elapsed:.0f}s", "primary"),
            ])
        )
        tbl = Table(show_header=True, header_style="accent", expand=True)
        tbl.add_column("module", style="label", no_wrap=True)
        tbl.add_column("status", justify="center", width=10)
        tbl.add_column("elapsed", style="muted", justify="right", width=9)
        tbl.add_column("findings", justify="right", width=8)
        tbl.add_column("info", style="muted", max_width=60)
        for name, r in results.items():
            icon = {"running": "[warn]●[/warn]", "done": "[ok]✓[/ok]",
                    "err": "[err]✗[/err]", "skipped": "[muted]⊘[/muted]"}.get(
                r.status, "[muted]○[/muted]")
            info = r.error or ""
            if not info and r.stats:
                info = ", ".join(f"{k}={v}" for k, v in list(r.stats.items())[:4])
            tbl.add_row(name, icon,
                        f"{r.elapsed:.1f}s" if r.status in ("done", "err") else "-",
                        str(len(r.findings)) if r.findings else "-", info[:60])
        return Group(cards, Text(""), tbl)


class LiveUI:
    def __init__(self, ui: UI, results: dict, ctx):
        self.results = results
        self.ctx = ctx
        self.live = Live(console=ui.console, refresh_per_second=2,
                         get_renderable=lambda: UI.live_dashboard(
                             self.results, self.ctx))

    async def __aenter__(self):
        self.live.start()
        return self

    async def __aexit__(self, *exc):
        self.refresh()
        self.live.stop()

    def refresh(self):
        try:
            self.live.update(UI.live_dashboard(self.results, self.ctx))
        except Exception:
            pass
