from __future__ import annotations

import typer
from rich.console import Console

app = typer.Typer(help="Ship/no-ship pre-deploy gate for AI-generated backend apps and bots.")
console = Console()


@app.command()
def scan(path: str = ".") -> None:
    """Placeholder scan command while the MVP is planned."""
    console.print(f"[bold yellow]Vibegate planning build.[/bold yellow] Target: {path}")
    console.print("Implementation plan lives in docs/plans/.")


if __name__ == "__main__":
    app()
