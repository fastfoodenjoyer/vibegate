from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from vibegate.scanner import Scanner

app = typer.Typer(help="Ship/no-ship pre-deploy gate for AI-generated backend apps and bots.")
console = Console()


@app.callback()
def main() -> None:
    """Vibegate command group."""


@app.command()
def scan(path: Path = typer.Argument(Path("."))) -> None:
    """Scan a backend project and print a ship/no-ship verdict."""
    result = Scanner().scan(path)

    console.print(f"[bold]Target:[/bold] {path}")
    console.print(f"[bold]Verdict:[/bold] {result.summary.verdict.value}")
    console.print(f"[bold]Findings:[/bold] {result.summary.total} findings")

    for finding in result.findings:
        location = f" ({finding.path})" if finding.path else ""
        console.print(f"- [{finding.severity.value}] {finding.title}{location}")


if __name__ == "__main__":
    app()
