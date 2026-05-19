from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from vibegate.profiles import ProfileRegistry, UnknownProfileError
from vibegate.scanner import Scanner

app = typer.Typer(help="Ship/no-ship pre-deploy gate for AI-generated backend apps and bots.")
profiles_app = typer.Typer(help="List Vibegate scan profiles.")
app.add_typer(profiles_app, name="profiles")
console = Console()


@app.callback()
def main() -> None:
    """Vibegate command group."""


@app.command()
def scan(
    path: Path = typer.Argument(Path(".")),
    profile: Annotated[
        list[str] | None,
        typer.Option(
            "--profile",
            help="Profile ID to run. Repeat to run multiple profiles. Auto-detects when omitted.",
        ),
    ] = None,
) -> None:
    """Scan a backend project and print a ship/no-ship verdict."""
    try:
        result = Scanner().scan(path, profile_ids=profile)
    except (UnknownProfileError, FileNotFoundError) as error:
        console.print(str(error), style="bold red")
        raise typer.Exit(code=2) from error

    console.print(f"[bold]Target:[/bold] {path}")
    profiles_text = ", ".join(result.active_profile_ids) if result.active_profile_ids else "none"
    console.print(f"[bold]Profiles:[/bold] {profiles_text}")
    console.print(f"[bold]Verdict:[/bold] {result.summary.verdict.value}")
    console.print(f"[bold]Findings:[/bold] {result.summary.total} findings")

    for finding in result.findings:
        location = f" ({finding.path})" if finding.path else ""
        console.print(f"- [{finding.severity.value}] {finding.title}{location}", markup=False)


@profiles_app.command("list")
def list_profiles() -> None:
    """List available scan profiles."""
    for profile in ProfileRegistry.default().list_profiles():
        console.print(f"{profile.profile_id}: {profile.description}")


if __name__ == "__main__":
    app()
