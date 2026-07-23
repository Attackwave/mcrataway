"""CLI entry point commands."""

import json
import webbrowser
from pathlib import Path

import click
import rich

from mcrataway.config import UserConfig, ensure_config_dir
from mcrataway.constants import DEFAULT_HOST, DEFAULT_PORT
from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.discovery.os_paths import discover_roots
from mcrataway.discovery.walker import FileWalker
from mcrataway.reporting.console_writer import ConsoleWriter
from mcrataway.rules.loader import RulePackLoader


@click.group()
@click.version_option(package_name="mcrataway")
def main() -> None:
    """mcrataway - Minecraft mod malware scanner."""
    ensure_config_dir()


@main.command()
@click.argument("paths", nargs=-1, required=False)
@click.option(
    "--report",
    "report_path",
    type=click.Path(),
    default=None,
    help="Write full JSON report to this path.",
)
@click.option(
    "--quarantine/--no-quarantine",
    default=None,
    help="Override quarantine setting from config.",
)
@click.option(
    "--rules",
    "rule_pack",
    type=click.Path(exists=True),
    default=None,
    help="Additional YAML rule pack to load.",
)
@click.option("--auto", "auto_discover", is_flag=True, help="Auto-discover Minecraft roots.")
def scan(
    paths: tuple[str, ...],
    report_path: str | None,
    quarantine: bool | None,
    rule_pack: str | None,
    auto_discover: bool,
) -> None:
    """Scan specified paths or auto-discovered Minecraft roots."""
    config = UserConfig.load()

    roots: list[Path] = []
    if paths:
        roots = [Path(p) for p in paths]
    elif auto_discover:
        roots = discover_roots(config.custom_roots)

    if not roots:
        rich.print("[red]No paths to scan. Use --auto or provide paths.[/red]")
        raise SystemExit(1)

    if quarantine is not None:
        config.quarantine_malicious = quarantine

    rule_loader = RulePackLoader()
    rule_loader.load_defaults()
    if rule_pack:
        rule_loader.load_pack(Path(rule_pack))

    quarantine_mgr = QuarantineManager(
        do_quarantine_malicious=config.quarantine_malicious,
        do_quarantine_suspicious=config.quarantine_suspicious,
    )

    engine = ScanEngine(
        rules=rule_loader.all_rules(),
        quarantine=quarantine_mgr,
        max_workers=config.max_workers,
        whitelisted_hashes=config.whitelisted_hashes,
        excluded_paths=config.excluded_paths,
    )

    is_game_layout = auto_discover or (
        bool(paths) and all(r.name in (".minecraft", "instances", "PrismLauncher") for r in roots)
    )

    walker = FileWalker(
        scan_archives=config.scan_archives,
        scan_scripts=config.scan_scripts,
        scan_configs=config.scan_configs,
        max_depth=config.max_recursion_depth,
        # Explicit user paths are scanned in full unless they explicitly point to
        # a known game root like .minecraft, in which case we restrict to scan subdirs.
        restrict_to_scan_subdirs=is_game_layout,
    )

    rich.print(f"[bold]Scanning {len(roots)} root(s)...[/bold]")

    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    ) as progress:
        for root in roots:
            task = progress.add_task(f"[cyan]Discovering files in {root.name}...", total=None)
            
            files = walker.walk(root)
            if not files:
                progress.stop_task(task)
                progress.update(task, description=f"[dim]Finished {root.name} (0 files)[/dim]")
                continue

            progress.update(task, description=f"[green]Scanning {root.name}...", total=len(files))
            
            def update_progress(f: Path) -> None:
                progress.update(task, advance=1, description=f"[green]Scanning: [dim]{f.name}[/dim]")
                
            results.extend(engine.scan_files(files, root=str(root), on_progress=update_progress))
            progress.update(task, description=f"[green]Finished {root.name}")

    report = engine.build_report(roots, results)

    console = ConsoleWriter()
    console.print_report(report)

    if report_path:
        with open(report_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
        rich.print(f"\n[dim]Report written to {report_path}[/dim]")

    malicious = sum(1 for r in results if r.verdict.value == "MALICIOUS")
    suspicious = sum(1 for r in results if r.verdict.value == "SUSPICIOUS")
    rich.print(f"\n[bold]Results:[/bold] {malicious} malicious, "
               f"{suspicious} suspicious, {len(results)} total")


@main.command()
@click.option("--host", default=DEFAULT_HOST, help="Bind address (default: 127.0.0.1).")
@click.option("--port", default=DEFAULT_PORT, type=int, help="Port (default: 8765).")
@click.option("--reload", "hot_reload", is_flag=True, help="Enable dev hot-reload.")
@click.option("--no-browser", "skip_browser", is_flag=True, help="Do not open browser on startup.")
def serve(host: str, port: int, hot_reload: bool, skip_browser: bool) -> None:
    """Start the web server."""
    import uvicorn

    from mcrataway.server.app import create_app

    url = f"http://{host}:{port}"
    rich.print(f"[bold green]mcrataway[/bold green] starting at {url}")
    if not skip_browser:
        webbrowser.open(url)

    if hot_reload:
        uvicorn.run(
            "mcrataway.server.app:create_app",
            host=host,
            port=port,
            factory=True,
            reload=True,
            loop="auto",
        )
    else:
        app = create_app()
        uvicorn.run(
            app,
            host=host,
            port=port,
            loop="auto",
        )
