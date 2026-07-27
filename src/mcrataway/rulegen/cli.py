"""`mcrataway rulegen` — analyze a directory of malware samples and
propose a detection rule.

Kept in a separate module from cli.py so the main CLI file does not
have to carry rulegen-specific logic, mirroring how other subsystems
(scan engine, rule loading) live in their own packages.
"""

from __future__ import annotations

from pathlib import Path

import click

from mcrataway.constants import CONFIG_DIR, Severity
from mcrataway.rulegen.engine import RuleGenEngine
from mcrataway.rules.yaml_writer import write_proposal

PROPOSED_RULES_DIR = CONFIG_DIR / "rules" / "proposed"


@click.command()
@click.argument("sample_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--family", required=True, help="Malware family name for this rule.")
@click.option(
    "-o", "--output", type=click.Path(path_type=Path), default=None,
    help="Output YAML path (default: ~/.mcrataway/rules/proposed/<family>.proposed.yaml)",
)
@click.option("--min-sample-fraction", default=0.6, type=float)
@click.option(
    "--severity", default="medium",
    type=click.Choice(["low", "medium", "high", "critical"]),
)
@click.option("--condition", default="count() >= 2")
def rulegen(
    sample_dir: Path,
    family: str,
    output: Path | None,
    min_sample_fraction: float,
    severity: str,
    condition: str,
) -> None:
    """Analyze malware samples in SAMPLE_DIR and propose a detection
    rule.

    Output requires human review before being trusted/signed — see
    docs/RULES.md.
    """
    engine = RuleGenEngine(min_sample_fraction=min_sample_fraction)
    proposal = engine.generate_from_directory(
        sample_dir,
        family,
        severity=getattr(Severity, severity.upper()),
        condition=condition,
    )

    if output is None:
        PROPOSED_RULES_DIR.mkdir(parents=True, exist_ok=True)
        output = PROPOSED_RULES_DIR / f"{family}.proposed.yaml"
    else:
        output.parent.mkdir(parents=True, exist_ok=True)

    write_proposal(proposal, output)
    click.echo(f"Wrote proposed rule '{proposal.definition.rule_id}' to {output}")
    click.echo(proposal.notes)
    click.echo("This proposal has NOT been reviewed — see docs/RULES.md before trusting it.")
