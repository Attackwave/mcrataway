"""JSON report writer."""

import json
from pathlib import Path

from mcrataway.reporting.model import ScanReport


class JsonWriter:
    """Write scan reports as JSON."""

    @staticmethod
    def write(report: ScanReport, path: Path) -> None:
        """Write a scan report to a JSON file."""
        with open(path, "w") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
