"""D05 — Persistence detector.

Catches:
- Windows Run keys
- Startup folders
- schtasks/crontab
- systemd unit paths
"""

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile


class D05Persistence(Detector):
    @property
    def detector_id(self) -> str:
        return "d05"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        persistence_strings = [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "schtasks",
            "crontab",
            "systemctl",
            "/etc/systemd/system/",
            "/etc/cron",
            "Startup",
            "startup",
            "schtasks.exe",
            "cmd.exe /c schtasks",
            "powershell -command",
        ]

        for s in cp.all_strings():
            for ps in persistence_strings:
                if ps.lower() in s.lower():
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            "",
                            0,
                            f"Persistence mechanism: {ps}",
                            Severity.HIGH,
                            matched_value=s[:200],
                        )
                    )

        return evidence
