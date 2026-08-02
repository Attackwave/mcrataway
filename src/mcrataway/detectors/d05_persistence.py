"""D05 — Persistence detector.

Catches:
- Windows Run keys and Startup folder paths
- schtasks/crontab/systemd unit paths

Design note: a bare identifier like "schtasks" or "crontab" appears in
help text, documentation strings, and error messages of entirely
benign mods (e.g. a server-admin utility mod that *talks about*
cron). Rated on its own, such a string is only a weak signal (LOW).
It is only escalated to HIGH when the same class also contains a
process-execution capability (D01) — i.e. the mod can actually *run*
the persistence command it references, not just mention it.
"""

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence, EvidenceIndex
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile

# Concrete paths/commands that are strong, specific persistence
# indicators on their own — these do not appear in ordinary mod code
# or documentation, so they stay HIGH regardless of co-occurrence.
_STRONG_PERSISTENCE_INDICATORS = [
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "\\Start Menu\\Programs\\Startup",
    "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "/etc/systemd/system/",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "schtasks.exe",
    "cmd.exe /c schtasks",
]

# Bare identifiers that are weak on their own — common in
# documentation, log messages, and command wrappers that never
# actually establish persistence.
_WEAK_PERSISTENCE_INDICATORS = [
    "schtasks",
    "crontab",
    "systemctl",
    "/etc/cron",
    "powershell -command",
]


class D05Persistence(Detector):
    @property
    def detector_id(self) -> str:
        return "d05"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        cp = class_file.constant_pool
        return self._scan_strings(class_file, cp.all_strings(), obfuscated=False)

    def analyze_reconstructed_strings(
        self, class_file: ClassFile, strings: list[str]
    ) -> list[Evidence]:
        return self._scan_strings(class_file, strings, obfuscated=True)

    def _scan_strings(
        self, class_file: ClassFile, strings: list[str], obfuscated: bool
    ) -> list[Evidence]:
        # Deduplicate per (indicator) — the same indicator matching
        # multiple constant-pool strings must not inflate the evidence
        # count the VerdictAggregator thresholds on.
        strong_hits: dict[str, str] = {}
        weak_hits: dict[str, str] = {}

        for s in strings:
            for ind in _STRONG_PERSISTENCE_INDICATORS:
                if ind.lower() in s.lower() and ind not in strong_hits:
                    strong_hits[ind] = s
            for ind in _WEAK_PERSISTENCE_INDICATORS:
                if ind.lower() in s.lower() and ind not in weak_hits:
                    weak_hits[ind] = s

        evidence: list[Evidence] = []
        prefix = "Obfuscated persistence mechanism" if obfuscated else "Persistence mechanism"
        strong_severity = Severity.CRITICAL if obfuscated else Severity.HIGH
        for ind, matched in strong_hits.items():
            evidence.append(
                self._add_evidence(
                    class_file, "", 0,
                    f"{prefix}: {ind}",
                    strong_severity,
                    matched_value=matched[:200],
                )
            )

        weak_prefix = (
            "Obfuscated persistence-related identifier"
            if obfuscated else "Persistence-related identifier"
        )
        weak_severity = Severity.MEDIUM if obfuscated else Severity.LOW
        for ind, matched in weak_hits.items():
            evidence.append(
                self._add_evidence(
                    class_file, "", 0,
                    f"{weak_prefix}: {ind}",
                    weak_severity,
                    matched_value=matched[:200],
                    context={"weak_indicator": "1", "indicator": ind},
                )
            )

        return evidence

    @staticmethod
    def escalate_weak_indicators(index: "EvidenceIndex") -> None:
        """Escalate weak D05 identifiers to HIGH when the same class also
        has a process-execution capability (D01) — the mod can actually
        run the command it references, not merely mention it.

        Called by the verdict/correlation layer after all detectors have
        run, since it needs cross-detector, class-scoped evidence.
        """
        for class_name, evs in index._class_evidence.items():
            if not index.has_cooccurring(class_name, "d05", "d01"):
                continue
            for ev in evs:
                if ev.detector_id == "d05" and ev.context.get("weak_indicator") == "1":
                    ev.severity = Severity.HIGH
                    ev.description = ev.description.replace(
                        "identifier", "mechanism (co-occurring with process execution)"
                    )
