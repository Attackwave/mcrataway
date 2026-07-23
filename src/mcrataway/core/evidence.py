"""Evidence index — class-scoped correlation gate for detector findings."""

from dataclasses import dataclass, field

from mcrataway.constants import Severity


@dataclass
class Evidence:
    """A single piece of evidence found by a detector."""

    detector_id: str
    severity: Severity
    class_name: str
    method_name: str
    offset: int
    description: str
    matched_value: str = ""
    context: dict[str, str] = field(default_factory=dict)


class EvidenceIndex:
    """Correlation index for all evidence found in a class file.

    Detectors add evidence here. The index enables cross-detector correlation:
    e.g., a class with both network I/O and credential access escalates.
    """

    def __init__(self) -> None:
        self.evidence: list[Evidence] = []
        self._class_evidence: dict[str, list[Evidence]] = {}
        self._capability_flags: dict[str, bool] = {}

    def add(self, ev: Evidence) -> None:
        self.evidence.append(ev)
        if ev.class_name not in self._class_evidence:
            self._class_evidence[ev.class_name] = []
        self._class_evidence[ev.class_name].append(ev)

    def add_many(self, items: list[Evidence]) -> None:
        for ev in items:
            self.add(ev)

    def get_for_class(self, class_name: str) -> list[Evidence]:
        return self._class_evidence.get(class_name, [])

    def has_capability(self, class_name: str, capability: str) -> bool:
        """Check if a capability flag has been set for this class.

        Capabilities are explicit tags set via :meth:`set_capability_flag`
        (e.g. ``"network"``, ``"persistence"``). The previous
        implementation checked ``capability in e.detector_id``, which
        never matched because detector IDs are short codes like
        ``d01``–``d12`` or ``rule:...`` rather than human-readable
        capability names.
        """
        return self.is_capability_set(class_name, capability)

    def get_max_severity_for_class(self, class_name: str) -> Severity:
        """Get the highest severity found in a class."""
        evs = self._class_evidence.get(class_name, [])
        if not evs:
            return Severity.INFO
        return max(e.severity for e in evs)

    def has_cooccurring(
        self, class_name: str, detector_id_a: str, detector_id_b: str
    ) -> bool:
        """Check if two detector types both fired in the same class."""
        evs = self._class_evidence.get(class_name, [])
        has_a = any(detector_id_a in e.detector_id for e in evs)
        has_b = any(detector_id_b in e.detector_id for e in evs)
        return has_a and has_b

    def set_capability_flag(self, class_name: str, capability: str) -> None:
        self._capability_flags[f"{class_name}:{capability}"] = True

    def is_capability_set(self, class_name: str, capability: str) -> bool:
        return self._capability_flags.get(f"{class_name}:{capability}", False)

    def get_all_urls(self) -> list[str]:
        """Extract all URL-like values from evidence."""
        urls: list[str] = []
        for ev in self.evidence:
            val = ev.matched_value
            if val and (val.startswith("http://") or val.startswith("https://")):
                urls.append(val)
        return urls

    def get_all_ips(self) -> list[str]:
        """Extract all IP addresses from evidence."""
        import re
        ips: list[str] = []
        for ev in self.evidence:
            val = ev.matched_value
            if val:
                matches = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', val)
                ips.extend(matches)
        return list(set(ips))

    def summary(self) -> dict[str, object]:
        """Return a summary of the evidence index."""
        by_detector: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for ev in self.evidence:
            by_detector[ev.detector_id] = by_detector.get(ev.detector_id, 0) + 1
            by_severity[ev.severity.name] = by_severity.get(ev.severity.name, 0) + 1
        return {
            "total": len(self.evidence),
            "by_detector": by_detector,
            "by_severity": by_severity,
            "classes_with_evidence": len(self._class_evidence),
        }
