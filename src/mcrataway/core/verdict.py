"""Verdict aggregation — combines evidence into a final CLEAN/SUSPICIOUS/MALICIOUS verdict."""

from mcrataway.constants import Severity, Verdict
from mcrataway.core.evidence import EvidenceIndex


class VerdictAggregator:
    """Aggregate evidence into a final verdict with confidence score."""

    def __init__(self) -> None:
        self._thresholds = {
            Verdict.MALICIOUS: {
                "critical_count": 1,
                "high_count": 2,
                "medium_count": 5,
            },
            Verdict.SUSPICIOUS: {
                "high_count": 1,
                "medium_count": 3,
                "low_count": 5,
            },
        }

    def compute(self, index: EvidenceIndex) -> tuple[Verdict, float]:
        """Compute verdict and confidence from the evidence index.

        Returns (verdict, confidence) where confidence is 0.0-1.0.
        """
        if not index.evidence:
            return Verdict.CLEAN, 1.0

        critical = sum(1 for e in index.evidence if e.severity == Severity.CRITICAL)
        high = sum(1 for e in index.evidence if e.severity == Severity.HIGH)
        medium = sum(1 for e in index.evidence if e.severity == Severity.MEDIUM)
        low = sum(1 for e in index.evidence if e.severity == Severity.LOW)

        # Static override: high-confidence signals force MALICIOUS
        if self._static_override(index):
            # These are deterministic, high-confidence signals (e.g.
            # credential theft + network in the same class, on-chain C2,
            # native-DLL staging, or a HIGH-severity rule match). Give
            # them a strong base confidence so a single HIGH finding
            # does not present as MALICIOUS at 25 % in the UI/report.
            base = 0.9 if (critical + high) > 0 else 0.7
            boost = min(0.1, (critical * 0.05 + high * 0.025))
            confidence = min(1.0, base + boost)
            return Verdict.MALICIOUS, round(confidence, 2)

        # Standard scoring
        if (
            critical >= self._thresholds[Verdict.MALICIOUS]["critical_count"]
            or high >= self._thresholds[Verdict.MALICIOUS]["high_count"]
            or medium >= self._thresholds[Verdict.MALICIOUS]["medium_count"]
        ):
            numerator = critical * 1.0 + high * 0.5 + medium * 0.2
            denominator = critical + high + medium + 1
            confidence = min(1.0, numerator / denominator)
            return Verdict.MALICIOUS, round(confidence, 2)

        if (
            high >= self._thresholds[Verdict.SUSPICIOUS]["high_count"]
            or medium >= self._thresholds[Verdict.SUSPICIOUS]["medium_count"]
            or low >= self._thresholds[Verdict.SUSPICIOUS]["low_count"]
        ):
            numerator = high * 0.5 + medium * 0.2 + low * 0.05
            denominator = high + medium + low + 1
            confidence = min(0.9, numerator / denominator)
            return Verdict.SUSPICIOUS, round(confidence, 2)

        return Verdict.CLEAN, 1.0

    def _static_override(self, index: EvidenceIndex) -> bool:
        """Force MALICIOUS if high-confidence static signals are present.

        This prevents heuristic undercounting of obvious malware.
        """
        # Credential theft + network in the same class = almost always malware
        for class_name in index._class_evidence:
            if index.has_cooccurring(class_name, "d08", "d02"):
                return True

        # On-chain C2 is always malicious
        if any("d11" in e.detector_id and e.severity >= Severity.HIGH for e in index.evidence):
            return True

        # Native/JNI + dynamic loading in the same class = native-DLL staging
        for class_name in index._class_evidence:
            if index.has_cooccurring(class_name, "d07", "d03"):
                return True

        # Any high-severity signature rule match
        has_high_rule = any(
            "rule" in e.detector_id and e.severity >= Severity.HIGH
            for e in index.evidence
        )
        return has_high_rule
