"""Verdict aggregation — combines evidence into a final CLEAN/SUSPICIOUS/MALICIOUS verdict."""

import math

from mcrataway.constants import Severity, Verdict
from mcrataway.core.evidence import EvidenceIndex

# Weights used by the saturating confidence function. Higher-severity
# evidence contributes more per item, but every scheme below is
# strictly increasing in each count — see _confidence_from_score.
_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.5,
    Severity.MEDIUM: 0.2,
    Severity.LOW: 0.05,
}

# Saturation constant for the confidence curve: 1 - exp(-score / _K).
# Chosen so a single CRITICAL (score 1.0) already yields a high (~0.86)
# confidence, matching the previous scheme's behavior for the common
# single-strong-signal case, while remaining strictly increasing as
# more evidence accumulates (unlike the old ratio, which could shrink
# when more corroborating MEDIUM evidence was added).
_K = 0.55


def _confidence_from_score(score: float, cap: float = 1.0) -> float:
    """Monotonically increasing confidence in [0, cap] from a weighted score.

    Unlike a ratio of weighted-sum / count, this never decreases when
    additional corroborating evidence is added — more evidence can only
    raise or hold confidence, never lower it.
    """
    return round(min(cap, 1 - math.exp(-score / _K)), 2)


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

        score = (
            critical * _SEVERITY_WEIGHTS[Severity.CRITICAL]
            + high * _SEVERITY_WEIGHTS[Severity.HIGH]
            + medium * _SEVERITY_WEIGHTS[Severity.MEDIUM]
            + low * _SEVERITY_WEIGHTS[Severity.LOW]
        )

        # Static override: high-confidence signals force MALICIOUS
        if self._static_override(index):
            # These are deterministic, high-confidence signals (e.g.
            # credential theft + network in the same class, on-chain C2,
            # native-DLL staging, or a HIGH-severity rule match). Floor
            # the score so at least one such signal already lands at a
            # strong confidence, then let additional evidence raise it
            # further via the same monotonic curve as the standard path.
            floored_score = max(score, 1.0)
            confidence = _confidence_from_score(floored_score)
            return Verdict.MALICIOUS, confidence

        # Standard scoring
        if (
            critical >= self._thresholds[Verdict.MALICIOUS]["critical_count"]
            or high >= self._thresholds[Verdict.MALICIOUS]["high_count"]
            or medium >= self._thresholds[Verdict.MALICIOUS]["medium_count"]
        ):
            confidence = _confidence_from_score(score)
            return Verdict.MALICIOUS, confidence

        if (
            high >= self._thresholds[Verdict.SUSPICIOUS]["high_count"]
            or medium >= self._thresholds[Verdict.SUSPICIOUS]["medium_count"]
            or low >= self._thresholds[Verdict.SUSPICIOUS]["low_count"]
        ):
            confidence = _confidence_from_score(score, cap=0.9)
            return Verdict.SUSPICIOUS, confidence

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
        if has_high_rule:
            return True

        # A deliberately hidden reference to a dangerous API (evidence
        # tagged "reconstructed") combined with dynamic class
        # resolution (D03: Class.forName) or indirect invocation (D10:
        # MethodHandles) in the same class describes exactly the
        # pattern used to build a call to Runtime.exec/ProcessBuilder
        # without a direct invoke the bytecode scan can see: resolve
        # the hidden class name via reflection, then invoke it
        # indirectly. A benign mod has no reason to hide such a string.
        for _class_name, evs in index._class_evidence.items():
            has_hidden_dangerous_ref = any(
                e.context.get("reconstructed") == "1" for e in evs
            )
            if not has_hidden_dangerous_ref:
                continue
            has_dynamic_resolution = any(
                e.detector_id in ("d03", "d10") for e in evs
            )
            if has_dynamic_resolution:
                return True

        return False
