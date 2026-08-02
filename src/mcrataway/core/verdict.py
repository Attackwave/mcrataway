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
        # Thresholds tuned against a 50-mod sample from Modrinth's
        # top-downloads list (see testdata/mods/). The previous
        # medium_count=5/3 thresholds produced an 82% false-positive
        # rate on entirely benign popular mods: a single large mod
        # with reflection (D10), network (D02), and entropy (D09)
        # easily accumulates 5+ MEDIUM findings across its bundled
        # libraries, tripping MALICIOUS with no HIGH/CRITICAL signal.
        # Raising to 8/4 keeps SUSPICIOUS meaningful (a mod with 4+
        # distinct medium capabilities IS worth looking at) while
        # reserving MALICIOUS for either a strong signal (CRITICAL/
        # HIGH/chain) or a genuinely broad capability spread (8+
        # MEDIUMs from *distinct* detectors — see the dedup below).
        self._thresholds = {
            Verdict.MALICIOUS: {
                "critical_count": 1,
                "high_count": 2,
                "medium_count": 8,
            },
            Verdict.SUSPICIOUS: {
                "high_count": 1,
                "medium_count": 4,
                "low_count": 6,
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

        # Distinct-detector count for MEDIUM and LOW: a single
        # detector (e.g. D10 reflection) firing across 50 classes in a
        # large mod's bundled libraries is ONE capability, not 50 —
        # counting raw findings made the threshold trivially
        # reachable for any mod with reflection + network + entropy,
        # all legitimate. Deduplicating by detector_id means "8
        # MEDIUMs" now means "8 *different* medium-severity
        # capabilities", which is a genuinely broad suspicious spread,
        # not one detector amplified by a large class count. The same
        # applies to LOW: D10 alone generating 455 LOWs in a big mod
        # is one capability, not 455.
        distinct_medium_detectors = {
            e.detector_id for e in index.evidence if e.severity == Severity.MEDIUM
        }
        distinct_low_detectors = {
            e.detector_id for e in index.evidence if e.severity == Severity.LOW
        }

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
        medium_for_threshold = len(distinct_medium_detectors)
        low_for_threshold = len(distinct_low_detectors)
        if (
            critical >= self._thresholds[Verdict.MALICIOUS]["critical_count"]
            or high >= self._thresholds[Verdict.MALICIOUS]["high_count"]
            or medium_for_threshold >= self._thresholds[Verdict.MALICIOUS]["medium_count"]
        ):
            confidence = _confidence_from_score(score)
            return Verdict.MALICIOUS, confidence

        if (
            high >= self._thresholds[Verdict.SUSPICIOUS]["high_count"]
            or medium_for_threshold >= self._thresholds[Verdict.SUSPICIOUS]["medium_count"]
            or low_for_threshold >= self._thresholds[Verdict.SUSPICIOUS]["low_count"]
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

        # A deliberately hidden reference to a *dangerous API*
        # (evidence tagged "reconstructed" AND the matched value
        # references a known dangerous class/method) combined with
        # dynamic class resolution (D03: Class.forName) or indirect
        # invocation (D10: MethodHandles) in the same class describes
        # exactly the pattern used to build a call to
        # Runtime.exec/ProcessBuilder without a direct invoke the
        # bytecode scan can see: resolve the hidden class name via
        # reflection, then invoke it indirectly. A benign mod has no
        # reason to hide such a string.
        #
        # The previous version fired on *any* reconstructed string
        # (including harmless Base64-decoded resource URLs and embedded
        # asset names), producing false positives on mods that use
        # Base64 for assets and also happen to use reflection for
        # config — a common and legitimate combination.
        _dangerous_api_patterns = (
            "java.lang.Runtime", "java/lang/Runtime",
            "java.lang.ProcessBuilder", "java/lang/ProcessBuilder",
            "getRuntime", "exec", "ProcessBuilder",
            "java.net.URLClassLoader", "URLClassLoader",
            "java.lang.Class.forName", "Class.forName",
            "MethodHandles", "LambdaMetafactory",
            "defineClass", "loadClass",
        )
        for _class_name, evs in index._class_evidence.items():
            has_hidden_dangerous_ref = any(
                e.context.get("reconstructed") == "1"
                and any(p in (e.matched_value or "") for p in _dangerous_api_patterns)
                for e in evs
            )
            if not has_hidden_dangerous_ref:
                continue
            has_dynamic_resolution = any(
                e.detector_id in ("d03", "d10") for e in evs
            )
            if has_dynamic_resolution:
                return True

        return False
