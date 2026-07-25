"""Behavior-chain correlation — evaluates ordered capability combinations
that describe a full attack behavior, as opposed to a single detector
firing in isolation.

Individual capability detectors (D01-D13) each answer "does this class
do X?". A single "yes" is frequently not enough to conclude malice —
D02 (network I/O) alone describes any mod with an update checker; D04
(filesystem access) alone describes any mod with a config file. What
actually distinguishes malware is *combinations that form a complete
behavior*:

- Exfiltration: read credentials, then send them somewhere, while
  hiding the destination (D08 + D02 + D09 in the same class)
- Reload: fetch something over the network, write it to disk, then
  load it as code (D02 + D04 + D03)
- Self-propagation: enumerate the mods directory, then write into a
  JAR — the fractureiser behavior (D04 with a mods-directory path
  reference)
- Native payload staging: unpack a resource, stage it as a temp file,
  then load it as a native library (D07 + D04)

This module runs after all detectors have populated an EvidenceIndex
for one artifact and does two things:

1. Escalates evidence to CRITICAL when a full chain is found in the
   same class — a complete behavior is a much stronger signal than
   any single link, even if every individual link was already
   escalated by its own detector's finer-grained co-occurrence logic
   (e.g. D05's escalate_weak_indicators).
2. Downgrades a capability's *lone* evidence (no chain, no
   detector-specific co-occurrence already applied) toward LOW/INFO —
   this is the main lever against false positives: a mod is not
   suspicious for doing ONE thing on this list, only for doing several
   of them together in a way that forms a complete behavior.
"""

from dataclasses import dataclass

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence, EvidenceIndex


@dataclass(frozen=True)
class BehaviorChain:
    """A named sequence of detector IDs that, found together in the same
    class, describe one complete malicious behavior."""

    name: str
    detector_ids: tuple[str, ...]
    description: str


CHAINS: tuple[BehaviorChain, ...] = (
    BehaviorChain(
        name="credential_exfiltration",
        detector_ids=("d08", "d02", "d09"),
        description=(
            "Credential access + network I/O + obfuscation in the same class: "
            "reads a credential, sends it somewhere, and hides the destination"
        ),
    ),
    BehaviorChain(
        name="reload_and_execute",
        detector_ids=("d02", "d04", "d03"),
        description=(
            "Network fetch + file write + dynamic class loading in the same class: "
            "downloads a payload, stages it on disk, then loads it as code"
        ),
    ),
    BehaviorChain(
        name="native_payload_staging",
        detector_ids=("d07", "d04"),
        description=(
            "Native library loading + filesystem write in the same class: "
            "unpacks and loads an unpacked native payload at runtime"
        ),
    ),
)

# Detector IDs that participate in at least one chain. A lone finding
# from one of these (no chain present, no per-detector escalation
# already applied via `context`) is the main false-positive lever —
# see module docstring point 2.
_CHAIN_PARTICIPANT_DETECTORS = frozenset(
    detector_id for chain in CHAINS for detector_id in chain.detector_ids
)

# Evidence carrying any of these context markers has already been
# escalated or is otherwise not a "bare" single-capability finding, so
# it is exempt from the lone-finding downgrade — downgrading it again
# would undo a detector's own, more specific correlation logic (e.g.
# D05's escalate_weak_indicators, D11's escalate_crypto_with_onchain_indicators)
# or a rule match, which is not what this module is meant to touch.
_EXEMPT_CONTEXT_MARKERS = ("reconstructed", "rule_pack")


def evaluate_chains(index: EvidenceIndex) -> None:
    """Escalate complete behavior chains and downgrade lone capability
    findings, in place, on *index*.

    Call this after all detectors (and their own per-detector
    escalation methods, e.g. D05Persistence.escalate_weak_indicators)
    have run, since it needs the full, final evidence picture for each
    class to decide what is "lone" versus "part of a chain".
    """
    for class_name, evs in index._class_evidence.items():
        present_detectors = {e.detector_id for e in evs}

        matched_chains = [
            chain
            for chain in CHAINS
            if all(d in present_detectors for d in chain.detector_ids)
        ]

        if matched_chains:
            _escalate_chain(index, class_name, evs, matched_chains)
        else:
            _downgrade_lone_findings(evs, present_detectors)


def _escalate_chain(
    index: EvidenceIndex,
    class_name: str,
    evs: list[Evidence],
    matched_chains: list[BehaviorChain],
) -> None:
    for chain in matched_chains:
        index.add(
            Evidence(
                detector_id="behavior_chain",
                severity=Severity.CRITICAL,
                class_name=class_name,
                method_name="",
                offset=0,
                description=(
                    f"Complete behavior chain detected ({chain.name}): {chain.description}"
                ),
                matched_value=",".join(chain.detector_ids),
                context={"chain": chain.name},
            )
        )

    # A complete chain means every link is significant, not noise —
    # ensure each participating detector's evidence in this class is
    # at least MEDIUM, since a chain link rated LOW/INFO would
    # otherwise still barely register in VerdictAggregator's counts
    # despite being part of a demonstrated complete behavior.
    participating_ids = {d for chain in matched_chains for d in chain.detector_ids}
    for ev in evs:
        if ev.detector_id in participating_ids and ev.severity < Severity.MEDIUM:
            ev.severity = Severity.MEDIUM


def _downgrade_lone_findings(evs: list[Evidence], present_detectors: set[str]) -> None:
    """Downgrade a chain-participant detector's evidence when it fired
    alone in this class (no chain completed) and was not already
    escalated by more specific logic."""
    lone_detectors = present_detectors & _CHAIN_PARTICIPANT_DETECTORS
    if len(lone_detectors) > 1:
        # More than one chain-participant capability present but no
        # full chain matched (e.g. only 2 of a 3-link chain) is still
        # a partial correlation, not a lone finding — leave it to the
        # detectors' own severities and VerdictAggregator's thresholds.
        return

    for ev in evs:
        if ev.detector_id not in _CHAIN_PARTICIPANT_DETECTORS:
            continue
        if any(ev.context.get(marker) for marker in _EXEMPT_CONTEXT_MARKERS):
            continue
        if ev.severity >= Severity.HIGH:
            # A HIGH/CRITICAL finding from a single detector (e.g. a
            # Discord webhook URL, a direct credential-file read) is
            # already a strong, specific signal on its own — chain
            # analysis downgrades weak/ambiguous single capabilities,
            # not detectors that already concluded high confidence
            # from the specific pattern they matched.
            continue
        if ev.severity > Severity.LOW:
            ev.severity = Severity.LOW
            ev.context = {**ev.context, "chain_downgraded": "1"}
