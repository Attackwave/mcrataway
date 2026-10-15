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
- Reload: fetch something from a hidden destination, then load it as
  code (D02 + D03 in the same class). The disk write in between is not
  a link: a plain file write is what every mod that saves a config
  does, so it stays INFO and requiring it at MEDIUM stopped the chain
  from matching the staged downloads it exists for.
- Hidden download executed as a process: fetch from a hidden
  destination, then hand it to the OS (D02 + D01 in the same class)
- Self-propagation: enumerate the mods directory, then write into a
  JAR — the fractureiser behavior (D04 with a mods-directory path
  reference). Not implemented as a chain: D04 does not currently mark
  a mods-directory path, and the fractureiser family is caught by the
  rule packs, the signed-archive check and the undeclared-nested-entry
  check.

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
        detector_ids=("d02", "d03"),
        description=(
            "Network fetch from a hidden destination + dynamic class loading in the "
            "same class: downloads a payload and loads it as code"
        ),
    ),
    BehaviorChain(
        name="hidden_download_and_exec",
        detector_ids=("d02", "d01"),
        description=(
            "Network fetch from a hidden destination + process execution in the same "
            "class: fetches a payload and hands it to the OS to run"
        ),
    ),
)

# Every link of a chain has to be a capability the detector rated MEDIUM
# or worse *in that class*, and at least one link has to be a specific
# finding (HIGH/CRITICAL). Merely mentioning the APIs a chain is made of
# is what a service loader, a plugin framework or a native-extraction
# library looks like: kotlinx's FastServiceLoader, flatlaf's
# UIDefaultsLoader, javacpp's Loader and JNA's Native each contain a
# URL, a file write and a Class.forName/URLClassLoader — all at
# INFO-LOW/MEDIUM, none of them suspicious. Rating that combination
# CRITICAL flagged twenty of the 510 popular mods in the local corpus
# and, on a third of them, was the only reason for the MALICIOUS verdict.
_MIN_LINK_SEVERITY = Severity.MEDIUM
_STRONG_LINK_SEVERITY = Severity.HIGH

# The discriminator for the download chains is therefore the
# *destination*: D02 only reaches MEDIUM when the URL is hidden,
# reconstructed or a known exfiltration endpoint, while a plaintext URL
# string is what every update checker in the corpus contains.

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
        strengths = index.class_strengths().get(class_name, {})

        matched_chains = [chain for chain in CHAINS if _links_hold(chain, strengths)]

        if matched_chains:
            _escalate_chain(index, class_name, evs, matched_chains)
        else:
            _downgrade_lone_findings(evs, present_detectors)


def _links_hold(chain: BehaviorChain, strengths: dict[str, Severity]) -> bool:
    """Whether every link of *chain* is present in the class as a real
    capability, with at least one link specific enough to carry it."""
    severities = [strengths.get(d, Severity.INFO) for d in chain.detector_ids]
    return (
        all(s >= _MIN_LINK_SEVERITY for s in severities)
        and max(severities) >= _STRONG_LINK_SEVERITY
    )


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
