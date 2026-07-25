"""Report enrichment — MITRE ATT&CK mapping and plain-language summaries.

A finding like ``d01 HIGH "ProcessBuilder usage detected"`` tells a
developer exactly what fired, but a user deciding whether to delete a
mod needs to know: what does this actually do, what data is at risk,
and what should I do about it? This module maps each detector (and a
few specific rule-pack families) to:

- A MITRE ATT&CK technique ID/name, where one applies.
- A one-sentence plain-language explanation of the capability.
- A recommended action.

It also defines the sort key used to order findings by how much they
actually tell the user, rather than by detector-registration or
archive-entry order — the finding that would change someone's
decision belongs at the top of the report.
"""

from dataclasses import dataclass

from mcrataway.constants import Severity


@dataclass(frozen=True)
class DetectorContext:
    """Plain-language and MITRE ATT&CK context for one detector."""

    mitre_id: str | None
    mitre_name: str | None
    plain_language: str
    recommended_action: str


# Detector ID (or "behavior_chain"/"rule"/"string_reconstruction" for
# the non-D-numbered evidence sources) -> context. Deliberately not
# exhaustive of every ATT&CK sub-technique; this maps to the technique
# that best matches the *capability* each detector looks for.
_DETECTOR_CONTEXT: dict[str, DetectorContext] = {
    "d01": DetectorContext(
        "T1059", "Command and Scripting Interpreter",
        "This mod can run operating-system commands on your computer.",
        "Do not run this mod unless you trust its source completely.",
    ),
    "d02": DetectorContext(
        "T1071", "Application Layer Protocol",
        "This mod can send or receive data over the network.",
        "Check whether the destination is a service you recognize and expect.",
    ),
    "d03": DetectorContext(
        "T1129", "Shared Modules",
        "This mod can load additional code at runtime, potentially from "
        "outside the mod file itself.",
        "Verify what code this mod loads and from where before trusting it.",
    ),
    "d04": DetectorContext(
        None, None,
        "This mod can read or write files on your computer, including "
        "other mod files.",
        "Review why this mod needs file access beyond its own configuration.",
    ),
    "d05": DetectorContext(
        "T1547", "Boot or Logon Autostart Execution",
        "This mod can configure your computer to run something "
        "automatically at startup, outside of Minecraft.",
        "This capability has no legitimate use in a Minecraft mod — treat as malicious.",
    ),
    "d06": DetectorContext(
        "T1055", "Process Injection",
        "This mod deserializes data in a way that can execute arbitrary "
        "code if the data is attacker-controlled.",
        "Verify the source of any data this mod deserializes.",
    ),
    "d07": DetectorContext(
        "T1129", "Shared Modules",
        "This mod loads a native (non-Java) library, which runs with "
        "fewer safety guarantees than Java code.",
        "Native libraries are rare in ordinary mods outside of rendering/audio (LWJGL) — verify the source.",
    ),
    "d08": DetectorContext(
        "T1528", "Steal Application Access Token",
        "This mod can access your Minecraft session token, Discord "
        "token, or saved browser credentials.",
        "Treat as credential theft unless you can verify exactly why this mod needs this access.",
    ),
    "d09": DetectorContext(
        "T1027", "Obfuscated Files or Information",
        "Parts of this mod's code are deliberately hidden or obscured.",
        "Legitimate mods rarely need to hide their own code — treat as suspicious.",
    ),
    "d10": DetectorContext(
        "T1055", "Process Injection",
        "This mod calls methods indirectly in a way that can bypass "
        "simple code scanning.",
        "Combined with other findings, this often indicates deliberate evasion.",
    ),
    "d11": DetectorContext(
        "T1102", "Web Service",
        "This mod may receive remote commands via a public blockchain, "
        "which cannot be taken down or blocked like a normal server.",
        "This is a known command-and-control technique — treat as malicious.",
    ),
    "d12": DetectorContext(
        None, None,
        "A resource/datapack file in this mod contains unusual or "
        "oversized content.",
        "Review the specific file flagged before installing.",
    ),
    "d13": DetectorContext(
        "T1055", "Process Injection",
        "This mod rewrites part of Minecraft's own code (or another "
        "mod's code) at load time, targeting session or network handling.",
        "Mixins/coremods targeting auth-related classes have no ordinary gameplay purpose — verify carefully.",
    ),
    "d14": DetectorContext(
        None, None,
        "This mod's file was digitally signed, but contains content "
        "added after signing, or loads additional external code.",
        "Treat as a tampered/trojanized copy of a legitimate mod — obtain the mod from its original source instead.",
    ),
    "behavior_chain": DetectorContext(
        None, None,
        "This mod exhibits a complete multi-step malicious behavior, "
        "not just an isolated capability.",
        "This is a strong, corroborated signal — do not run this mod.",
    ),
    "string_reconstruction": DetectorContext(
        "T1027", "Obfuscated Files or Information",
        "This mod hides text (such as a URL or class name) inside its "
        "code rather than storing it plainly.",
        "A benign mod has no reason to hide this information — treat as suspicious.",
    ),
}

_RULE_CONTEXT = DetectorContext(
    None, None,
    "This mod matched a known threat-intelligence signature.",
    "This matches a documented pattern from known malicious mods.",
)


def context_for(detector_id: str) -> DetectorContext:
    """Return the plain-language/MITRE context for a finding's detector_id.

    Rule matches carry an ID like ``rule:<pack>:<rule_id>``.
    """
    if detector_id.startswith("rule:") or detector_id == "archive":
        return _RULE_CONTEXT
    return _DETECTOR_CONTEXT.get(
        detector_id,
        DetectorContext(None, None, "This mod exhibits a flagged capability.", "Review this finding manually."),
    )


def finding_sort_key(severity: Severity, detector_id: str) -> tuple[int, int, str]:
    """Sort key ordering findings by how much they should influence a
    user's decision, most-significant first: severity descending, then
    a corroborated behavior chain ahead of a single-detector finding of
    the same severity (a demonstrated complete behavior is more
    conclusive than any single capability), then detector_id for a
    stable, readable order among equals.
    """
    is_chain = detector_id == "behavior_chain"
    return (-int(severity), 0 if is_chain else 1, detector_id)
