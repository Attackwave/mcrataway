"""D14 — JAR signature/manifest tamper detector.

Catches:
- Classes present in a signed JAR but absent from its META-INF/*.SF
  signature block — the signature block lists a digest for every
  entry that existed when the JAR was signed, so an entry added
  afterwards (a payload injected into an otherwise legitimate,
  previously-signed mod — "trojanizing" a real mod) simply does not
  appear in it. A JVM performing real signature verification would
  reject such a JAR outright; this scanner does not verify
  cryptographic signatures (that would require the signer's
  certificate chain and is a much larger undertaking), but the
  presence/absence check alone is a strong, cheap signal that
  something was added after the fact.
- `Class-Path` manifest entries, which point at additional JARs to
  load from arbitrary (often relative, sometimes absolute) paths —
  legitimate mods essentially never need this since Minecraft's own
  classloading handles mod dependencies.

This detector operates on archive entries as a whole (it needs the
full set of entry names plus the .SF file contents), not on individual
parsed classes, so it is invoked once per top-level archive rather
than via the per-class analyze_class hook.
"""

import re

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile

_SF_NAME_LINE = re.compile(r"^Name:\s*(.+)$", re.MULTILINE)

# More unsigned classes than a payload injection would add: at that
# point the signature is stale rather than tampered with — see the
# reasoning in analyze_signed_archive.
_MAX_INJECTED_CLASSES = 5


def _parse_sf_entry_names(sf_text: str) -> set[str]:
    """Extract the set of entry names listed in a META-INF/*.SF file.

    .SF files use the same RFC-822-with-continuation-lines format as
    MANIFEST.MF: a "Name: <path>" line, optionally wrapped onto
    following lines that start with a single space. Continuation
    lines never affect the entry name itself (only long digest
    values wrap), so a plain regex over "Name:" lines is sufficient
    here without needing the full continuation-line unwrapping logic
    parsers/manifest.py uses for MANIFEST.MF's own values.
    """
    return {name.strip() for name in _SF_NAME_LINE.findall(sf_text)}


class D14SignatureTamper(Detector):
    @property
    def detector_id(self) -> str:
        return "d14"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        # This detector needs the whole archive's entry list and the
        # .SF file contents, not a single parsed class — see the
        # archive-level analysis wired in scan_engine.py instead.
        return []

    def analyze_signed_archive(
        self, entry_names: set[str], sf_contents: dict[str, str]
    ) -> list[Evidence]:
        """Check *entry_names* (every non-directory entry in the
        archive) against the signed entry set declared in each
        META-INF/*.SF file in *sf_contents* (path -> decoded text).

        Only .class entries are checked: legitimate build tooling
        (build metadata, generated resources) can vary between build
        and sign steps in ways that would produce noisy false
        positives for non-code entries, whereas an added .class file
        is exactly the payload-injection pattern this detector exists
        to catch.
        """
        evidence: list[Evidence] = []
        if not sf_contents:
            return evidence

        for sf_name, sf_text in sf_contents.items():
            signed_names = _parse_sf_entry_names(sf_text)
            if not signed_names:
                continue

            class_entries = [name for name in entry_names if name.endswith(".class")]
            unsigned_classes = sorted(
                name for name in class_entries if name not in signed_names
            )
            if not unsigned_classes:
                continue

            # How many classes are missing decides how to read it. The
            # pattern this detector exists for — a payload injected into
            # an otherwise intact signed mod — adds one class, or a
            # handful. A signature that leaves out dozens is not that:
            # the JAR was repackaged after signing (a build step such as
            # shading or remapping that runs after jarsigner), so the
            # finding is a lead, not proof. In the local 510-mod corpus
            # this separates single-class additions from author-signed
            # mods with a stale .SF, which had 57 of 106, 82 of 230 and
            # 99 of ~250 classes absent and were reported MALICIOUS for
            # it.
            if len(unsigned_classes) <= _MAX_INJECTED_CLASSES:
                severity = Severity.HIGH
                note = (
                    "added after the JAR was signed, possibly indicating a "
                    "legitimate mod was trojanized post-signing"
                )
            else:
                severity = Severity.MEDIUM
                note = (
                    f"{len(unsigned_classes)} of {len(class_entries)} classes are "
                    f"absent from it — the JAR was repackaged after it was signed, "
                    f"so the signature covers only part of the archive"
                )

            for class_name in unsigned_classes:
                evidence.append(
                    Evidence(
                        detector_id=self.detector_id,
                        severity=severity,
                        class_name=class_name,
                        method_name="",
                        offset=0,
                        description=(
                            f"Class file present in signed archive but absent from "
                            f"{sf_name} — {note}"
                        ),
                        matched_value=class_name,
                        context={"signature_file": sf_name},
                    )
                )

        return evidence

    def analyze_manifest_class_path(self, manifest_text: str) -> list[Evidence]:
        """Flag a Class-Path entry in META-INF/MANIFEST.MF.

        Handles RFC-822 continuation lines the same way
        parsers/manifest.py does, since Class-Path lists can be long
        enough to wrap.
        """
        evidence: list[Evidence] = []
        current_key: str | None = None
        current_value = ""

        for line in manifest_text.splitlines():
            if line.startswith(" "):
                if current_key == "Class-Path":
                    current_value += line[1:]
                continue
            if ":" not in line:
                current_key = None
                current_value = ""
                continue
            key, _, value = line.partition(":")
            current_key = key.strip()
            current_value = value.strip()

        if current_key == "Class-Path" and current_value:
            evidence.append(
                Evidence(
                    detector_id=self.detector_id,
                    severity=Severity.MEDIUM,
                    class_name="",
                    method_name="",
                    offset=0,
                    description=(
                        f"Manifest declares Class-Path, loading additional JARs from "
                        f"outside normal mod dependency resolution: {current_value[:150]}"
                    ),
                    matched_value=current_value[:200],
                    context={"manifest_key": "Class-Path"},
                )
            )

        return evidence
