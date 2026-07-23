"""D08 — Credential theft detector.

Catches:
- Minecraft session token access (getSession, getAccessToken)
- Discord token paths
- Browser cookie / login databases
- launcher_accounts.json access
"""

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import resolve_invokes


class D08CredentialTheft(Detector):
    @property
    def detector_id(self) -> str:
        return "d08"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        # Minecraft session access patterns
        session_methods = {
            ("net/minecraft/class_310", "method_1548"),  # getSession (intermediary)
            ("net/minecraft/client/MinecraftClient", "getSession"),  # yarn
            ("net/minecraft/class_310", "method_1676"),  # getUsername (intermediary)
            ("net/minecraft/client/MinecraftClient", "getUsername"),  # yarn
            ("net/minecraft/class_310", "method_1674"),  # getAccessToken (intermediary)
            ("net/minecraft/client/MinecraftClient", "getAccessToken"),  # yarn
            ("net/minecraft/class_310", "method_44717"),  # getUuid (intermediary)
            ("net/minecraft/client/MinecraftClient", "getUuid"),  # yarn
            ("net/minecraft/util/Session", "getAccessToken"),
            ("net/minecraft/util/Session", "getSessionUuid"),
        }

        for method in class_file.methods:
            if not method.bytecode:
                continue

            invokes = resolve_invokes(method.bytecode, cp)
            for inv in invokes:
                if (inv.owner, inv.name) in session_methods:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            f"Minecraft session access: {inv.owner}.{inv.name}",
                            Severity.HIGH,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                        )
                    )

        # File path references to sensitive locations
        sensitive_paths = [
            "session.json",
            "launcher_accounts.json",
            "launcher_profiles.json",
            "Local State",
            "Login Data",
            "Cookies",
            "Discord/Local State",
            "discord_token",
            "tokens/localstorage",
        ]

        for s in cp.all_strings():
            for sp in sensitive_paths:
                if sp in s:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            "",
                            0,
                            f"Sensitive file path: {sp}",
                            Severity.HIGH,
                            matched_value=s[:200],
                        )
                    )

        return evidence
