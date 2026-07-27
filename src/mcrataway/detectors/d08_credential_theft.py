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

            invokes = resolve_invokes(method.bytecode, cp, class_file.bootstrap_methods)
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
                            context={"invoke_owner": inv.owner, "invoke_name": inv.name},
                        )
                    )

        evidence.extend(self._scan_paths(class_file, cp.all_strings(), obfuscated=False))
        return evidence

    def analyze_reconstructed_strings(
        self, class_file: ClassFile, strings: list[str]
    ) -> list[Evidence]:
        """Flag de-obfuscated references to credential file locations.

        Hiding "launcher_accounts.json" or "Login Data" in a byte array
        has no legitimate purpose — no benign mod needs to conceal that
        it reads these paths — so the match is rated CRITICAL.
        """
        return self._scan_paths(class_file, strings, obfuscated=True)

    def _scan_paths(
        self, class_file: ClassFile, strings: list[str], obfuscated: bool
    ) -> list[Evidence]:
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

        evidence: list[Evidence] = []
        severity = Severity.CRITICAL if obfuscated else Severity.HIGH
        prefix = "Obfuscated sensitive file path" if obfuscated else "Sensitive file path"
        for s in strings:
            for sp in sensitive_paths:
                if sp in s:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            "",
                            0,
                            f"{prefix}: {sp}",
                            severity,
                            matched_value=s[:200],
                        )
                    )

        return evidence
