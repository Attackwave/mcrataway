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

# Characters that indicate the sensitive name is being used as part
# of a filesystem path, not as a bare word in code. A bare "Cookies"
# in an HTTP library is noise; "AppData/.../Cookies" or
# "Library/.../Cookies" is a credential-file read.
_PATH_SEPARATORS = ("/", "\\", ":")


def _has_path_context(haystack: str, needle: str) -> bool:
    """Check whether *needle* appears in *haystack* surrounded by path
    context — a directory separator or drive letter nearby — rather
    than as a bare word in code/UI text."""
    idx = haystack.find(needle)
    if idx < 0:
        return False
    before = haystack[:idx]
    after = haystack[idx + len(needle):]
    # A separator before or after the needle (e.g. "/Cookies",
    # "Cookies.db", "AppData\\...\\Cookies") indicates a path.
    if before and before[-1] in _PATH_SEPARATORS:
        return True
    if after and after[0] in (".", "/", "\\"):
        return True
    # A drive-letter prefix (e.g. "C:\\Users\\...\\Cookies") or an
    # explicit home/expansion prefix also counts.
    return before.startswith(("~", "C:", "D:", "/home", "/Users", "AppData", "Library"))


class D08CredentialTheft(Detector):
    @property
    def detector_id(self) -> str:
        return "d08"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        # Minecraft session access patterns.
        # getAccessToken is the actual credential — HIGH.
        # getSession/getUsername/getUuid are used by virtually every
        # UI mod to display the player name/skin — MEDIUM.
        token_methods = {
            ("net/minecraft/class_310", "method_1674"),  # getAccessToken (intermediary)
            ("net/minecraft/client/MinecraftClient", "getAccessToken"),  # yarn
            ("net/minecraft/util/Session", "getAccessToken"),
        }
        info_methods = {
            ("net/minecraft/class_310", "method_1548"),  # getSession (intermediary)
            ("net/minecraft/client/MinecraftClient", "getSession"),  # yarn
            ("net/minecraft/class_310", "method_1676"),  # getUsername (intermediary)
            ("net/minecraft/client/MinecraftClient", "getUsername"),  # yarn
            ("net/minecraft/class_310", "method_44717"),  # getUuid (intermediary)
            ("net/minecraft/client/MinecraftClient", "getUuid"),  # yarn
            ("net/minecraft/util/Session", "getSessionUuid"),
        }

        for method in class_file.methods:
            if not method.bytecode:
                continue

            invokes = resolve_invokes(method.bytecode, cp, class_file.bootstrap_methods)
            for inv in invokes:
                if (inv.owner, inv.name) in token_methods:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            f"Minecraft session token access: {inv.owner}.{inv.name}",
                            Severity.HIGH,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                            context={"invoke_owner": inv.owner, "invoke_name": inv.name},
                        )
                    )
                elif (inv.owner, inv.name) in info_methods:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            f"Minecraft session info access: {inv.owner}.{inv.name}",
                            Severity.MEDIUM,
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
        """Flag references to credential/token file locations.

        Plain substring matching on names like ``"Cookies"`` or
        ``"Local State"`` produces massive false positives — these
        words appear in every HTTP library, config UI, and browser-
        interface code. A *path* reference (with directory separators
        or a drive letter) is a much stronger signal: a benign mod
        has no reason to construct ``AppData/.../Cookies`` or
        ``Library/Application Support/.../Login Data`` as a path.

        For *obfuscated* (reconstructed) strings, the bar is lower:
        hiding *any* of these names in a byte array is already
        suspicious, since there is no benign reason to conceal them.
        """
        # Paths that are only suspicious as a real filesystem path,
        # not as a bare word. Matched with a path-context requirement
        # (directory separator or drive letter prefix) to avoid
        # tripping on the word "Cookies" in an HTTP library.
        path_sensitive = {
            "Cookies": True,           # browser cookie DB file
            "Local State": True,       # Chrome encryption-key file
            "Login Data": True,        # Chrome password DB file
            "session.json": True,
            "launcher_accounts.json": False,  # always suspicious
            "launcher_profiles.json": False,
            "Discord/Local State": False,
            "discord_token": False,
            "tokens/localstorage": False,
        }

        evidence: list[Evidence] = []
        severity = Severity.CRITICAL if obfuscated else Severity.HIGH
        prefix = "Obfuscated sensitive file path" if obfuscated else "Sensitive file path"
        for s in strings:
            for sp, requires_path_context in path_sensitive.items():
                if sp not in s:
                    continue
                if requires_path_context and not _has_path_context(s, sp):
                    # Bare word match (e.g. "Cookies" in an HTTP
                    # library) — downgrade to LOW so it's still
                    # recorded for forensic completeness but does
                    # not trip the HIGH threshold that drives the
                    # MALICIOUS verdict.
                    evidence.append(
                        self._add_evidence(
                            class_file, "", 0,
                            f"Sensitive name reference (no path context): {sp}",
                            Severity.LOW,
                            matched_value=s[:200],
                            context={"sensitive_name": sp},
                        )
                    )
                    continue
                evidence.append(
                    self._add_evidence(
                        class_file, "", 0,
                        f"{prefix}: {sp}",
                        severity,
                        matched_value=s[:200],
                    )
                )
        return evidence
