"""D02 — Network I/O detector.

Catches:
- URL, HttpURLConnection, HttpClient
- Socket APIs
- Extracted URLs from constant pool
"""

import re

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import resolve_invokes


class D02NetworkIO(Detector):
    @property
    def detector_id(self) -> str:
        return "d02"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        network_classes = {
            "java/net/URL",
            "java/net/HttpURLConnection",
            "java/net/http/HttpClient",
            "java/net/http/HttpRequest",
            "java/net/http/HttpResponse",
            "java/net/Socket",
            "java/net/ServerSocket",
            "java/net/DatagramSocket",
            "okhttp3/OkHttpClient",
            "org/apache/http/client/HttpClient",
        }

        for method in class_file.methods:
            if not method.bytecode:
                continue

            invokes = resolve_invokes(method.bytecode, cp, class_file.bootstrap_methods)
            for inv in invokes:
                if inv.owner in network_classes:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            f"Network I/O: {inv.owner}.{inv.name}",
                            Severity.INFO,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                        )
                    )

        evidence.extend(self._scan_strings(class_file, cp.all_strings(), obfuscated=False))
        return evidence

    def analyze_reconstructed_strings(
        self, class_file: ClassFile, strings: list[str]
    ) -> list[Evidence]:
        """Flag de-obfuscated URLs/webhook endpoints — hiding the C2
        destination is itself evidence of intent to exfiltrate, so
        matches here are rated higher than the plain constant-pool scan.
        """
        return self._scan_strings(class_file, strings, obfuscated=True)

    def _scan_strings(
        self, class_file: ClassFile, strings: list[str], obfuscated: bool
    ) -> list[Evidence]:
        evidence: list[Evidence] = []
        url_pattern = re.compile(r'https?://[^\s"\'\(\)]+')
        url_severity = Severity.MEDIUM if obfuscated else Severity.LOW
        webhook_severity = Severity.CRITICAL if obfuscated else Severity.HIGH

        for s in strings:
            for match in url_pattern.finditer(s):
                url = match.group(0)
                if not self._is_legitimate_url(url):
                    prefix = "Obfuscated " if obfuscated else ""
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            "",
                            0,
                            f"{prefix}Suspicious URL in constant pool: {url[:100]}",
                            url_severity,
                            matched_value=url,
                        )
                    )

            if "discord.com/api/webhooks/" in s or "discordapp.com/api/webhooks/" in s:
                prefix = "Obfuscated " if obfuscated else ""
                evidence.append(
                    self._add_evidence(
                        class_file,
                        "",
                        0,
                        f"{prefix}Discord webhook URL detected",
                        webhook_severity,
                        matched_value=s[:200],
                    )
                )

        return evidence

    @staticmethod
    def _is_legitimate_url(url: str) -> bool:
        """Filter out obviously legitimate URLs (Maven, etc.)."""
        legitimate = [
            "maven.apache.org",
            "repo1.maven.org",
            "central.sonatype.org",
            "github.com/",
            "jitpack.io",
            "minecraft.net",
            "mojang.com",
            "fabricmc.net",
            "minecraftforge.net",
            "files.minecraftforge.net",
        ]
        return any(host in url.lower() for host in legitimate)
