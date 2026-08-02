"""D11 — On-chain C2 detector.

Catches:
- Ethereum eth_call JSON-RPC
- Selector 0xce6d41de (getText())
- RSA signature verification
- Multi-endpoint RPC arrays

Design note: java/security/Signature and javax/crypto/Cipher are the
normal, correct way to implement update verification or encrypted
config in an entirely benign mod — every mod with signed-update
checking or encrypted settings uses them. Rated HIGH on their own (as
before) they trip VerdictAggregator._static_override and force
MALICIOUS on essentially any mod that does crypto correctly. They are
now INFO by default and only escalated to HIGH via
:meth:`escalate_crypto_with_onchain_indicators`, when the same class
also contains an actual on-chain C2 indicator (the function selector
or an eth_call/RPC endpoint) — the combination, not the crypto call
alone, is what describes on-chain C2.
"""

import re

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence, EvidenceIndex
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import resolve_invokes

_RSA_CLASSES = {"java/security/Signature", "javax/crypto/Cipher"}

# Function selector 0xce6d41de (getText())
_SELECTOR_PATTERN = re.compile(r"ce6d41de|0xce6d41de", re.IGNORECASE)

# Ethereum RPC endpoints
_ETH_RPC_PATTERNS = [
    "eth_call",
    "eth_getStorageAt",
    "eth_getCode",
    "infura.io",
    "alchemyapi.io",
    "etherscan.io",
    "publicnode.com",
    "drpc.org",
    "rpc.ankr.com",
]


class D11OnchainC2(Detector):
    @property
    def detector_id(self) -> str:
        return "d11"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        evidence.extend(self._scan_strings(class_file, cp.all_strings(), obfuscated=False))
        evidence.extend(self._scan_crypto_invokes(class_file))
        return evidence

    def analyze_reconstructed_strings(
        self, class_file: ClassFile, strings: list[str]
    ) -> list[Evidence]:
        return self._scan_strings(class_file, strings, obfuscated=True)

    def _scan_strings(
        self, class_file: ClassFile, strings: list[str], obfuscated: bool
    ) -> list[Evidence]:
        evidence: list[Evidence] = []
        selector_severity = Severity.CRITICAL
        rpc_severity = Severity.HIGH if obfuscated else Severity.MEDIUM
        prefix = "Obfuscated " if obfuscated else ""

        for s in strings:
            if _SELECTOR_PATTERN.search(s):
                evidence.append(
                    self._add_evidence(
                        class_file, "", 0,
                        f"{prefix}Ethereum function selector 0xce6d41de (getText) detected",
                        selector_severity,
                        matched_value=s[:200],
                        context={"onchain_indicator": "1"},
                    )
                )

            for rpc in _ETH_RPC_PATTERNS:
                if rpc in s.lower():
                    evidence.append(
                        self._add_evidence(
                            class_file, "", 0,
                            f"{prefix}Ethereum RPC endpoint: {rpc}",
                            rpc_severity,
                            matched_value=s[:200],
                            context={"onchain_indicator": "1"},
                        )
                    )

        return evidence

    def _scan_crypto_invokes(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        for method in class_file.methods:
            if not method.bytecode:
                continue

            invokes = resolve_invokes(method.bytecode, cp, class_file.bootstrap_methods)
            for inv in invokes:
                if inv.owner in _RSA_CLASSES and inv.name in ("verify", "initVerify", "doFinal"):
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            f"RSA/Signature operation: {inv.owner}.{inv.name}",
                            Severity.INFO,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                            context={
                                "crypto_call": "1",
                                "invoke_owner": inv.owner,
                                "invoke_name": inv.name,
                            },
                        )
                    )

        return evidence

    @staticmethod
    def escalate_crypto_with_onchain_indicators(index: "EvidenceIndex") -> None:
        """Escalate D11 crypto calls to HIGH when the same class also has
        an on-chain indicator (function selector or RPC endpoint) — the
        combination describes signature-gated on-chain C2, not merely
        "this mod uses crypto correctly".
        """
        for _class_name, evs in index._class_evidence.items():
            has_onchain = any(
                ev.detector_id == "d11" and ev.context.get("onchain_indicator") == "1"
                for ev in evs
            )
            if not has_onchain:
                continue
            for ev in evs:
                if ev.detector_id == "d11" and ev.context.get("crypto_call") == "1":
                    ev.severity = Severity.HIGH
                    ev.description += " (co-occurring with on-chain C2 indicator)"
