"""D11 — On-chain C2 detector.

Catches:
- Ethereum eth_call JSON-RPC
- Selector 0xce6d41de (getText())
- RSA signature verification
- Multi-endpoint RPC arrays
"""

import re

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import resolve_invokes


class D11OnchainC2(Detector):
    @property
    def detector_id(self) -> str:
        return "d11"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        # Function selector 0xce6d41de (getText())
        selector_pattern = re.compile(r"ce6d41de|0xce6d41de", re.IGNORECASE)

        # Ethereum RPC endpoints
        eth_rpc_patterns = [
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

        for s in cp.all_strings():
            if selector_pattern.search(s):
                evidence.append(
                    self._add_evidence(
                        class_file,
                        "",
                        0,
                        "Ethereum function selector 0xce6d41de (getText) detected",
                        Severity.CRITICAL,
                        matched_value=s[:200],
                    )
                )

            for rpc in eth_rpc_patterns:
                if rpc in s.lower():
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            "",
                            0,
                            f"Ethereum RPC endpoint: {rpc}",
                            Severity.MEDIUM,
                            matched_value=s[:200],
                        )
                    )

        # Check for RSA signature verification
        rsa_classes = {"java/security/Signature", "javax/crypto/Cipher"}
        for method in class_file.methods:
            if not method.bytecode:
                continue

            invokes = resolve_invokes(method.bytecode, cp)
            for inv in invokes:
                if inv.owner in rsa_classes and inv.name in ("verify", "initVerify", "doFinal"):
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            f"RSA/Signature operation: {inv.owner}.{inv.name}",
                            Severity.HIGH,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                        )
                    )

        return evidence
