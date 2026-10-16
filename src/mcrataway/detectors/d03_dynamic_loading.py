"""D03 — Dynamic class loading detector.

Catches:
- URLClassLoader
- ClassLoader.defineClass
- Class.forName with dynamic strings
- In-memory class loading patterns
"""

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import resolve_invokes

# Calls on a class loader that actually obtain or define a class. A
# read-only accessor such as ``URLClassLoader.getURLs`` says no more than
# a reference to the class does, and rating it the same as the
# constructor made JNA's ``Native`` read as native-DLL staging next to
# D07 — every mod bundling JNA has ``System.load()`` and a class-loader
# call in that one class and reached MALICIOUS.
_LOADING_METHODS = frozenset({"<init>", "loadClass", "findClass", "defineClass", "newInstance"})


def _severity_for(method_name: str, is_stdlib: bool) -> Severity:
    """Severity of a URLClassLoader/SecureClassLoader call in a class."""
    return Severity.HIGH if method_name in _LOADING_METHODS and not is_stdlib else Severity.MEDIUM


class D03DynamicLoading(Detector):
    @property
    def detector_id(self) -> str:
        return "d03"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        dangerous_classes = {
            "java/net/URLClassLoader",
            "java/security/SecureClassLoader",
        }

        dangerous_methods = {
            ("java/lang/ClassLoader", "defineClass"),
            ("java/lang/Class", "forName"),
            # Defining a class from a byte array through a Lookup is the
            # same capability as ClassLoader.defineClass without needing
            # a subclass, and it is how modern loaders (and malware)
            # avoid the ClassLoader API. MEDIUM, like defineClass: nine
            # popular mods in the local corpus (Sodium, Embeddium,
            # Trinkets, Cardinal Components, c2me, XaeroPlus) use it for
            # ASM-generated code, so a hit is a lead, not a verdict.
            ("java/lang/invoke/MethodHandles$Lookup", "defineClass"),
            ("java/lang/invoke/MethodHandles$Lookup", "defineHiddenClass"),
        }

        std_lib_prefixes = (
            "kotlin/",
            "kotlinx/",
            "org/jetbrains/",
            "it/unimi/dsi/fastutil/",
            "com/google/gson/",
            "org/apache/commons/",
        )
        is_stdlib = class_file.this_class.startswith(std_lib_prefixes)

        for method in class_file.methods:
            if not method.bytecode:
                continue

            invokes = resolve_invokes(method.bytecode, cp, class_file.bootstrap_methods)
            for inv in invokes:
                if inv.owner in dangerous_classes:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            f"Dynamic class loading via {inv.owner}.{inv.name}",
                            _severity_for(inv.name, is_stdlib),
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                            context={"invoke_owner": inv.owner, "invoke_name": inv.name},
                        )
                    )

                if (inv.owner, inv.name) in dangerous_methods:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            f"Dynamic class resolution: {inv.owner}.{inv.name}",
                            Severity.MEDIUM if not is_stdlib else Severity.INFO,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                            context={"invoke_owner": inv.owner, "invoke_name": inv.name},
                        )
                    )

        return evidence
