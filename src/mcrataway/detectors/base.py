"""Detector base class — interface for all capability detectors."""

from abc import ABC, abstractmethod

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.parsers.classfile import ClassFile


class Detector(ABC):
    """Base class for all bytecode capability detectors."""

    @property
    @abstractmethod
    def detector_id(self) -> str:
        """Unique identifier for this detector (e.g., 'd01', 'd02')."""

    @abstractmethod
    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        """Analyze a parsed class file and return evidence found."""

    def analyze_archive_entry(self, entry_name: str, entry_data: bytes) -> list[Evidence]:
        """Analyze a non-class archive entry for suspicious content.

        Default implementation returns no evidence. Override in detectors
        that need to inspect PNG/JSON/mcfunction/etc. entries.
        """
        return []

    def _add_evidence(
        self,
        class_file: ClassFile,
        method_name: str,
        offset: int,
        description: str,
        severity: Severity,
        matched_value: str = "",
        context: dict[str, str] | None = None,
    ) -> Evidence:
        """Helper to create Evidence with standard fields."""
        return Evidence(
            detector_id=self.detector_id,
            severity=severity,
            class_name=class_file.this_class,
            method_name=method_name,
            offset=offset,
            description=description,
            matched_value=matched_value,
            context=context or {},
        )
