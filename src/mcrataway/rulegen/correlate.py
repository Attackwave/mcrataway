"""Cross-sample correlation/generalization of candidate features.

Deliberately simple: a frequency threshold over exact value equality,
not a clustering/ML algorithm. Merging same-value candidates across
samples and keeping only those that appear in enough of them avoids
overfitting a proposed rule to one specific sample variant.
"""

from __future__ import annotations

from mcrataway.rulegen.features import CandidateFeature


def generalize(
    per_sample_candidates: list[list[CandidateFeature]],
    min_sample_fraction: float = 0.6,
) -> list[CandidateFeature]:
    """Merge same-value candidates across samples; keep only those
    appearing in >= min_sample_fraction of samples.

    A single-sample input (len == 1) short-circuits to "keep
    everything from that sample" — this is the local single-sample
    mode's path.
    """
    if not per_sample_candidates:
        return []

    if len(per_sample_candidates) == 1:
        return list(per_sample_candidates[0])

    # Keyed by (value, kind), not value alone: two samples can expose
    # the same underlying string through different pattern kinds (e.g.
    # one sample has it in the plain constant pool as a "literal",
    # another only recovers it as a "hex" pattern from an obfuscated
    # byte sequence). Merging those into a single CandidateFeature
    # would silently drop one kind and could propose a pattern that
    # cannot match the samples that only exhibited the other kind.
    merged: dict[tuple[str, str], CandidateFeature] = {}
    for sample_candidates in per_sample_candidates:
        for cand in sample_candidates:
            key = (cand.value, cand.kind)
            existing = merged.get(key)
            if existing is None:
                merged[key] = CandidateFeature(
                    kind=cand.kind,
                    value=cand.value,
                    source=cand.source,
                    technique=cand.technique,
                    sample_hashes=set(cand.sample_hashes),
                    detector_ids=set(cand.detector_ids),
                )
            else:
                existing.sample_hashes |= cand.sample_hashes
                existing.detector_ids |= cand.detector_ids

    total_samples = len(per_sample_candidates)
    threshold = min_sample_fraction * total_samples
    return [
        cand for cand in merged.values()
        if len(cand.sample_hashes) >= threshold
    ]
