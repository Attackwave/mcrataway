"""Tests for rule-pack signature integrity.

Every rule pack shipped in the repo (src/mcrataway/rules/packs/*.yaml)
must carry a valid detached signature (.yaml.sig) that verifies against
the public key embedded in rules/signing.py (TRUSTED_PUBLIC_KEYS_B64).

This catches:
  - A pack that was edited but not re-signed (the .sig is now stale).
  - A key rotation that updated the public key but not the .sig files.
  - A missing .sig file for a newly-added pack.

Without this test, a stale-signed pack would only be discovered when a
user's scanner rejects the remote update — silent breakage of the
entire dynamic-update feature.
"""

from pathlib import Path

from mcrataway.rules.signing import TRUSTED_PUBLIC_KEYS_B64, verify_file

PACKS_DIR = Path(__file__).resolve().parents[2] / "src" / "mcrataway" / "rules" / "packs"


def test_trust_root_is_provisioned():
    """The trust root must not be empty — an empty TRUSTED_PUBLIC_KEYS_B64
    rejects ALL remote rule packs, which silently disables dynamic
    updates in production."""
    assert len(TRUSTED_PUBLIC_KEYS_B64) > 0, (
        "TRUSTED_PUBLIC_KEYS_B64 is empty — no remote rule pack can be "
        "verified. Provision a signing key (see rules/signing.py)."
    )


def test_all_shipped_packs_are_signed_and_verify():
    """Every .yaml pack in the repo must have a .sig sibling that
    validates against the shipped trust root."""
    packs = sorted(PACKS_DIR.glob("*.yaml"))
    assert packs, "No rule packs found — expected at least the built-in packs."

    for pack in packs:
        sig = pack.with_name(pack.name + ".sig")
        assert sig.exists(), f"Missing signature for {pack.name}"
        assert verify_file(pack), (
            f"{pack.name} signature does not verify against the shipped "
            "public key — re-sign the pack (see .github/workflows/sign-rules.yml)."
        )
