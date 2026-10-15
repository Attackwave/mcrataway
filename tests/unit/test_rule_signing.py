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

from mcrataway.rules import signing
from mcrataway.rules.loader import RulePackLoader
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


def _pack_yaml(pack_id: str, rule_id: str = "r1") -> str:
    return (
        f"pack_id: {pack_id}\n"
        "rules:\n"
        f"  - id: {rule_id}\n"
        "    family: test\n"
        "    severity: medium\n"
        "    description: test rule\n"
        "    condition: any\n"
        "    strings:\n"
        "      - kind: literal\n"
        "        value: evil\n"
    )


def _write_signed_pack(path: Path, text: str, private_key_b64: str) -> None:
    # write_bytes: write_text translates the newlines to CRLF on Windows,
    # and the signature covers the exact bytes it was made over.
    data = text.encode()
    path.write_bytes(data)
    path.with_name(path.name + ".sig").write_text(signing.sign_data(data, private_key_b64))


def test_load_pack_ignores_a_pack_whose_signature_no_longer_matches(
    tmp_path: Path, monkeypatch
) -> None:
    """A pack is verified when it is downloaded; the copy on disk can be
    changed afterwards, so load has to check the signature again rather
    than trust that the file is still the one that was signed."""
    private_b64, public_b64 = signing.generate_keypair()
    monkeypatch.setattr(signing, "TRUSTED_PUBLIC_KEYS_B64", (public_b64,))

    pack = tmp_path / "remote_pack_1.yaml"
    _write_signed_pack(pack, _pack_yaml("remote_pack_1"), private_b64)
    pack.write_text(_pack_yaml("remote_pack_1", rule_id="weakened"))

    loader = RulePackLoader()
    loader.load_pack(pack)

    assert loader.all_rules() == []


def test_load_pack_accepts_a_pack_whose_signature_verifies(
    tmp_path: Path, monkeypatch
) -> None:
    private_b64, public_b64 = signing.generate_keypair()
    monkeypatch.setattr(signing, "TRUSTED_PUBLIC_KEYS_B64", (public_b64,))

    pack = tmp_path / "remote_pack_1.yaml"
    _write_signed_pack(pack, _pack_yaml("remote_pack_1"), private_b64)

    loader = RulePackLoader()
    loader.load_pack(pack)

    assert [p.pack_id for p in loader.all_rules()] == ["remote_pack_1"]


def test_an_unsigned_pack_cannot_replace_a_builtin_pack(tmp_path: Path) -> None:
    """Reusing a built-in pack_id is how a dropped file would delete the
    shipped detections; without a signature that is refused."""
    loader = RulePackLoader()
    loader.load_defaults()
    builtin_packs = [p for p in loader.all_rules() if p.builtin]
    assert builtin_packs, "expected the built-in packs to load"
    victim = builtin_packs[0]

    impostor = tmp_path / "impostor.yaml"
    impostor.write_text(_pack_yaml(victim.pack_id, rule_id="only_rule"))

    loader.load_pack(impostor)

    reloaded = {p.pack_id: p for p in loader.all_rules()}[victim.pack_id]
    assert reloaded.rules == victim.rules
    assert reloaded.builtin


def test_an_unsigned_pack_with_a_new_id_is_still_loaded(tmp_path: Path) -> None:
    """Locally authored packs stay trusted implicitly (docs/RULES.md) —
    the load-time check only applies to packs that carry a signature."""
    loader = RulePackLoader()
    local = tmp_path / "my_pack.yaml"
    local.write_text(_pack_yaml("my_local_pack"))

    loader.load_pack(local)

    assert "my_local_pack" in {p.pack_id for p in loader.all_rules()}


def test_a_signed_pack_may_replace_a_builtin_pack(tmp_path: Path, monkeypatch) -> None:
    """A verified pack is how the updater ships a newer version of a
    built-in pack, so the shadow guard must not block it."""
    loader = RulePackLoader()
    loader.load_defaults()
    builtin_packs = [p for p in loader.all_rules() if p.builtin]
    assert builtin_packs, "expected the built-in packs to load"
    target = builtin_packs[0]

    # Loaded first: swapping the trust root for a test key would stop the
    # shipped packs from verifying.
    private_b64, public_b64 = signing.generate_keypair()
    monkeypatch.setattr(signing, "TRUSTED_PUBLIC_KEYS_B64", (public_b64,))

    update = tmp_path / "remote_pack_1.yaml"
    _write_signed_pack(update, _pack_yaml(target.pack_id, rule_id="updated"), private_b64)

    loader.load_pack(update)

    replaced = {p.pack_id: p for p in loader.all_rules()}[target.pack_id]
    assert [rule.rule_id for rule in replaced.rules] == ["updated"]
    assert not replaced.builtin
