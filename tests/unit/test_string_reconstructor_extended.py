"""Tests for the extended string-reconstruction techniques (task 6.5):
char[] arrays, the weedhack/Majanito XOR cipher (decode_xor_cipher was
implemented but never actually invoked before), and Base64 decoding.

Uses real javac-compiled fixtures (tests/javac_fixtures/), not
hand-assembled bytecode, so the actual invoke/array-literal bytecode
shapes javac produces are what gets tested.
"""

import zipfile
from pathlib import Path

import pytest

from mcrataway.parsers.classfile import parse_class
from mcrataway.parsers.string_reconstructor import decode_xor_cipher, reconstruct_strings

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "javac_fixtures"


def _class_bytes(name: str) -> bytes:
    jar_path = FIXTURES_DIR / f"{name}.jar"
    if not jar_path.exists():
        pytest.skip(
            f"{jar_path} missing — run `python tests/build_javac_fixtures.py` "
            "(requires a JDK) to (re)generate javac fixtures"
        )
    with zipfile.ZipFile(jar_path) as zf:
        return zf.read(f"{name}.class")


def test_char_array_hidden_url_is_reconstructed() -> None:
    cf = parse_class(_class_bytes("CharArrayHiddenUrl"))
    assert cf is not None
    results = reconstruct_strings(cf)
    char_array_results = [r for r in results if r.technique == "char_array_string"]
    assert any(r.value == "https://evil.com" for r in char_array_results)


def test_base64_hidden_url_is_decoded() -> None:
    """Base64.getDecoder().decode(...) on a constant-pool literal must
    be recognized and decoded, gated on the Base64 API actually being
    called in the same method (so arbitrary base64-looking constants
    elsewhere in the class are not spuriously "decoded")."""
    cf = parse_class(_class_bytes("Base64HiddenUrl"))
    assert cf is not None
    results = reconstruct_strings(cf)
    base64_results = [r for r in results if r.technique == "base64_string"]
    assert any(r.value == "https://evil.example.com/collect" for r in base64_results)


def test_weedhack_cipher_call_is_actually_decoded() -> None:
    """Regression test: decode_xor_cipher existed and correctly
    implemented the weedhack/Majanito S-box+XOR inverse, but nothing
    extracted the int[]/int[]/int/int arguments from bytecode to call
    it with, so the cipher was never actually decoded despite the
    decoder being present. This verifies the Helper.load(int[], int[],
    int, int) call pattern is now recognized and decode_xor_cipher is
    actually invoked with the extracted arguments.
    """
    cf = parse_class(_class_bytes("WeedhackCipher"))
    assert cf is not None
    results = reconstruct_strings(cf)
    cipher_results = [r for r in results if r.technique == "weedhack_xor_cipher"]
    assert len(cipher_results) == 1

    # WeedhackCipher.java: d1=[10,20,30], d2=[40,50], k1=7, k2=3
    expected = decode_xor_cipher([10, 20, 30], [40, 50], 7, 3)
    assert cipher_results[0].value == expected


def test_decode_xor_cipher_is_reachable_from_reconstruct_strings() -> None:
    """Sanity check that the wiring is real, not just parameter
    extraction without an actual call: patch decode_xor_cipher and
    confirm reconstruct_strings's weedhack path actually invokes it."""
    from unittest.mock import patch

    import mcrataway.parsers.string_reconstructor as sr_module

    cf = parse_class(_class_bytes("WeedhackCipher"))
    assert cf is not None

    with patch.object(sr_module, "decode_xor_cipher", return_value="SENTINEL") as mock_decode:
        results = reconstruct_strings(cf)
        assert mock_decode.called
        assert any(r.value == "SENTINEL" for r in results)


class TestGenericXorCipher:
    """Tests for the generic repeating-key XOR cipher detector (task
    23: obfuskations-ausbau). Before this, the scanner only recognized
    the one specific weedhack S-box+XOR cipher — any other obfuscator
    using a plain repeating-key XOR with the key stored as an ordinary
    string constant in the same class went completely undetected.
    decode_simple_xor existed for this but, like decode_xor_cipher
    before it, was never actually called from reconstruct_strings.
    """

    def test_xor_hidden_url_is_decoded_with_correct_key(self) -> None:
        cf = parse_class(_class_bytes("XorHiddenUrl"))
        assert cf is not None
        results = reconstruct_strings(cf)
        xor_results = [r for r in results if r.technique == "generic_xor_cipher"]
        assert len(xor_results) == 1
        assert xor_results[0].value == "https://evil.example.com/exfil"

    def test_benign_byte_array_is_not_falsely_decoded(self) -> None:
        """A byte array unrelated to any cipher (magic-number bytes)
        must not produce a spurious generic_xor_cipher finding — the
        brute-force search over candidate keys must not "succeed" on
        data that just happens to look printable under some key."""
        cf = parse_class(_class_bytes("BenignByteArray"))
        assert cf is not None
        results = reconstruct_strings(cf)
        xor_results = [r for r in results if r.technique == "generic_xor_cipher"]
        assert xor_results == []

    def test_plausibility_check_rejects_random_printable_noise(self) -> None:
        """Regression test for the initial (too permissive) version of
        _is_plausible_text: a bare "printable ASCII" check let a WRONG
        candidate key's incidental printable-looking garbage win before
        the correct key was ever tried. The check must require mostly
        alphanumeric/path-like characters, not just "no control chars"."""
        from mcrataway.parsers.string_reconstructor import _is_plausible_text

        # Real, correct decode of the XorHiddenUrl fixture:
        assert _is_plausible_text("https://evil.example.com/exfil")
        # Printable-but-meaningless XOR noise (an actual wrong-key
        # output observed while decoding the same fixture with a
        # different candidate key) must be rejected:
        assert not _is_plausible_text("i&{0rh od$f,/7w!l\"c%/1`-.7w&h>")

    def test_is_plausible_text_rejects_too_short_strings(self) -> None:
        from mcrataway.parsers.string_reconstructor import _is_plausible_text

        assert not _is_plausible_text("abc")
        assert not _is_plausible_text("")
