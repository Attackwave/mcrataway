"""Signature verification for remotely-fetched YAML rule packs.

Downloaded rules directly control which files are flagged as
malicious and, with auto-quarantine enabled, which files get removed
from disk. ``yaml.safe_load`` prevents code execution from a
malicious rule file, but does nothing to stop a compromised
distribution channel (repo takeover, MITM'd HTTPS despite TLS, a
malicious mirror) from shipping rules that either wave through real
malware or quarantine arbitrary benign mods. Signing closes that gap:
only rule packs signed by a trusted Ed25519 key are accepted.

Each rule pack ``foo.yaml`` is distributed alongside a detached
signature ``foo.yaml.sig`` — a base64-encoded Ed25519 signature over
the exact bytes of ``foo.yaml``. The trusted public key(s) are
embedded in this module (the scanner's own trust root), not
downloaded, so an attacker who controls the download channel cannot
also supply their own "trusted" key.
"""

import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Trusted public keys, base64-encoded raw Ed25519 public key bytes.
# Rule packs signed by any key NOT in this list are rejected. This list
# is the scanner's trust root — it ships with the binary, not downloaded,
# so an attacker who controls the download channel cannot also supply
# their own "trusted" key.
#
# The corresponding private key is held as a GitHub Actions secret
# (MCRATAWAY_RULE_SIGNING_KEY) and is never committed to the repo. The
# sign-rules workflow (.github/workflows/sign-rules.yml) re-signs every
# rule pack on each push to main, so the .sig files in the repo are
# always current. To rotate the key, generate a new keypair
# (rules.signing.generate_keypair), update the public key here AND the
# Actions secret, then re-run the workflow.
TRUSTED_PUBLIC_KEYS_B64: tuple[str, ...] = (
    "OsjTxfjX7fdD5dmLuN35wDRITQhCWDpEpOrOCSCcsSo=",
)


def generate_keypair() -> tuple[str, str]:
    """Generate a new Ed25519 keypair for signing rule packs.

    Returns (private_key_b64, public_key_b64). The private key must be
    kept offline/secret by whoever maintains the rule-pack repository;
    the public key is added to :data:`TRUSTED_PUBLIC_KEYS_B64` and
    shipped with the scanner.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes_raw()
    public_bytes = public_key.public_bytes_raw()

    return (
        base64.b64encode(private_bytes).decode("ascii"),
        base64.b64encode(public_bytes).decode("ascii"),
    )


def sign_data(data: bytes, private_key_b64: str) -> str:
    """Sign *data* with a base64-encoded raw Ed25519 private key.

    Returns the base64-encoded signature (the contents of a
    ``.sig`` file).
    """
    private_bytes = base64.b64decode(private_key_b64)
    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    signature = private_key.sign(data)
    return base64.b64encode(signature).decode("ascii")


def verify_signature(data: bytes, signature_b64: str) -> bool:
    """Verify *data* against a base64-encoded signature using any of
    the trusted public keys. Returns True if any trusted key validates
    the signature.
    """
    if not TRUSTED_PUBLIC_KEYS_B64:
        return False

    try:
        signature = base64.b64decode(signature_b64)
    except Exception:
        return False

    for key_b64 in TRUSTED_PUBLIC_KEYS_B64:
        try:
            public_bytes = base64.b64decode(key_b64)
            public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
            public_key.verify(signature, data)
            return True
        except (InvalidSignature, Exception):
            continue

    return False


def verify_file(data_path: Path) -> bool:
    """Verify a rule pack file against its detached ``.sig`` sibling.

    Returns False if the signature file is missing, unreadable, or
    does not validate against any trusted key.
    """
    sig_path = data_path.with_name(data_path.name + ".sig")
    if not sig_path.exists():
        return False

    try:
        data = data_path.read_bytes()
        signature_b64 = sig_path.read_text().strip()
    except Exception:
        return False

    return verify_signature(data, signature_b64)
