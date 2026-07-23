"""Generate synthetic malicious and benign JAR fixtures for testing."""

import struct
import zipfile
from io import BytesIO
from pathlib import Path


def _make_class_bytecode(
    strings_to_ldc: list[str] | None = None,
    invoke_bytecode: bytes = b"",
) -> bytes:
    """Build bytecode that loads strings and optionally invokes methods.

    Returns raw bytecode (no method header).
    """
    bc = bytearray()
    # Load strings via ldc_w (opcode 19). Constant-pool layout in
    # _build_class_file is: 1=class_name, 2=Object, 3=method_name,
    # 4=()V, 5="Code", 6+=cp_strings — so cp_strings[i] lives at
    # index 6 + i.
    for i in range(len(strings_to_ldc or [])):
        bc += struct.pack(">BH", 19, 6 + i)  # ldc_w, constant pool index

    # Add invoke bytecode
    if invoke_bytecode:
        bc += invoke_bytecode

    bc += struct.pack(">B", 177)  # return
    return bytes(bc)


def _build_minimal_jar(
    classes: list[tuple[str, bytes]],
    manifest: dict[str, bytes] | None = None,
) -> bytes:
    """Build a minimal JAR file with given class entries and optional manifest."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if manifest:
            for name, data in manifest.items():
                zf.writestr(name, data)
        for name, data in classes:
            zf.writestr(name, data)
    return buf.getvalue()


def _build_class_file(
    class_name: str,
    method_name: str,
    bytecode: bytes,
    cp_strings: list[str],
) -> bytes:
    """Build a valid .class file from parts.

    Constant-pool layout (1-indexed):
        1 -> class_name (Utf8)
        2 -> "java/lang/Object" (Utf8)
        3 -> method_name (Utf8)
        4 -> "()V" (Utf8)
        5 -> "Code" (Utf8)  <-- used as the Code attribute name
        6+ -> cp_strings

    The previous implementation set ``name_idx = 1`` for the Code
    attribute, which pointed at the class name Utf8 entry instead of
    "Code", so the classfile parser never recognized the attribute and
    ``MethodInfo.bytecode`` was always ``b""``. Invoke-based detectors
    (D01/D03/D06/D07/D10) thus never ran on generated fixtures.
    """
    all_strings = [class_name, "java/lang/Object", method_name, "()V", "Code"] + cp_strings
    pool = struct.pack(">H", 1 + len(all_strings))
    for s in all_strings:
        encoded = s.encode("utf-8")
        pool += struct.pack(">BH", 1, len(encoded)) + encoded

    # Code attribute body: max_stack, max_locals, code_length, code,
    # then exception_table_count=0 and attributes_count=0 (4 bytes
    # total — the previous code wrote 8 bytes, mismatching `length`).
    code_attr = struct.pack(">HHI", 1, 2, len(bytecode))
    code_attr += bytecode
    code_attr += struct.pack(">HH", 0, 0)

    # Code attribute wrapper — name_idx 5 points at the "Code" Utf8
    code_attr_name_idx = 5
    method = struct.pack(">HHH", 0x0001, 3, 4)  # access, name_idx=3, desc_idx=4
    method += struct.pack(">H", 1)  # attributes_count = 1 (no extra length field)
    method += struct.pack(">HI", code_attr_name_idx, len(code_attr))
    method += code_attr

    body = struct.pack(">HHHHHH", 0x0001, 1, 2, 0, 0, 1)
    body += method
    body += struct.pack(">H", 0)

    return b"\xCA\xFE\xBA\xBE" + struct.pack(">HH", 0, 52) + pool + body


def generate_benign_mod(tmp_path: Path) -> Path:
    """Generate a benign mod JAR (simple rendering helper)."""
    bc = _make_class_bytecode()
    class_data = _build_class_file(
        "com/example/RenderHelper", "render", bc,
        cp_strings=["rendering", "helper"],
    )
    jar_data = _build_minimal_jar([("com/example/RenderHelper.class", class_data)])
    out = tmp_path / "benign_mod.jar"
    out.write_bytes(jar_data)
    return out


def generate_session_stealer(tmp_path: Path) -> Path:
    """Generate a synthetic session token stealer JAR.

    Contains:
    - References to getSession, getAccessToken
    - HTTP POST to a URL
    """
    cp_strings = [
        "getSession",
        "getAccessToken",
        "https://evil.example.com/collect",
        "java/net/http/HttpClient",
        "net/minecraft/client/MinecraftClient",
    ]
    bc = _make_class_bytecode(cp_strings)
    class_data = _build_class_file(
        "com/stealer/Exfil", "steal", bc,
        cp_strings=cp_strings,
    )
    jar_data = _build_minimal_jar([("com/stealer/Exfil.class", class_data)])
    out = tmp_path / "session_stealer.jar"
    out.write_bytes(jar_data)
    return out


def generate_eth_c2_mod(tmp_path: Path) -> Path:
    """Generate a synthetic on-chain C2 JAR.

    Contains:
    - Function selector 0xce6d41de
    - eth_call reference
    """
    cp_strings = [
        "ce6d41de",
        "eth_call",
        "https://mainnet.infura.io/v3/...",
        "java/security/Signature",
    ]
    bc = _make_class_bytecode(cp_strings)
    class_data = _build_class_file(
        "com/c2/Resolver", "resolve", bc,
        cp_strings=cp_strings,
    )
    jar_data = _build_minimal_jar([("com/c2/Resolver.class", class_data)])
    out = tmp_path / "eth_c2_mod.jar"
    out.write_bytes(jar_data)
    return out


def generate_native_loader(tmp_path: Path) -> Path:
    """Generate a synthetic native DLL loader JAR.

    Contains:
    - System.load reference
    - createTempFile + deleteOnExit
    - .dll extension string
    """
    cp_strings = [
        "System.load",
        "createTempFile",
        "deleteOnExit",
        "libpayload.dll",
    ]
    bc = _make_class_bytecode(cp_strings)
    class_data = _build_class_file(
        "com/native/Loader", "load", bc,
        cp_strings=cp_strings,
    )
    jar_data = _build_minimal_jar([("com/native/Loader.class", class_data)])
    out = tmp_path / "native_loader.jar"
    out.write_bytes(jar_data)
    return out


def generate_all_fixtures(output_dir: Path) -> list[Path]:
    """Generate all fixture JARs and return their paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    return [
        generate_benign_mod(output_dir),
        generate_session_stealer(output_dir),
        generate_eth_c2_mod(output_dir),
        generate_native_loader(output_dir),
    ]


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        out = Path(sys.argv[1])
    else:
        out = Path(__file__).resolve().parent

    paths = generate_all_fixtures(out)
    for p in paths:
        print(f"Generated: {p} ({p.stat().st_size} bytes)")
