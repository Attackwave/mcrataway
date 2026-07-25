"""Build JAR fixtures from real javac-compiled .class files.

Run this manually (requires a JDK — `javac`) whenever
fixtures/java_src/*.java changes:

    python tests/build_javac_fixtures.py

The output JARs under tests/javac_fixtures/ are checked into the repo
so running the test suite itself never requires a JDK — only
rebuilding the fixtures does.

tests/javac_fixtures/ is deliberately NOT under tests/fixtures/: the
websocket integration tests (tests/integration/test_websocket.py)
scan tests/fixtures/ as a custom root, and with quarantine-on-malicious
enabled by default, a fixture JAR correctly detected as MALICIOUS
would get moved into the real quarantine directory by that test run.
Keeping these fixtures in a sibling directory that no test scans as a
target root avoids that.

Why this exists: the older generate_all_fixtures() in generator.py
builds synthetic .class files by hand-assembling bytecode, and its
_make_class_bytecode() only ever emits `ldc_w` (load a constant pool
string) followed by `return` — it never emits an `invoke*`
instruction. That means every detector that resolves method calls
(D01 Runtime.exec/ProcessBuilder, D03 Class.forName/defineClass, D06
ObjectInputStream.readObject, D07 System.load, D10 MethodHandles) was
never actually exercised by those fixtures; only constant-pool string
matching was ever tested. These fixtures close that gap by compiling
real Java source with javac, so the resulting bytecode contains
genuine invoke* instructions.
"""

import subprocess
import sys
import zipfile
from pathlib import Path

SRC_DIR = Path(__file__).parent / "fixtures" / "java_src"
OUT_DIR = Path(__file__).parent / "javac_fixtures"


def build() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    java_files = sorted(SRC_DIR.glob("*.java"))
    if not java_files:
        print(f"No .java files found in {SRC_DIR}", file=sys.stderr)
        sys.exit(1)

    subprocess.run(
        ["javac", "-g", *[str(f) for f in java_files]],
        cwd=SRC_DIR,
        check=True,
    )

    for java_file in java_files:
        class_name = java_file.stem
        class_file = SRC_DIR / f"{class_name}.class"
        if not class_file.exists():
            print(f"Expected {class_file} after compilation, not found", file=sys.stderr)
            continue

        jar_path = OUT_DIR / f"{class_name}.jar"
        with zipfile.ZipFile(jar_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{class_name}.class", class_file.read_bytes())
        print(f"Built {jar_path}")

        class_file.unlink()  # clean up the intermediate .class file


if __name__ == "__main__":
    build()
