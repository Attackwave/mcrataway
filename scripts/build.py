"""Build script for packaging mcrataway into a standalone binary using PyInstaller."""

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def copy_with_fallback(src: Path, dist_dir: Path, base_name: str) -> Path:
    """Copy src to dist_dir/base_name. If target is locked by OS/WSL, try base_name_1, base_name_2, etc."""
    target_path = dist_dir / base_name
    if src.resolve() == target_path.resolve():
        return src

    stem = target_path.stem
    ext = target_path.suffix

    candidates = [base_name] + [f"{stem}_{i}{ext}" for i in range(1, 20)]

    for candidate in candidates:
        target = dist_dir / candidate
        try:
            if target.resolve() == src.resolve():
                return target
            if target.exists():
                target.unlink()
            shutil.copy2(src, target)
            return target
        except (PermissionError, OSError):
            continue

    # Fallback to timestamp if all numbered candidates are locked
    timestamp_target = dist_dir / f"{stem}_{int(time.time())}{ext}"
    shutil.copy2(src, timestamp_target)
    return timestamp_target


def main() -> None:
    root_dir = Path(__file__).parent.parent
    src_dir = root_dir / "src"
    entry_point = src_dir / "mcrataway" / "__main__.py"

    is_windows = sys.platform == "win32"
    exe_name = "mcrataway.exe" if is_windows else "mcrataway"

    # Ensure any old spec file is removed so PyInstaller generates a clean spec
    spec_file = root_dir / "mcrataway.spec"
    if spec_file.exists():
        try:
            spec_file.unlink()
        except OSError:
            pass

    # Use dist_win for Windows builds to avoid 9P file permission locks across WSL shares
    dist_dir = root_dir / ("dist_win" if is_windows else "dist")
    dist_dir.mkdir(parents=True, exist_ok=True)

    # Compile into system TEMP directory across platforms to avoid in-place copy locks
    temp_dist_dir = Path(tempfile.gettempdir()) / "mcrataway_build"

    print(f"Building standalone binary for mcrataway from {entry_point}...")

    # Cross-platform path separator for PyInstaller --add-data (';' on Windows, ':' on Posix)
    sep = os.pathsep

    packs_dir = src_dir / "mcrataway" / "rules" / "packs"
    static_dir = src_dir / "mcrataway" / "server" / "static"

    add_data_flags: list[str] = []
    if packs_dir.exists():
        add_data_flags.extend(["--add-data", f"{packs_dir}{sep}mcrataway/rules/packs"])
    if static_dir.exists():
        add_data_flags.extend(["--add-data", f"{static_dir}{sep}mcrataway/server/static"])

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--onefile",
        "--name",
        "mcrataway",
        "--distpath",
        str(temp_dist_dir),
        "--paths",
        str(src_dir),
        "--collect-submodules",
        "mcrataway",
        *add_data_flags,
        str(entry_point),
    ]

    try:
        subprocess.run(cmd, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as err:
        print(f"\nBuild failed: {err}")
        print("Ensure pyinstaller and mcrataway dependencies are installed: pip install -e .[dev] pyinstaller")
        sys.exit(1)

    # Copy binary to dist_dir with automatic fallback counter if target file is locked
    compiled_binary = temp_dist_dir / exe_name
    if compiled_binary.exists():
        final_path = copy_with_fallback(compiled_binary, dist_dir, exe_name)
        if final_path.name != exe_name:
            print(f"[INFO] '{exe_name}' is currently locked. Copied binary as '{final_path.name}'.")
        print(f"\nBuild completed successfully! Binary located in {final_path}")


if __name__ == "__main__":
    main()
