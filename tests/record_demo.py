"""Record and dump clean, ANSI-stripped demo transcript for judges and evaluation."""

import os
import re
import subprocess
import sys
from pathlib import Path

# ANSI escape sequence regex
ANSI_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return ANSI_REGEX.sub("", text)


def record_demo() -> Path:
    repo_root = Path(__file__).parent.parent
    demo_script = repo_root / "demo.py"
    output_file = repo_root / "demo_transcript.txt"

    # Resolve python interpreter
    venv_py = repo_root / ".venv" / ("Scripts" if sys.platform == "win32" else "bin") / ("python.exe" if sys.platform == "win32" else "python")
    python_bin = str(venv_py) if venv_py.exists() else sys.executable

    print(f"[*] Executing {demo_script} using {python_bin} in auto mode...")
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = str(repo_root)

    proc = subprocess.run(
        [python_bin, str(demo_script), "--auto"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=120,
    )

    combined_output = proc.stdout + ("\n--- STDERR ---\n" + proc.stderr if proc.stderr else "")
    clean_text = strip_ansi(combined_output)

    # Ensure CRLF/LF normalization
    output_file.write_text(clean_text, encoding="utf-8")

    print(f"[+] Demo transcript saved -> {output_file}")
    print(f"[+] Total lines: {len(clean_text.splitlines())}, Size: {output_file.stat().st_size} bytes")
    print(f"[+] Demo Exit Code: {proc.returncode}")

    if proc.returncode != 0:
        print("[!] Warning: Demo exited with non-zero status code.")
        sys.exit(proc.returncode)

    return output_file


if __name__ == "__main__":
    record_demo()
