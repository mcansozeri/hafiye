#!/usr/bin/env python3
"""
Builds a working, patched detect-secrets under  tools/detect-secrets-patched/
from the files in  upgrade/tools/detect-secrets/  — WITHOUT touching the venv
or the existing project layout (secret_scanner_main.py keeps working as before).

What it does
  1. git clone Yelp/detect-secrets at tag v1.5.0  ->  tools/detect-secrets-patched
  2. copies upgrade/.../settings.py, filters/heuristic.py, plugins/keyword.py into it
  3. fixes keyword.py imports (secret_keeper.* -> detect_secrets relative imports)
  4. adds the FileType members keyword.py needs (JAVA_PROPERTIES, PACKAGE_JSON)
  5. verifies: imports, filters, and a scan of a small sample with Turkish keywords

Usage (project root, project venv):
    pip install pyenchant           # macOS also needs:  brew install enchant
    python setup_patched_tools.py
    python setup_patched_tools.py --verify-only

run_benchmark.py picks the patched copy up automatically (PYTHONPATH), and records
both 'stock' and 'patched' detect-secrets results so the contribution of the
customisations can be reported as an ablation row.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path.cwd()
UPGRADE = ROOT / "upgrade" / "tools" / "detect-secrets" / "detect_secrets"
TARGET = ROOT / "tools" / "detect-secrets-patched"
PKG = TARGET / "detect_secrets"
REPO = "https://github.com/Yelp/detect-secrets"
TAG = "v1.5.0"

IMPORT_FIXES = [
    (r"from secret_keeper\.core\.potential_secret import PotentialSecret",
     "from ..core.potential_secret import PotentialSecret"),
    (r"from secret_keeper\.util\.filetype import determine_file_type",
     "from ..util.filetype import determine_file_type"),
    (r"from secret_keeper\.util\.filetype import FileType",
     "from ..util.filetype import FileType"),
    (r"from secret_keeper\.core\.plugins\.base import BasePlugin",
     "from .base import BasePlugin"),
]


def run(cmd, **kw):
    print("  $", " ".join(cmd) if isinstance(cmd, list) else cmd, flush=True)
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw)


def clone():
    if PKG.exists():
        print(f"[1] {TARGET} exists, skipping clone")
        return
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    print(f"[1] cloning detect-secrets {TAG}")
    run(["git", "clone", "--quiet", "--depth", "1", "--branch", TAG, REPO, str(TARGET)])


def apply_upgrade():
    print("[2] applying upgrade files")
    pairs = [
        (UPGRADE / "settings.py", PKG / "settings.py"),
        (UPGRADE / "filters" / "heuristic.py", PKG / "filters" / "heuristic.py"),
        (UPGRADE / "plugins" / "keyword.py", PKG / "plugins" / "keyword.py"),
    ]
    for src, dst in pairs:
        if not src.exists():
            sys.exit(f"  !! missing {src}")
        shutil.copy2(src, dst)
        print(f"  {src.relative_to(ROOT)} -> {dst.relative_to(ROOT)}")

    print("[3] fixing keyword.py imports")
    kw = PKG / "plugins" / "keyword.py"
    text = kw.read_text(encoding="utf-8")
    for pat, rep in IMPORT_FIXES:
        text, n = re.subn(pat, rep, text)
        if n:
            print(f"  {pat.split('import')[0].strip()} -> {rep}")
    kw.write_text(text, encoding="utf-8")

    print("[4] extending FileType")
    ft = PKG / "util" / "filetype.py"
    text = ft.read_text(encoding="utf-8")
    if "PACKAGE_JSON" not in text:
        text = re.sub(r"(\n    OTHER = )(\d+)", lambda m: f"\n    JAVA_PROPERTIES = {int(m.group(2))+1}\n    PACKAGE_JSON = {int(m.group(2))+2}{m.group(1)}{m.group(2)}", text, count=1)
        # package.json is matched by basename before the extension table
        text = text.replace(
            "def determine_file_type(filename: str) -> FileType:\n",
            "def determine_file_type(filename: str) -> FileType:\n"
            "    if os.path.basename(filename) == 'package.json':\n"
            "        return FileType.PACKAGE_JSON\n")
        ft.write_text(text, encoding="utf-8")
        print("  added JAVA_PROPERTIES, PACKAGE_JSON")
    else:
        print("  already extended")


def env_with_patched():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(TARGET) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return env


def verify():
    print("[5] verifying")
    env = env_with_patched()
    code = (
        "import detect_secrets, detect_secrets.filters.heuristic as h, detect_secrets.plugins.keyword as k, detect_secrets.settings as s;"
        "print('module:', detect_secrets.__file__);"
        "print('language filter:', hasattr(h,'is_language_specific_string'));"
        "print('KeywordDetector.secret_type:', k.KeywordDetector.secret_type);"
        "print('sifre in DENYLIST:', 'sifre' in k.DENYLIST);"
        "print('filter registered:', any('is_language_specific_string' in f for f in s.Settings().filters))"
    )
    r = subprocess.run([sys.executable, "-c", code], env=env, text=True, capture_output=True)
    print(r.stdout, end="")
    if r.returncode != 0:
        print(r.stderr)
        if "enchant" in r.stderr:
            print("  !! pyenchant / enchant library missing.  macOS:  brew install enchant && pip install pyenchant")
        sys.exit("  !! verification failed")

    # detect-secrets silently ignores paths outside the current directory -> temp dir inside ROOT
    with tempfile.TemporaryDirectory(dir=ROOT, prefix="_verify_") as td:
        td = os.path.relpath(td, ROOT)
        sample = Path(td) / "Config.java"
        sample.write_text(
            'public class Config {\n'
            '  String sifre = "Xk9#pLq2$vT7wZ";\n'
            '  String password = "hunter2hunter2";\n'
            '  int keyLength = 256;\n'
            '  String db_password = "example";\n'
            '}\n', encoding="utf-8")
        r = subprocess.run([sys.executable, "-m", "detect_secrets", "scan", "--all-files", td],
                           env=env, text=True, capture_output=True)
        import json
        out = json.loads(r.stdout) if r.stdout.strip() else {}
        found = [(s["line_number"], s["type"]) for v in out.get("results", {}).values() for s in v]
        print("  sample scan findings:", found)
        ok = any(t == "KeywordDetector" for _, t in found) and any(ln == 2 for ln, _ in found)
        print("  Turkish keyword 'sifre' detected:", any(ln == 2 for ln, _ in found))
        print("  dictionary word 'example' filtered:", not any(ln == 5 for ln, _ in found))
        if not ok:
            print(r.stderr[-800:])
            sys.exit("  !! patched scanner did not behave as expected")
    print("[OK] patched detect-secrets ready at", TARGET.relative_to(ROOT))
    print("     use it manually with:  PYTHONPATH=tools/detect-secrets-patched python -m detect_secrets scan --all-files <dir>")


if __name__ == "__main__":
    if "--verify-only" not in sys.argv:
        clone()
        apply_upgrade()
    verify()
