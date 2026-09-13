import os
import re
import sys
import subprocess

_CACHE = {}


def _is_interactive() -> bool:
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


def _auto_yes() -> bool:
    return os.environ.get("PHISHSCAN_YES", "").lower() in ("1", "true", "yes", "y")


def _normalize(s: str) -> str:
    s = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", s)
    s = "".join(c for c in s if c.isprintable() and c != "\r")
    return s.strip().lower()


def ensure(import_name: str, pip_name: str = None, reason: str = "") -> bool:
    if import_name in _CACHE:
        return _CACHE[import_name]

    try:
        __import__(import_name)
        _CACHE[import_name] = True
        return True
    except ImportError:
        pass

    if not (_is_interactive() or _auto_yes()):
        _CACHE[import_name] = False
        return False

    pip_name = pip_name or import_name

    if _auto_yes():
        ans = "y"
    else:
        print()
        print(f"  Paket '{pip_name}' belum terpasang.")
        if reason:
            print(f"  Kegunaan: {reason}")
        sys.stdout.flush()
        sys.stderr.flush()
        try:
            raw = input("  Install sekarang? [y/N]: ")
        except EOFError:
            raw = ""
        ans = _normalize(raw)
        if ans and not ans.startswith("y"):
            print(f"  [debug] input mentah: {raw!r}")
            print(f"  [debug] setelah normalisasi: {ans!r}")

    accept = ans.startswith("y") or ans in ("1", "ya", "yes")

    if not accept:
        print("  → dilewati.")
        _CACHE[import_name] = False
        return False

    print(f"  → memasang {pip_name} ...")
    sys.stdout.flush()
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", pip_name],
        )
        __import__(import_name)
        _CACHE[import_name] = True
        print(f"  ✔ {pip_name} berhasil dipasang.")
        return True
    except Exception as e:
        print(f"  ✘ Gagal memasang {pip_name}: {e}")
        _CACHE[import_name] = False
        return False
