#!/usr/bin/env python3
"""
PhishScan CLI — analisis URL mencurigakan.

Pemakaian:
    python phishscan.py <url>
    python phishscan.py --json <url>
    python phishscan.py --verbose <url>
    python phishscan.py --no-color <url>

Env:
    NO_COLOR=1                → matikan warna
    PHISHSCAN_YES=1           → auto-install dependency opsional
    PHISHSCAN_ALLOW_PRIVATE=1 → izinkan scan IP privat (hati-hati!)
"""
import os
import sys
import json
import argparse

_THIS = os.path.dirname(os.path.abspath(__file__))
if _THIS not in sys.path:
    sys.path.insert(0, _THIS)


# ---------- warna ----------
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[31m"
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    BLUE   = "\033[34m"
    MAGENTA= "\033[35m"
    CYAN   = "\033[36m"


def _supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return stream.isatty()
    except Exception:
        return False


USE_COLOR = _supports_color(sys.stdout)


def color(s, *codes):
    if not USE_COLOR or not codes:
        return s
    return "".join(codes) + s + C.RESET


def strip_ansi(s: str) -> str:
    import re
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", s)


# ---------- tampilan ----------

VERDICT_STYLE = {
    "safe":            (C.GREEN,  "✔ AMAN"),
    "suspicious":      (C.YELLOW, "⚠ MENCURIGAKAN"),
    "likely_phishing": (C.MAGENTA,"✘ KEMUNGKINAN BESAR PHISHING"),
    "dangerous":       (C.RED,    "☠ BERBAHAYA"),
}

BOX_WIDTH = 60


def _bar(score: int, width: int = 30) -> str:
    filled = int(round(score / 100 * width))
    empty = width - filled
    if score >= 75:
        col = C.RED
    elif score >= 50:
        col = C.MAGENTA
    elif score >= 20:
        col = C.YELLOW
    else:
        col = C.GREEN
    return color("█" * filled, col) + color("░" * empty, C.DIM)


def _sev_color(sev: int) -> str:
    if sev >= 40: return C.RED
    if sev >= 25: return C.MAGENTA
    if sev >= 15: return C.YELLOW
    return C.CYAN


def _box_line(text: str, width: int = BOX_WIDTH) -> str:
    """
    Bikin baris kotak: │ text padding │
    `text` dihitung tanpa ANSI escape untuk padding.
    """
    vis_len = len(strip_ansi(text))
    # border total = 1 + width + 1
    # baris        = 2 + vis_len + pad + 2
    # supaya sejajar: pad = width - vis_len - 2
    pad = max(width - vis_len - 2, 0)
    return color("│ ", C.DIM) + text + " " * pad + color(" │", C.DIM)


def print_report(result: dict, verbose: bool = False):
    url      = result["url"]
    score    = result["score"]
    verdict  = result["verdict"]
    inds     = result["indicators"]
    notes    = result["notes"]
    steps    = result.get("steps", {})

    col, label = VERDICT_STYLE.get(verdict, (C.RESET, verdict.upper()))

    # header
    print()
    print(color("┌" + "─" * BOX_WIDTH + "┐", C.DIM))
    print(_box_line(color("PhishScan", C.BOLD, C.CYAN) +
                    color(" — analisis URL mencurigakan", C.DIM)))
    print(color("└" + "─" * BOX_WIDTH + "┘", C.DIM))
    print()

    print(f"  URL      : {color(url, C.BOLD)}")
    print(f"  Skor     : {color(str(score).rjust(3), col, C.BOLD)}/100  {_bar(score)}")
    print(f"  Verdict  : {color(label, col, C.BOLD)}")
    print()

    # indikator
    if not inds:
        print("  " + color("Tidak ada indikator mencurigakan.", C.GREEN))
    else:
        print(f"  {color('Indikator', C.BOLD)} ({len(inds)}):")
        for i in inds:
            sev = i["severity"]
            col_sev = _sev_color(sev)
            tag = color(f"[{sev:>3}]", col_sev, C.BOLD)
            code = color(i["code"], C.DIM)
            print(f"    {tag} {i['label']}  {code}")
            if i.get("detail"):
                print(f"           {color(i['detail'], C.DIM)}")
    print()

    # bonus — notes sudah mengandung '+'
    if notes:
        print(f"  {color('Bonus kombinasi:', C.BOLD)}")
        for n in notes:
            print(f"    {color(n, C.YELLOW)}")
        print()

    # verbose: timing
    if verbose and steps:
        print(f"  {color('Timing:', C.BOLD)}")
        for name, s in steps.items():
            ms = s.get("ms", 0)
            err = s.get("error")
            skip = s.get("skipped")
            status = color("ok", C.GREEN)
            if err:
                status = color(f"err: {err}", C.RED)
            elif skip:
                status = color(f"skip: {skip}", C.DIM)
            print(f"    {name:<12} {ms:>8.1f} ms   {status}")
        print()

    # kesimpulan
    if verdict == "safe":
        print("  " + color("Tidak ditemukan indikator phishing.", C.GREEN))
    elif verdict == "suspicious":
        print("  " + color("Ada beberapa tanda mencurigakan. Hati-hati.", C.YELLOW))
    elif verdict == "likely_phishing":
        print("  " + color("Kemungkinan besar phishing. Jangan masukkan data apapun.", C.MAGENTA))
    else:
        print("  " + color("BAHAYA. Jangan buka di browser, jangan masukkan kredensial.",
                            C.RED, C.BOLD))
    print()


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(
        prog="phishscan",
        description="Analisis URL untuk deteksi phishing.",
    )
    ap.add_argument("url", help="URL yang akan diperiksa")
    ap.add_argument("--json",   action="store_true", help="output JSON mentah")
    ap.add_argument("--verbose", "-v", action="store_true", help="tampilkan timing per langkah")
    ap.add_argument("--no-color", action="store_true", help="matikan warna")
    args = ap.parse_args()

    if args.no_color:
        global USE_COLOR
        USE_COLOR = False

    try:
        from pipeline import run
    except ImportError as e:
        print(f"Error: tidak bisa import pipeline ({e})", file=sys.stderr)
        print("Jalankan dari direktori project PhishScan.", file=sys.stderr)
        sys.exit(2)

    result = run(args.url, verbose=(args.verbose and not args.json))

    if args.json:
        out = {k: v for k, v in result.items() if k != "steps"}
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return

    print_report(result, verbose=args.verbose)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nDibatalkan.", file=sys.stderr)
        sys.exit(130)
