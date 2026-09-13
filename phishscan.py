#!/usr/bin/env python3
"""
PhishScan CLI — analisis URL mencurigakan.

Pemakaian:
    python phishscan.py <url>
    python phishscan.py --help
"""
import os
import sys
import json
import argparse

_THIS = os.path.dirname(os.path.abspath(__file__))
if _THIS not in sys.path:
    sys.path.insert(0, _THIS)


VERSION = "0.1.0"


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


def _supports_color(stream):
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


def strip_ansi(s):
    import re
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", s)


VERDICT_STYLE = {
    "safe":            (C.GREEN,  "\u2714 AMAN"),
    "suspicious":      (C.YELLOW, "\u26a0 MENCURIGAKAN"),
    "likely_phishing": (C.MAGENTA,"\u2718 KEMUNGKINAN BESAR PHISHING"),
    "dangerous":       (C.RED,    "\u2620 BERBAHAYA"),
}

BOX_WIDTH = 60


def _bar(score, width=30):
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
    return color("\u2588" * filled, col) + color("\u2591" * empty, C.DIM)


def _sev_color(sev):
    if sev >= 40: return C.RED
    if sev >= 25: return C.MAGENTA
    if sev >= 15: return C.YELLOW
    return C.CYAN


def _box_line(text, width=BOX_WIDTH):
    vis_len = len(strip_ansi(text))
    pad = max(width - vis_len - 2, 0)
    return color("\u2502 ", C.DIM) + text + " " * pad + color(" \u2502", C.DIM)


def print_report(result, verbose=False):
    url      = result["url"]
    score    = result["score"]
    verdict  = result["verdict"]
    inds     = result["indicators"]
    notes    = result["notes"]
    steps    = result.get("steps", {})

    col, label = VERDICT_STYLE.get(verdict, (C.RESET, verdict.upper()))

    print()
    print(color("\u250c" + "\u2500" * BOX_WIDTH + "\u2510", C.DIM))
    print(_box_line(color("PhishScan", C.BOLD, C.CYAN) +
                    color(" \u2014 analisis URL mencurigakan", C.DIM)))
    print(color("\u2514" + "\u2500" * BOX_WIDTH + "\u2518", C.DIM))
    print()

    print("  URL      : " + color(url, C.BOLD))
    print("  Skor     : " + color(str(score).rjust(3), col, C.BOLD) + "/100  " + _bar(score))
    print("  Verdict  : " + color(label, col, C.BOLD))
    print()

    if not inds:
        print("  " + color("Tidak ada indikator mencurigakan.", C.GREEN))
    else:
        print("  " + color("Indikator", C.BOLD) + " (" + str(len(inds)) + "):")
        for i in inds:
            sev = i["severity"]
            col_sev = _sev_color(sev)
            tag = color("[" + str(sev).rjust(3) + "]", col_sev, C.BOLD)
            code = color(i["code"], C.DIM)
            print("    " + tag + " " + i["label"] + "  " + code)
            if i.get("detail"):
                print("           " + color(i["detail"], C.DIM))
    print()

    if notes:
        print("  " + color("Bonus kombinasi:", C.BOLD))
        for n in notes:
            print("    " + color(n, C.YELLOW))
        print()

    if verbose and steps:
        print("  " + color("Timing:", C.BOLD))
        for name, s in steps.items():
            ms = s.get("ms", 0)
            err = s.get("error")
            skip = s.get("skipped")
            status = color("ok", C.GREEN)
            if err:
                status = color("err: " + str(err), C.RED)
            elif skip:
                status = color("skip: " + str(skip), C.DIM)
            print("    " + name.ljust(12) + " " + str(round(ms, 1)).rjust(8) + " ms   " + status)
        print()

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


def _build_epilog():
    SEP = "\u2500" * 65
    lines = [
        SEP,
        "CONTOH PEMAKAIAN",
        SEP,
        "",
        "  Analisis satu URL:",
        '      python phishscan.py "http://suspicious-site.tk/login"',
        "",
        "  Tampilkan timing per modul (untuk debug/performa):",
        '      python phishscan.py --verbose "https://example.com"',
        "",
        "  Output JSON (untuk otomasi / dipipe ke tool lain):",
        '      python phishscan.py --json "https://example.com"',
        "",
        "  Matikan warna (cocok untuk log atau pipe):",
        '      python phishscan.py --no-color "https://example.com"',
        "",
        "  Auto-install dependency opsional tanpa prompt:",
        '      PHISHSCAN_YES=1 python phishscan.py "https://example.com"',
        "",
        "  Izinkan scan IP privat (hati-hati, bisa bahaya):",
        '      PHISHSCAN_ALLOW_PRIVATE=1 python phishscan.py "http://192.168.1.1"',
        "",
        SEP,
        "SKOR & VERDICT",
        SEP,
        "",
        "  0-19    AMAN                        tidak ada indikator",
        "  20-49   MENCURIGAKAN                ada beberapa tanda",
        "  50-74   KEMUNGKINAN BESAR PHISHING  jangan masukkan data",
        "  75-100  BERBAHAYA                   jangan buka sama sekali",
        "",
        SEP,
        "ENVIRONMENT VARIABLE",
        SEP,
        "",
        "  NO_COLOR=1                Matikan warna output",
        "  PHISHSCAN_YES=1           Auto-install dependency opsional",
        "  PHISHSCAN_ALLOW_PRIVATE=1 Izinkan scan IP privat (berisiko!)",
        "",
        SEP,
        "LINK",
        SEP,
        "",
        "  Repo    : https://github.com/spidercyber12/phishscan",
        "  Issues  : https://github.com/spidercyber12/phishscan/issues",
        "  Lisensi : MIT",
    ]
    return "\n".join(lines)


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="phishscan",
        description=(
            "PhishScan \u2014 analisis URL untuk mendeteksi phishing.\n"
            "Tool ini memeriksa struktur URL, DNS, sertifikat TLS, rantai redirect,\n"
            "dan konten HTML. Tidak butuh API key. Berjalan dengan stdlib Python."
        ),
        epilog=_build_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="URL yang akan diperiksa. Boleh dengan atau tanpa skema.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output JSON mentah (tanpa warna) \u2014 cocok untuk script.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Tampilkan timing setiap modul (parse, DNS, SSL, redirect, HTML).",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Matikan warna ANSI. Sama seperti set env NO_COLOR=1.",
    )
    parser.add_argument(
        "-V", "--version", action="version",
        version="PhishScan " + VERSION,
        help="Tampilkan versi dan keluar.",
    )
    return parser


def main(argv=None):
    global USE_COLOR
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        USE_COLOR = False

    if not args.url:
        print(color("\n  Tidak ada URL yang diberikan.\n", C.YELLOW))
        print(color("  Coba jalankan salah satu contoh ini:\n", C.DIM))
        print('    python phishscan.py "https://example.com"')
        print('    python phishscan.py "http://suspicious-site.tk/login"')
        print("    python phishscan.py --help")
        print()
        parser.print_help()
        sys.exit(0)

    try:
        from pipeline import run
    except ImportError as e:
        print("Error: tidak bisa import pipeline (" + str(e) + ")", file=sys.stderr)
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
