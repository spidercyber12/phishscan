"""
pipeline.py — jalankan seluruh modul secara berurutan.

Alur:
    1. url_parser         → pecah URL
    2. heuristics         → cek pola string
    3. dns_lookup         → A/AAAA, MX, NS
    4. ssl_inspector      → sertifikat TLS
    5. redirect_tracer    → ikuti redirect + SSRF guard
    6. html_scanner       → deteksi form/iframe/meta (dengan guard)
    7. scoring engine     → gabung semua jadi skor + verdict

Pemakaian:
    from pipeline import run
    result = run("http://suspicious.tk/login")
"""
import os
import sys
import time

_THIS = os.path.dirname(os.path.abspath(__file__))
if _THIS not in sys.path:
    sys.path.insert(0, _THIS)

from analyzers.url_parser      import analyze as parse_url
from analyzers.heuristics      import analyze as run_heuristics
from analyzers.dns_lookup      import analyze as dns_analyze,   indicators as dns_ind
from analyzers.ssl_inspector   import analyze as ssl_analyze,   indicators as ssl_ind
from analyzers.redirect_tracer import analyze as redirect_analyze, indicators as redir_ind
from analyzers.html_scanner    import analyze as html_analyze,  indicators as html_ind
from scoring.engine            import score_indicators


def _timed(fn, *a, **kw):
    t0 = time.perf_counter()
    try:
        result = fn(*a, **kw)
        err = None
    except Exception as e:
        result = None
        err = f"{type(e).__name__}: {e}"
    dt = (time.perf_counter() - t0) * 1000
    return result, err, dt


def run(url: str, verbose: bool = False) -> dict:
    """
    Jalankan seluruh pipeline. Return dict lengkap dengan timing.
    """
    log = (lambda *a: print(*a, file=sys.stderr)) if verbose else (lambda *a: None)

    steps = {}

    # --- 1. parse URL ---
    log("[1/6] parse URL ...")
    parsed, err, ms = _timed(parse_url, url)
    steps["url_parser"] = {"ms": ms, "error": err, "data": parsed}
    if err or not parsed:
        return _finalize(url, steps, [], err or "gagal parse URL")

    host = parsed["host"]

    # --- 2. heuristics ---
    log("[2/6] heuristics ...")
    heur, err, ms = _timed(run_heuristics, parsed)
    steps["heuristics"] = {"ms": ms, "error": err, "data": heur}
    indicators = list(heur["indicators"]) if heur else []

    # --- 3. DNS ---
    log(f"[3/6] DNS lookup {host} ...")
    dns, err, ms = _timed(dns_analyze, host)
    steps["dns"] = {"ms": ms, "error": err, "data": dns}
    if dns:
        indicators += dns_ind(dns)

    # --- 4. SSL ---
    log(f"[4/6] SSL inspect {host} ...")
    if parsed["scheme"] == "https" or not parsed["flags"]["is_ip"]:
        ssl_res, err, ms = _timed(ssl_analyze, host)
        steps["ssl"] = {"ms": ms, "error": err, "data": ssl_res}
        if ssl_res:
            indicators += ssl_ind(ssl_res)
    else:
        steps["ssl"] = {"ms": 0, "error": None, "data": None, "skipped": "bukan https"}

    # --- 5. redirect + SSRF ---
    log("[5/6] redirect trace ...")
    redir, err, ms = _timed(redirect_analyze, url)
    steps["redirect"] = {"ms": ms, "error": err, "data": redir}
    if redir:
        indicators += redir_ind(redir)

    # --- 6. HTML scan ---
    log("[6/6] HTML scan ...")
    target_url = redir.get("final_url") if redir else url
    if redir and redir.get("blocked"):
        steps["html"] = {"ms": 0, "error": None, "data": None, "skipped": "SSRF blocked"}
    else:
        html, err, ms = _timed(html_analyze, target_url)
        steps["html"] = {"ms": ms, "error": err, "data": html}
        if html:
            indicators += html_ind(html)

    return _finalize(url, steps, indicators, None)


def _finalize(url: str, steps: dict, indicators: list, fatal_error) -> dict:
    scored = score_indicators(indicators)

    return {
        "url": url,
        "score": scored["score"],
        "verdict": scored["verdict"],
        "indicators": scored["indicators"],
        "notes": scored["notes"],
        "steps": steps,
        "fatal_error": fatal_error,
    }


if __name__ == "__main__":
    import json
    if len(sys.argv) < 2:
        print('Usage: python pipeline.py "<url>"')
        sys.exit(1)
    r = run(sys.argv[1], verbose=True)
    # steps.data bisa sangat besar; sembunyikan saat print ringkas
    r_print = {k: v for k, v in r.items() if k != "steps"}
    print(json.dumps(r_print, indent=2))
