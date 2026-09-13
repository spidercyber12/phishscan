"""
Modul 3: Scoring Engine
Input : list indikator mentah dari modul apapun
Output: dict { score, verdict, indicators, notes }

Tes:
    python scoring/engine.py "http://paypa1-login.tk/verify"
"""
import os
import sys
import json

_THIS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_THIS)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


VERDICT_THRESHOLDS = [
    (75, "dangerous"),
    (50, "likely_phishing"),
    (20, "suspicious"),
    (0,  "safe"),
]

CAP_PER_CODE = {
    "SUSPICIOUS_KEYWORD": 25,
    "MANY_SUBDOMAIN":     20,
    "LONG_URL":           15,
    "NO_MX":              5,
    "HTTP_NO_TLS":        10,
    "CERT_EXPIRING":      15,
    "FETCH_ERROR":        10,
    "HTML_FETCH_FAIL":    5,
    "DOMAIN_RECENT":      15,
}

COMBINATION_BONUS = [
    ({"TYPOSQUAT", "SUSPICIOUS_KEYWORD"},     15, "typosquat + kata kunci login"),
    ({"BRAND_MISUSE", "SUSPICIOUS_KEYWORD"},  15, "brand di luar domain resmi + kata kunci login"),
    ({"IP_HOST", "DANGEROUS_FILE"},           10, "IP langsung + file berbahaya"),
    ({"SUSPICIOUS_TLD", "TYPOSQUAT"},         10, "TLD murah + typosquat"),
    ({"PASSWORD_FORM_OTHER_HOST", "SUSPICIOUS_TLD"}, 15, "form password bocor + TLD murah"),
    ({"CERT_EXPIRED", "TYPOSQUAT"},           10, "sert kadaluarsa + typosquat"),
    ({"DOMAIN_NEW", "TYPOSQUAT"},             15, "domain baru + typosquat"),
    ({"DOMAIN_VERY_NEW", "TYPOSQUAT"},        20, "domain sangat baru + typosquat"),
    ({"FAVICON_MISMATCH", "SUSPICIOUS_KEYWORD"}, 15, "favicon brand dipalsukan + kata kunci login"),
]


# Kalau ada kode "penyebab", kode "akibat" ini dibuang
SUPPRESS_IF = {
    "UNRESOLVED": {"HTML_FETCH_FAIL", "NO_TLS_CERT"},
}


def _apply_suppression(indicators: list) -> list:
    codes = {i["code"] for i in indicators}
    to_remove = set()
    for cause, effects in SUPPRESS_IF.items():
        if cause in codes:
            to_remove |= effects
    if not to_remove:
        return indicators
    return [i for i in indicators if i["code"] not in to_remove]


def _dedup_and_cap(indicators: list) -> list:
    indicators = _apply_suppression(indicators)
    best = {}
    for ind in indicators:
        code = ind["code"]
        if code not in best or ind["severity"] > best[code]["severity"]:
            best[code] = ind

    result = []
    for code, ind in best.items():
        sev = ind["severity"]
        cap = CAP_PER_CODE.get(code)
        if cap is not None:
            sev = min(sev, cap)
        result.append({**ind, "severity": sev})

    result.sort(key=lambda x: x["severity"], reverse=True)
    return result


def _combination_bonus(indicators: list):
    codes = {i["code"] for i in indicators}
    total = 0
    notes = []
    for need, bonus, desc in COMBINATION_BONUS:
        if need.issubset(codes):
            total += bonus
            notes.append(f"+{bonus} ({desc})")
    return total, notes


def _verdict(score: int) -> str:
    for threshold, name in VERDICT_THRESHOLDS:
        if score >= threshold:
            return name
    return "safe"


def score_indicators(indicators: list) -> dict:
    """Entry point utama — terima list indikator mentah dari mana saja."""
    deduped = _dedup_and_cap(indicators)
    base = sum(i["severity"] for i in deduped)
    bonus, notes = _combination_bonus(deduped)
    score = min(base + bonus, 100)
    return {
        "score": score,
        "verdict": _verdict(score),
        "indicators": deduped,
        "notes": notes,
    }


# --- kompatibilitas dengan pemakaian lama ---
def analyze(heuristics_result: dict) -> dict:
    return score_indicators(heuristics_result.get("indicators", []))


def run(url: str) -> dict:
    """Helper lengkap standalone."""
    from analyzers.url_parser import analyze as parse_url
    from analyzers.heuristics import analyze as run_heuristics

    parsed = parse_url(url)
    heur = run_heuristics(parsed)
    scored = score_indicators(heur["indicators"])
    return {"url": url, "parsed": parsed, "heuristics": heur, "result": scored}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python scoring/engine.py "<url>"')
        sys.exit(1)
    print(json.dumps(run(sys.argv[1]), indent=2))
