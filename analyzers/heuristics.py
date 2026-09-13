"""
Modul 2: Heuristics (stdlib only)
Input : dict hasil url_parser.analyze()
Output: dict { "indicators": [...], "raw_score": int }

Tes:
    python analyzers/heuristics.py "http://paypa1-login.tk/verify"
"""
import sys
import json
import re

try:
    from analyzers.url_parser import analyze as parse_url
except ImportError:
    from url_parser import analyze as parse_url


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure",
    "account", "update", "confirm", "banking", "wallet",
    "password", "recover", "unlock", "suspend", "billing",
    "invoice", "payment", "reset",
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "work", "click", "link",
    "country", "stream", "download", "loan", "review",
    "zip", "mov",
}

POPULAR_DOMAINS = [
    "google.com", "facebook.com", "instagram.com", "whatsapp.com",
    "youtube.com", "twitter.com", "tiktok.com",
    "paypal.com", "apple.com", "microsoft.com", "amazon.com",
    "netflix.com", "linkedin.com", "github.com", "dropbox.com",
    "binance.com", "coinbase.com", "metamask.io",
    "bca.co.id", "bni.co.id", "bri.co.id", "mandiri.co.id",
    "dana.id", "ovo.id", "gopay.co.id", "shopee.co.id", "tokopedia.com",
]

DANGEROUS_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".apk", ".msi", ".vbs", ".js", ".jar",
    ".zip", ".rar", ".7z", ".iso", ".img",
}

NONSTANDARD_PORTS = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5900, 8080, 8443}

LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "b", "7": "t", "8": "b", "9": "g",
})


# ---------- helper ----------

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def _deleet(s: str) -> str:
    return s.translate(LEET_MAP)


def _indicator(code: str, label: str, severity: int, detail: str = "") -> dict:
    return {"code": code, "label": label, "severity": severity, "detail": detail}


# ---------- rules ----------

def _check_basic_flags(parsed: dict) -> list:
    out = []
    f = parsed["flags"]

    if f["is_ip"]:
        out.append(_indicator("IP_HOST", "Host berupa alamat IP", 40, parsed["host"]))
    if f["is_shortener"]:
        out.append(_indicator("SHORTENER", "URL shortener (menyembunyikan tujuan)", 15, parsed["host"]))
    if f["has_at"]:
        out.append(_indicator("AT_IN_URL", "URL mengandung '@' (teknik menipu)", 30))
    if f["num_subdomains"] >= 3:
        out.append(_indicator("MANY_SUBDOMAIN", f'{f["num_subdomains"]} subdomain', 20, parsed["subdomain"]))
    if f["url_length"] > 75:
        out.append(_indicator("LONG_URL", "URL sangat panjang", 15, f'{f["url_length"]} karakter'))
    if not f["is_https"]:
        out.append(_indicator("HTTP_NO_TLS", "Tidak pakai HTTPS", 10))
    if f["has_port"] and parsed["port"] not in (80, 443):
        out.append(_indicator("NONSTANDARD_PORT", f'Port tidak lazim: {parsed["port"]}', 20, str(parsed["port"])))

    return out


def _check_keywords(parsed: dict) -> list:
    hay = (parsed["path"] + "?" + parsed["query"]).lower()
    hits = [w for w in SUSPICIOUS_KEYWORDS if w in hay]
    if hits:
        return [_indicator(
            "SUSPICIOUS_KEYWORD",
            "Kata kunci mencurigakan di URL",
            15,
            ", ".join(sorted(set(hits))),
        )]
    return []


def _check_tld(parsed: dict) -> list:
    if parsed["suffix"] in SUSPICIOUS_TLDS:
        return [_indicator(
            "SUSPICIOUS_TLD",
            f'TLD ".{parsed["suffix"]}" sering dipakai phishing',
            25,
            parsed["suffix"],
        )]
    return []


def _extract_tokens(parsed: dict) -> list:
    """
    Kumpulkan token kandidat dari domain + subdomain.
    - Tidak split di angka (biar '1' bisa dibanding sebagai 'l')
    - Hanya split di '-' dan '_'
    - Minimal 4 karakter
    """
    reg = parsed["registered_domain"].lower()
    sub = parsed["subdomain"].lower()
    name = reg.split(".")[0] if "." in reg else reg

    raw = name + " " + sub.replace(".", " ")
    tokens = [t for t in re.split(r"[-_\s]+", raw) if len(t) >= 4]

    # tambah nama domain utuh juga kalau belum ada
    if len(name) >= 4 and name not in tokens:
        tokens.insert(0, name)

    # dedup, jaga urutan
    seen = set()
    uniq = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def _check_typosquat(parsed: dict) -> list:
    reg = parsed["registered_domain"].lower()
    if not reg:
        return []

    tokens = _extract_tokens(parsed)
    if not tokens:
        return []

    for tok in tokens:
        tok_norm = _deleet(tok)

        for pop in POPULAR_DOMAINS:
            pop_name = pop.split(".")[0]
            if len(pop_name) < 4:
                continue

            # exact match dengan brand populer → cek apakah di domain resmi
            if tok == pop_name:
                if reg != pop:
                    return [_indicator(
                        "BRAND_MISUSE",
                        f'Brand "{pop}" muncul di luar domain resminya',
                        50,
                        f'{reg} memakai "{tok}"',
                    )]
                continue

            # exact setelah de-leet → typosquat (mis. faceb00k → facebook)
            if tok_norm == pop_name:
                return [_indicator(
                    "TYPOSQUAT",
                    f'Mirip "{pop}"',
                    45,
                    f'{tok} → {tok_norm}',
                )]

            # jarak Levenshtein pada raw dan de-leet, ambil yang terkecil
            d = min(
                _levenshtein(tok, pop_name),
                _levenshtein(tok_norm, pop_name),
            )
            max_d = 1 if len(pop_name) <= 5 else 2
            if 0 < d <= max_d:
                return [_indicator(
                    "TYPOSQUAT",
                    f'Mirip "{pop}"',
                    45,
                    f'{tok} vs {pop_name} (jarak {d})',
                )]

    return []


def _check_punycode(parsed: dict) -> list:
    if "xn--" in parsed["host"]:
        return [_indicator(
            "PUNYCODE",
            "Host IDN (punycode) — bisa jadi homograph",
            35,
            parsed["host"],
        )]
    return []


def _check_dangerous_ext(parsed: dict) -> list:
    path = parsed["path"].lower()
    for ext in DANGEROUS_EXT:
        if path.endswith(ext):
            return [_indicator(
                "DANGEROUS_FILE",
                f'URL mengarah ke file "{ext}"',
                35,
                parsed["path"],
            )]
    return []


# ---------- entry ----------

def analyze(parsed: dict) -> dict:
    indicators = []
    indicators += _check_basic_flags(parsed)
    indicators += _check_keywords(parsed)
    indicators += _check_tld(parsed)
    indicators += _check_typosquat(parsed)
    indicators += _check_punycode(parsed)
    indicators += _check_dangerous_ext(parsed)

    raw = sum(i["severity"] for i in indicators)
    return {"indicators": indicators, "raw_score": raw}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python analyzers/heuristics.py "<url>"')
        sys.exit(1)
    p = parse_url(sys.argv[1])
    h = analyze(p)
    print(json.dumps({"parsed": p, "heuristics": h}, indent=2))
