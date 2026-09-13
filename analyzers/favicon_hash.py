"""
Modul 9: Favicon Hash (stdlib)
Deteksi situs tiruan dari favicon yang sama dengan brand populer.

Cara kerja:
1. Ambil /favicon.ico dari target
2. Hitung hash (mmh3-style base64 SHA256)
3. Bandingkan dengan hash brand terkenal di BRAND_FAVICONS

Tes:
    python analyzers/favicon_hash.py https://github.com
    python analyzers/favicon_hash.py https://google.com
"""
import os
import sys
import json
import base64
import hashlib
import urllib.request
import urllib.error
from urllib.parse import urljoin, urlparse

_THIS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_THIS)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.ssrf_guard import check_host


TIMEOUT = 8.0
MAX_BYTES = 128 * 1024
USER_AGENT = "PhishScan/0.1 (+https://github.com/spidercyber12/phishscan)"

# ---------------------------------------------------------------
# Hash favicon brand populer.
# Format: { "domain_resmi": "<hash>" }
# Kosong dulu. Akan diisi dengan hash yang kita hitung manual dari
# brand populer. Kalau hash target cocok dengan salah satu di sini
# TAPI domain berbeda -> indikasi phishing.
# ---------------------------------------------------------------
BRAND_FAVICONS = {
    "paypal.com":     "FpDE4ghpw3Y7f8ER4vlANbCn7oMDEd1oCskUIdqtNmc=",
    "facebook.com":   "iST0TXZCajQLEFy9xbk2eMa3cuhHs5PyVo2UhHwNjYA=",
    "instagram.com":  "0xzkeMlykTAwOjU3pDkGvIFk3r9VRvetTRvu2dmyxjA=",
    "x.com":          "zEk5r10WhV8r6oMi2/M0YevGv9CS+j4ikdh9PYPr2O0=",
    "shopee.co.id":   "r9Y7GZ6rO865fhUL5+/PH0NzgmUkTRVtDMQGVucGgyU=",
    "tokopedia.com":  "UWdg4AS/KCFjeKvndlCkvNbUOF6GhoMhDsL+sOHKO9g=",
    "bca.co.id":      "BfAZaDhn505KFa5hhFyz2uCJNJAvD3jIubIKhONz1TU=",
}


def _hash_favicon(data):
    """Hash favicon pakai SHA256 -> base64. Deterministik."""
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _fetch_favicon(url):
    """
    Fetch favicon. Return (data_bytes, final_url, error_str).
    Coba beberapa kandidat URL favicon.
    """
    parsed = urlparse(url)
    base = parsed.scheme + "://" + parsed.netloc

    candidates = [
        urljoin(base + "/", "/favicon.ico"),
        urljoin(url, "favicon.ico"),
    ]

    for fav_url in candidates:
        host = urlparse(fav_url).hostname or ""
        ok, reason, _, ssrf = check_host(host)
        if not ok:
            return None, fav_url, "SSRF blocked: " + reason

        req = urllib.request.Request(fav_url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                data = resp.read(MAX_BYTES)
                if data and len(data) >= 4:
                    return data, fav_url, None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            return None, fav_url, "HTTP " + str(e.code)
        except Exception as e:
            return None, fav_url, type(e).__name__ + ": " + str(e)

    return None, candidates[0], "favicon tidak ditemukan"


def analyze(url):
    """
    Return dict:
        {
          url, favicon_url, fetched, size, hash, matched_brand, error
        }
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    out = {
        "url": url,
        "favicon_url": None,
        "fetched": False,
        "size": 0,
        "hash": None,
        "matched_brand": None,
        "error": None,
    }

    data, fav_url, err = _fetch_favicon(url)
    out["favicon_url"] = fav_url

    if not data:
        out["error"] = err
        return out

    out["fetched"] = True
    out["size"] = len(data)
    out["hash"] = _hash_favicon(data)

    # Cek apakah cocok dengan brand populer
    target_host = urlparse(url).hostname or ""
    for brand_domain, brand_hash in BRAND_FAVICONS.items():
        if brand_hash == out["hash"]:
            if target_host.lower() != brand_domain.lower():
                out["matched_brand"] = brand_domain
            break

    return out


def indicators(fav):
    out = []
    if fav.get("matched_brand"):
        out.append({
            "code": "FAVICON_MISMATCH",
            "label": "Favicon sama dengan brand " + fav["matched_brand"] + " (domain berbeda)",
            "severity": 60,
            "detail": "hash " + (fav.get("hash") or "")[:16] + "...",
        })
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python analyzers/favicon_hash.py "<url>"')
        sys.exit(1)
    print(json.dumps(analyze(sys.argv[1]), indent=2))
