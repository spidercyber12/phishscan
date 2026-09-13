"""
Modul 6: Redirect Tracer + SSRF Guard
- Ikuti redirect manual (max 5 hop)
- Cek SSRF guard di SETIAP hop
- Tidak download body, hanya header
- Limit ukuran header & waktu

Tes:
    python analyzers/redirect_tracer.py https://httpbin.org/redirect/3
    python analyzers/redirect_tracer.py http://localhost:8080/
    python analyzers/redirect_tracer.py http://169.254.169.254/
"""
import os
import sys
import json
import urllib.request
import urllib.error
from urllib.parse import urljoin, urlparse

_THIS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_THIS)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from analyzers.ssrf_guard import check_host  # noqa: E402


MAX_HOPS = 5
TIMEOUT = 6.0
USER_AGENT = "PhishScan/0.1 (+https://example.org/phishscan)"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Handler yang memblokir redirect otomatis → kita follow manual."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _build_opener():
    return urllib.request.build_opener(_NoRedirect())


def _fetch_head(url: str):
    """
    Fetch HEAD (fallback ke GET kalau HEAD tidak didukung).
    Return (status_code, headers_dict, error_str).
    """
    opener = _build_opener()
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            return resp.status, dict(resp.headers), None
    except urllib.error.HTTPError as e:
        # HTTPError tetap punya status & headers (mis. 301 → follow redirect)
        return e.code, dict(e.headers or {}), None
    except urllib.error.URLError as e:
        # Coba GET sebagai fallback (beberapa server tolak HEAD)
        try:
            req2 = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
            with opener.open(req2, timeout=TIMEOUT) as resp:
                return resp.status, dict(resp.headers), None
        except urllib.error.HTTPError as e2:
            return e2.code, dict(e2.headers or {}), None
        except Exception as e2:
            return None, {}, f"{type(e2).__name__}: {e2}"
    except Exception as e:
        return None, {}, f"{type(e).__name__}: {e}"


def analyze(url: str) -> dict:
    """
    Return:
    {
      chain: [ {url, status, location, blocked, reason}, ... ],
      final_url, final_status,
      num_hops, blocked, error
    }
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    chain = []
    current = url
    seen = set()

    for hop in range(MAX_HOPS + 1):
        if current in seen:
            chain.append({
                "url": current,
                "status": None,
                "location": None,
                "blocked": True,
                "reason": "loop redirect terdeteksi",
            })
            return _summarize(chain, blocked=True, error="redirect loop")
        seen.add(current)

        # SSRF guard per hop
        parsed = urlparse(current)
        host = parsed.hostname or ""
        ok, reason, ips, ssrf = check_host(host)
        if not ok:
            chain.append({
                "url": current,
                "status": None,
                "location": None,
                "blocked": ssrf,
                "reason": reason,
                "ips": ips,
            })
            return _summarize(chain, blocked=ssrf, error=reason)

        status, headers, err = _fetch_head(current)
        location = headers.get("Location") or headers.get("location")

        chain.append({
            "url": current,
            "status": status,
            "location": location,
            "blocked": False,
            "reason": err or "",
            "ips": ips,
        })

        if err and status is None:
            return _summarize(chain, blocked=False, error=err)

        # redirect?
        if status in (301, 302, 303, 307, 308) and location:
            nxt = urljoin(current, location)
            if not nxt.startswith(("http://", "https://")):
                return _summarize(chain, blocked=True, error=f"skema tidak didukung: {nxt}")
            current = nxt
            continue

        return _summarize(chain, blocked=False, error=None)

    # max hop tercapai
    return _summarize(chain, blocked=True, error=f"melebihi {MAX_HOPS} redirect")


def _summarize(chain, blocked: bool, error):
    return {
        "chain": chain,
        "final_url": chain[-1]["url"] if chain else None,
        "final_status": chain[-1]["status"] if chain else None,
        "num_hops": max(len(chain) - 1, 0),
        "blocked": blocked,
        "error": error,
    }


def indicators(trace_result: dict) -> list:
    out = []
    if trace_result.get("blocked"):
        out.append({
            "code": "SSRF_BLOCKED",
            "label": "URL menuju jaringan internal/privat (diblokir)",
            "severity": 50,
            "detail": trace_result.get("error") or "",
        })
    n = trace_result.get("num_hops", 0)
    if n >= 3:
        out.append({
            "code": "MANY_REDIRECT",
            "label": f"Redirect berantai ({n} hop)",
            "severity": 20,
            "detail": " → ".join(h["url"] for h in trace_result["chain"]),
        })
    # tidak resolve / tidak reachable sudah ditangani DNS (UNRESOLVED),
    # jadi tidak perlu indikator tambahan di sini.
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python analyzers/redirect_tracer.py "<url>"')
        sys.exit(1)
    r = analyze(sys.argv[1])
    print(json.dumps(r, indent=2))
