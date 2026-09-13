"""
Modul 7: HTML Scanner
- Fetch HTML (dengan SSRF guard & size limit)
- Deteksi: form password, iframe hidden, meta refresh lintas domain,
  base64 panjang di atribut, form action ke http://

Tes:
    python analyzers/html_scanner.py "https://example.com"
    python analyzers/html_scanner.py "http://localhost:8080/"
    python analyzers/html_scanner.py "http://paypa1-login.tk/"
"""
import os
import re
import sys
import json
import base64
import urllib.request
import urllib.error
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

_THIS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_THIS)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from analyzers.ssrf_guard import check_host  # noqa: E402


TIMEOUT = 8.0
MAX_BYTES = 500 * 1024        # 500 KB
USER_AGENT = "PhishScan/0.1 (+https://example.org/phishscan)"
MIN_BASE64_LEN = 200          # panjang minimum blob base64 untuk ditandai


# ---------- fetch ----------

def _fetch_html(url: str):
    """
    Return (html_str, error_str, final_url, status).
    """
    parsed = urlparse(url)
    ok, reason, _, ssrf = check_host(parsed.hostname or "")
    if not ok:
        prefix = "SSRF blocked" if ssrf else "unreachable"
        return None, f"{prefix}: {reason}", url, None

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raw = raw[:MAX_BYTES]
            enc = resp.headers.get_content_charset() or "utf-8"
            return raw.decode(enc, errors="replace"), None, resp.geturl(), resp.status
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}", url, e.code
    except urllib.error.URLError as e:
        return None, f"URL error: {e.reason}", url, None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}", url, None


# ---------- parser ----------

class _FormParser(HTMLParser):
    """Deteksi form + input + atribut mencurigakan."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.base_host = urlparse(base_url).hostname or ""

        self.forms = []
        self.iframes = []
        self.metas = []
        self.scripts = []
        self._current_form = None

    # --- form ---
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)

        if tag == "form":
            action = a.get("action", "")
            method = a.get("method", "get").lower()
            self._current_form = {
                "action": action,
                "method": method,
                "password_inputs": 0,
                "email_inputs": 0,
                "text_inputs": 0,
                "hidden_inputs": 0,
                "other_inputs": 0,
            }

        elif tag == "input" and self._current_form is not None:
            typ = (a.get("type") or "text").lower()
            if typ == "password":
                self._current_form["password_inputs"] += 1
            elif typ == "email":
                self._current_form["email_inputs"] += 1
            elif typ == "hidden":
                self._current_form["hidden_inputs"] += 1
            elif typ in ("text", "search", "tel", "url"):
                self._current_form["text_inputs"] += 1
            else:
                self._current_form["other_inputs"] += 1

        elif tag == "iframe":
            self.iframes.append({
                "src": a.get("src", ""),
                "style": (a.get("style") or "").lower(),
                "width": (a.get("width") or "").strip(),
                "height": (a.get("height") or "").strip(),
                "hidden": a.get("hidden") is not None,
            })

        elif tag == "meta":
            http_equiv = (a.get("http-equiv") or "").lower()
            if http_equiv == "refresh":
                self.metas.append({
                    "content": a.get("content", ""),
                })

        elif tag == "script":
            src = a.get("src")
            if src:
                self.scripts.append({"src": src, "inline_b64": 0})
            else:
                # inline script → cek base64 blob nanti via data nanti
                pass

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data):
        # deteksi base64 blob di dalam <script> inline
        if len(data) < MIN_BASE64_LEN:
            return
        s = data.strip()
        # heuristik: panjang, hanya karakter base64, ada padding atau sangat panjang
        if re.fullmatch(r"[A-Za-z0-9+/=\s]+", s) and len(s) >= MIN_BASE64_LEN:
            try:
                base64.b64decode(s[: 4 * ((len(s) // 4))], validate=False)
                self.scripts.append({"src": None, "inline_b64": len(s)})
            except Exception:
                pass


# ---------- analyze ----------

def analyze(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    html, err, final_url, status = _fetch_html(url)

    out = {
        "url": url,
        "final_url": final_url,
        "status": status,
        "fetched": html is not None,
        "error": err,
        "size_bytes": len(html.encode("utf-8", errors="replace")) if html else 0,
        "forms": [],
        "iframes": [],
        "metas": [],
        "scripts": [],
        "has_password_form": False,
        "password_form_to_other_host": False,
        "hidden_iframes": 0,
        "meta_refresh_cross": 0,
        "base64_blobs": 0,
    }

    if not html:
        return out

    p = _FormParser(final_url or url)
    try:
        p.feed(html)
    except Exception as e:
        out["error"] = f"parse: {type(e).__name__}: {e}"
        return out

    base_host = urlparse(final_url or url).hostname or ""

    # enrich form: deteksi action ke host lain & ke http://
    forms = []
    for f in p.forms:
        action_raw = f["action"].strip()
        action_abs = urljoin(final_url or url, action_raw) if action_raw else (final_url or url)
        action_host = urlparse(action_abs).hostname or ""
        action_scheme = urlparse(action_abs).scheme

        forms.append({
            **f,
            "action_abs": action_abs,
            "action_host": action_host,
            "action_scheme": action_scheme,
            "to_other_host": action_host and action_host != base_host,
            "to_http": action_scheme == "http",
        })

    out["forms"] = forms
    out["iframes"] = p.iframes
    out["metas"] = p.metas
    out["scripts"] = p.scripts

    out["has_password_form"] = any(f["password_inputs"] > 0 for f in forms)
    out["password_form_to_other_host"] = any(
        f["password_inputs"] > 0 and f["to_other_host"] for f in forms
    )

    hidden = 0
    for ifr in p.iframes:
        st = ifr["style"]
        if (
            ifr["hidden"]
            or "display:none" in st
            or "visibility:hidden" in st
            or ifr["width"] in ("0", "0px")
            or ifr["height"] in ("0", "0px")
        ):
            hidden += 1
    out["hidden_iframes"] = hidden

    cross = 0
    for m in p.metas:
        content = m["content"].lower()
        # format: "0; url=http://..."
        m2 = re.search(r"url=([^\s;]+)", content)
        if not m2:
            continue
        target = urljoin(final_url or url, m2.group(1))
        th = urlparse(target).hostname or ""
        if th and th != base_host:
            cross += 1
    out["meta_refresh_cross"] = cross

    out["base64_blobs"] = sum(1 for s in p.scripts if s.get("inline_b64", 0) >= MIN_BASE64_LEN)

    return out


# ---------- indikator ----------

def indicators(scan: dict) -> list:
    out = []

    if not scan["fetched"]:
        if scan.get("error", "").startswith("SSRF blocked"):
            return []  # sudah ditangani redirect_tracer
        out.append({
            "code": "HTML_FETCH_FAIL",
            "label": "Gagal mengambil HTML",
            "severity": 5,
            "detail": scan.get("error") or "",
        })
        return out

    if scan["password_form_to_other_host"]:
        out.append({
            "code": "PASSWORD_FORM_OTHER_HOST",
            "label": "Form password mengirim ke domain lain",
            "severity": 60,
            "detail": next(
                (f["action_abs"] for f in scan["forms"] if f["password_inputs"] > 0 and f["to_other_host"]),
                "",
            ),
        })
    elif scan["has_password_form"] and any(f["password_inputs"] > 0 and f["to_http"] for f in scan["forms"]):
        out.append({
            "code": "PASSWORD_FORM_HTTP",
            "label": "Form password dikirim via HTTP (tanpa TLS)",
            "severity": 40,
            "detail": next(
                (f["action_abs"] for f in scan["forms"] if f["password_inputs"] > 0 and f["to_http"]),
                "",
            ),
        })

    if scan["hidden_iframes"] > 0:
        out.append({
            "code": "HIDDEN_IFRAME",
            "label": f'{scan["hidden_iframes"]} iframe tersembunyi',
            "severity": 30,
            "detail": "",
        })

    if scan["meta_refresh_cross"] > 0:
        out.append({
            "code": "META_REFRESH_CROSS",
            "label": "Meta refresh ke domain lain",
            "severity": 25,
            "detail": f'{scan["meta_refresh_cross"]} kejadian',
        })

    if scan["base64_blobs"] > 0:
        out.append({
            "code": "BASE64_BLOB",
            "label": f'{scan["base64_blobs"]} blob base64 besar di script inline',
            "severity": 20,
            "detail": "sering dipakai untuk menyembunyikan payload",
        })

    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python analyzers/html_scanner.py "<url>"')
        sys.exit(1)
    r = analyze(sys.argv[1])
    print(json.dumps(r, indent=2))
