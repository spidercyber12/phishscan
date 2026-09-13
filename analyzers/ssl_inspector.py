"""
Modul 5: SSL/TLS Inspector
- Ambil sertifikat TLS pakai stdlib ssl + socket
- Parsing detail pakai cryptography kalau tersedia (opsional)
- Fallback: parsing minimal dari cert (stdlib)

Tes:
    python analyzers/ssl_inspector.py google.com
    python analyzers/ssl_inspector.py expired.badssl.com
    python analyzers/ssl_inspector.py self-signed.badssl.com
    python analyzers/ssl_inspector.py wrong.host.badssl.com
"""
import os
import sys
import ssl
import json
import socket
import tempfile
from datetime import datetime, timezone

_THIS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_THIS)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


TIMEOUT = 6.0


# ---------- fetch cert ----------

def _fetch_pem(host: str, port: int = 443):
    """
    Return (pem_str, error_str).
    ssl.get_server_certificate otomatis ambil cert walau tidak valid.
    """
    try:
        pem = ssl.get_server_certificate((host, port), timeout=TIMEOUT)
        return pem, None
    except socket.timeout:
        return None, "timeout"
    except socket.gaierror as e:
        return None, f"DNS: {e}"
    except ConnectionRefusedError:
        return None, "connection refused"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


# ---------- parsing: cryptography ----------

def _parse_with_crypto(pem: str):
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        return None
    try:
        return x509.load_pem_x509_certificate(pem.encode(), default_backend())
    except Exception:
        return None


# ---------- parsing: stdlib fallback ----------

def _parse_with_stdlib(pem: str):
    decode = getattr(ssl._ssl, "_test_decode_cert", None)
    if decode is None:
        return None

    tmp = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    try:
        tmp.write(pem)
        tmp.close()
        return decode(tmp.name)
    except Exception:
        return None
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


# ---------- util ----------

def _to_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _now():
    return datetime.now(timezone.utc)


def _name_to_str(name) -> str:
    if not name:
        return ""
    parts = []
    for rdn in name:
        for k, v in rdn:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def _host_matches(host: str, sans: list) -> bool:
    """Cocokkan host dengan SAN, dukung wildcard *.example.com (1 level)."""
    host = host.lower()
    for san in sans:
        san = san.lower()
        if san == host:
            return True
        if san.startswith("*."):
            suffix = san[1:]  # ".example.com"
            if host.endswith(suffix) and host.count(".") == san.count("."):
                return True
    return False


# ---------- analyze ----------

def analyze(host: str, port: int = 443) -> dict:
    host = host.lower().strip()
    out = {
        "host": host,
        "port": port,
        "has_cert": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "expired": None,
        "self_signed": None,
        "matches_host": None,
        "san": [],
        "parser": None,
        "error": None,
    }

    pem, err = _fetch_pem(host, port)
    if not pem:
        out["error"] = err
        return out

    out["has_cert"] = True

    # --- jalur 1: cryptography ---
    cert_obj = _parse_with_crypto(pem)
    if cert_obj is not None:
        out["parser"] = "cryptography"
        try:
            out["subject"] = cert_obj.subject.rfc4514_string()
            out["issuer"] = cert_obj.issuer.rfc4514_string()
        except Exception:
            pass

        try:
            # cryptography baru pakai *_utc, lama tidak
            nb = getattr(cert_obj, "not_valid_before_utc", None) or cert_obj.not_valid_before
            na = getattr(cert_obj, "not_valid_after_utc", None) or cert_obj.not_valid_after
            nb = _to_utc(nb)
            na = _to_utc(na)
            out["not_before"] = nb.isoformat() if nb else None
            out["not_after"] = na.isoformat() if na else None
            if na:
                delta = na - _now()
                out["days_remaining"] = delta.days
                out["expired"] = delta.total_seconds() < 0
        except Exception:
            pass

        try:
            from cryptography import x509
            san_ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            out["san"] = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass

        if out["subject"] and out["issuer"]:
            out["self_signed"] = out["subject"] == out["issuer"]
        if out["san"]:
            out["matches_host"] = _host_matches(host, out["san"])

        return out

    # --- jalur 2: stdlib fallback ---
    data = _parse_with_stdlib(pem)
    if data:
        out["parser"] = "stdlib"
        out["subject"] = _name_to_str(data.get("subject"))
        out["issuer"] = _name_to_str(data.get("issuer"))
        out["not_before"] = data.get("notBefore")
        out["not_after"] = data.get("notAfter")

        sans = []
        for typ, val in data.get("subjectAltName", []):
            if typ == "DNS":
                sans.append(val)
        out["san"] = sans

        if out["subject"] and out["issuer"]:
            out["self_signed"] = out["subject"] == out["issuer"]
        if sans:
            out["matches_host"] = _host_matches(host, sans)

        return out

    out["error"] = "tidak bisa parse sertifikat"
    return out


# ---------- indikator ----------

def indicators(ssl_result: dict) -> list:
    out = []
    if not ssl_result.get("has_cert"):
        out.append({
            "code": "NO_TLS_CERT",
            "label": "Tidak bisa mengambil sertifikat TLS",
            "severity": 25,
            "detail": ssl_result.get("error") or "",
        })
        return out

    if ssl_result.get("expired"):
        out.append({
            "code": "CERT_EXPIRED",
            "label": "Sertifikat TLS sudah kadaluarsa",
            "severity": 40,
            "detail": ssl_result.get("not_after") or "",
        })
    elif ssl_result.get("days_remaining") is not None and ssl_result["days_remaining"] < 7:
        out.append({
            "code": "CERT_EXPIRING",
            "label": f'Sertifikat hampir kadaluarsa ({ssl_result["days_remaining"]} hari)',
            "severity": 15,
            "detail": ssl_result.get("not_after") or "",
        })

    if ssl_result.get("self_signed"):
        out.append({
            "code": "SELF_SIGNED",
            "label": "Sertifikat self-signed",
            "severity": 30,
            "detail": ssl_result.get("issuer") or "",
        })

    if ssl_result.get("matches_host") is False:
        out.append({
            "code": "HOST_MISMATCH",
            "label": "Sertifikat tidak cocok dengan hostname",
            "severity": 40,
            "detail": f'host={ssl_result["host"]}',
        })

    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python analyzers/ssl_inspector.py "<host>"')
        sys.exit(1)
    r = analyze(sys.argv[1])
    print(json.dumps(r, indent=2))
