"""
Modul 4: DNS Lookup
- A/AAAA pakai stdlib socket (selalu jalan)
- MX/NS pakai dnspython (ditawarkan install kalau belum ada)
- Nameserver publik eksplisit supaya tidak bergantung /etc/resolv.conf
  (penting untuk Termux/Android)

Tes:
    python analyzers/dns_lookup.py google.com
    python analyzers/dns_lookup.py thisdomaindoesnotexist-xyz123.tk
"""
import os
import sys
import json
import socket

_THIS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_THIS)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from deps import ensure  # noqa: E402


TIMEOUT = 5.0
PUBLIC_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]

_dns_resolver = None


def _load_dns():
    """Muat dns.resolver + set nameserver publik. Return modul atau None."""
    global _dns_resolver
    if _dns_resolver is not None:
        return _dns_resolver
    if not ensure("dns", "dnspython", "Cek MX & NS record (lebih akurat)"):
        return None
    import dns.resolver  # type: ignore

    # Gunakan resolver sendiri dengan nameserver publik
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = PUBLIC_NAMESERVERS
    res.timeout = TIMEOUT
    res.lifetime = TIMEOUT

    _dns_resolver = res
    return _dns_resolver


def _resolve_ipv4(host: str):
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        return ips, None
    except socket.gaierror as e:
        return [], str(e)
    except Exception as e:
        return [], f"{type(e).__name__}: {e}"


def _has_record(host: str, rrtype: str):
    resolver = _load_dns()
    if resolver is None:
        return None, None
    try:
        answers = resolver.resolve(host, rrtype)
        return len(list(answers)) > 0, None
    except Exception as e:
        # NoAnswer = domain ada tapi tidak punya record tipe ini (bukan error)
        if type(e).__name__ == "NoAnswer":
            return False, None
        return None, f"{type(e).__name__}: {e}"


def analyze(host: str) -> dict:
    host = host.lower().strip()
    _load_dns()  # trigger prompt install sekali

    result = {
        "host": host,
        "resolved": False,
        "ipv4": [],
        "has_mx": None,
        "has_ns": None,
        "has_dnspython": _dns_resolver is not None,
        "error": None,
        "dns_error": None,
    }

    ips, err = _resolve_ipv4(host)
    if ips:
        result["resolved"] = True
        result["ipv4"] = ips
    else:
        result["error"] = err

    mx, mx_err = _has_record(host, "MX")
    ns, ns_err = _has_record(host, "NS")
    result["has_mx"] = mx
    result["has_ns"] = ns
    result["dns_error"] = mx_err or ns_err

    return result


def indicators(dns_result: dict) -> list:
    out = []
    if not dns_result["resolved"]:
        out.append({
            "code": "UNRESOLVED",
            "label": "Host tidak bisa di-resolve (domain mati / sinkhole)",
            "severity": 30,
            "detail": dns_result.get("error") or "",
        })
    if dns_result.get("has_mx") is False:
        out.append({
            "code": "NO_MX",
            "label": "Domain tidak punya MX record",
            "severity": 5,
            "detail": "",
        })
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python analyzers/dns_lookup.py "<host>"')
        sys.exit(1)
    r = analyze(sys.argv[1])
    print(json.dumps(r, indent=2))
