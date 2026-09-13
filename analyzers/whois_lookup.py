"""
Modul 8: WHOIS Lookup (stdlib socket port 43)
Cek umur domain - domain baru (<30 hari) = sinyal kuat phishing

Tes:
    python analyzers/whois_lookup.py paypal.com
    python analyzers/whois_lookup.py google.com
"""
import os
import re
import sys
import json
import socket
from datetime import datetime, timezone

_THIS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_THIS)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


TIMEOUT = 8.0

TLD_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "id": "whois.id",
    "co.id": "whois.id",
    "or.id": "whois.id",
    "my.id": "whois.id",
    "web.id": "whois.id",
    "xyz": "whois.nic.xyz",
    "info": "whois.afilias.net",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "me": "whois.nic.me",
    "tv": "whois.nic.tv",
    "biz": "whois.nic.biz",
    "ru": "whois.tcinet.ru",
    "cn": "whois.cnnic.cn",
    "jp": "whois.jprs.jp",
    "kr": "whois.kr",
    "de": "whois.denic.de",
    "uk": "whois.nic.uk",
    "co.uk": "whois.nic.uk",
    "fr": "whois.nic.fr",
    "it": "whois.nic.it",
    "au": "whois.auda.org.au",
    "com.au": "whois.auda.org.au",
    "sg": "whois.sgnic.sg",
    "com.sg": "whois.sgnic.sg",
    "my": "whois.mynic.my",
    "com.my": "whois.mynic.my",
    "in": "whois.registry.in",
    "co.in": "whois.registry.in",
    "br": "whois.registro.br",
    "com.br": "whois.registro.br",
}

IANA_SERVER = "whois.iana.org"


def _query(server, query):
    try:
        with socket.create_connection((server, 43), timeout=TIMEOUT) as s:
            s.sendall((query + "\r\n").encode("ascii", errors="ignore"))
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if sum(len(c) for c in chunks) > 512 * 1024:
                    break
            return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception as e:
        return "__ERROR__: " + type(e).__name__ + ": " + str(e)


def _parse_date(s):
    if not s:
        return None
    s = s.strip().split("\n")[0].strip()
    fmts = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d.%m.%Y",
        "%Y.%m.%d",
    ]
    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    m = re.search(r"(\d{4})[-.](\d{2})[-.](\d{2})", s)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
        except ValueError:
            pass
    m = re.search(r"(\d{1,2})-([A-Za-z]{3})-(\d{4})", s)
    if m:
        try:
            return datetime.strptime(m.group(0), "%d-%b-%Y").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def _extract(text, keys):
    for key in keys:
        pat = r"^" + re.escape(key) + r"\s*:\s*(.+)$"
        m = re.search(pat, text, re.MULTILINE | re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None


def _find_server(domain):
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        last2 = ".".join(parts[-2:])
        if last2 in TLD_SERVERS:
            return TLD_SERVERS[last2]
    if parts and parts[-1] in TLD_SERVERS:
        return TLD_SERVERS[parts[-1]]
    resp = _query(IANA_SERVER, domain)
    if resp.startswith("__ERROR__"):
        return None
    m = re.search(r"^refer:\s*(\S+)", resp, re.MULTILINE | re.IGNORECASE)
    return m.group(1).strip() if m else None


def _extract_registrar_server(text):
    """Cari baris 'Registrar WHOIS Server: xxx' dari respons Verisign."""
    m = re.search(r"^\s*Registrar WHOIS Server:\s*(\S+)", text,
                  re.MULTILINE | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"^\s*Whois Server:\s*(\S+)", text,
                  re.MULTILINE | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


def analyze(domain, debug=False):
    domain = domain.lower().strip()
    out = {
        "domain": domain,
        "queried": False,
        "whois_server": None,
        "registrar": None,
        "creation_date": None,
        "expiry_date": None,
        "age_days": None,
        "error": None,
    }

    if not domain or "." not in domain:
        out["error"] = "domain tidak valid"
        return out

    # Step 1: cari registry WHOIS
    server = _find_server(domain)
    if not server:
        out["error"] = "tidak bisa menemukan WHOIS server"
        return out

    out["whois_server"] = server
    resp = _query(server, domain)

    if resp.startswith("__ERROR__"):
        out["error"] = resp.replace("__ERROR__: ", "")
        return out

    if debug:
        print("=== RESPONS 1 dari " + server + " ===", file=sys.stderr)
        print(resp[:2000], file=sys.stderr)
        print("=== END ===", file=sys.stderr)

    # Coba parse dari respons pertama
    cd_str = _extract(resp, [
        "Creation Date", "Created On", "created", "Domain Registration Date",
        "Registered on", "Registration Date", "created date",
    ])
    ed_str = _extract(resp, [
        "Registry Expiry Date", "Registrar Registration Expiration Date",
        "Expiration Date", "Expiry Date", "paid-till",
    ])
    registrar = _extract(resp, ["Registrar", "Sponsoring Registrar"])

    cd = _parse_date(cd_str)
    ed = _parse_date(ed_str)

    # Step 2: kalau belum dapat creation date, query WHOIS registrar
    if cd is None:
        reg_server = _extract_registrar_server(resp)
        if reg_server and reg_server.lower() not in (server.lower(), ""):
            # sebagian registrar butuh prefix "domain " atau "="
            for q in (domain, "domain " + domain, "=" + domain):
                resp2 = _query(reg_server, q)
                if resp2.startswith("__ERROR__"):
                    continue
                if debug:
                    print("=== RESPONS 2 dari " + reg_server + " ===", file=sys.stderr)
                    print(resp2[:2000], file=sys.stderr)
                    print("=== END ===", file=sys.stderr)

                cd_str = _extract(resp2, [
                    "Creation Date", "Created On", "created", "Domain Registration Date",
                    "Registered on", "Registration Date", "created date",
                ])
                ed_str = _extract(resp2, [
                    "Registry Expiry Date", "Registrar Registration Expiration Date",
                    "Expiration Date", "Expiry Date", "paid-till",
                ])
                registrar2 = _extract(resp2, ["Registrar", "Sponsoring Registrar"])
                if registrar2:
                    registrar = registrar2

                cd = _parse_date(cd_str)
                ed = _parse_date(ed_str)
                if cd or ed:
                    break

    out["queried"] = True
    out["registrar"] = registrar

    if cd:
        out["creation_date"] = cd.isoformat()
        out["age_days"] = (datetime.now(timezone.utc) - cd).days
    if ed:
        out["expiry_date"] = ed.isoformat()

    if not cd and not ed:
        out["error"] = "creation/expiry date tidak ditemukan di respons WHOIS"

    return out


def indicators(w):
    out = []
    age = w.get("age_days")
    if age is None:
        return out
    if age < 7:
        out.append({
            "code": "DOMAIN_VERY_NEW",
            "label": "Domain sangat baru (" + str(age) + " hari)",
            "severity": 50,
            "detail": w.get("creation_date") or "",
        })
    elif age < 30:
        out.append({
            "code": "DOMAIN_NEW",
            "label": "Domain baru (" + str(age) + " hari)",
            "severity": 35,
            "detail": w.get("creation_date") or "",
        })
    elif age < 90:
        out.append({
            "code": "DOMAIN_RECENT",
            "label": "Domain relatif baru (" + str(age) + " hari)",
            "severity": 15,
            "detail": w.get("creation_date") or "",
        })
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python analyzers/whois_lookup.py "<domain>"')
        sys.exit(1)
    print(json.dumps(analyze(sys.argv[1]), indent=2))
