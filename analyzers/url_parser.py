"""
Modul 1: URL Parser (stdlib only)
Input : string URL
Output: dict berisi komponen URL + flag dasar

Tes:
    python analyzers/url_parser.py "http://paypa1-login.tk/verify?id=1"
"""
import sys
import json
import ipaddress
from urllib.parse import urlparse

# TLD 2-level yang umum
MULTI_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.id", "or.id", "ac.id", "go.id", "web.id", "my.id", "sch.id",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.in", "net.in", "org.in", "gov.in",
    "com.sg", "com.my", "com.hk", "com.tw", "com.cn",
    "co.kr", "or.kr", "go.kr",
    "com.tr", "com.mx", "com.ar",
}

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _split_host(host: str) -> dict:
    """
    Pisah host jadi subdomain / domain / suffix.
    - IP  : return early, tidak di-split
    - Multi-level suffix (co.id, co.uk, ...) di-handle
    """
    # IP → tidak ada subdomain/domain/suffix
    if _is_ip(host):
        return {"subdomain": "", "domain": "", "suffix": ""}

    parts = host.split(".")
    if len(parts) < 2:
        return {"subdomain": "", "domain": host, "suffix": ""}

    last2 = ".".join(parts[-2:])
    if last2 in MULTI_LEVEL_SUFFIXES and len(parts) >= 3:
        # contoh: login.bank.co.id
        #   suffix   = co.id
        #   domain   = bank
        #   subdomain= login
        suffix = last2
        domain = parts[-3]
        subdomain = ".".join(parts[:-3])
    else:
        # contoh: a.b.example.com
        #   suffix   = com
        #   domain   = example
        #   subdomain= a.b
        suffix = parts[-1]
        domain = parts[-2]
        subdomain = ".".join(parts[:-2])

    return {
        "subdomain": subdomain,
        "domain": domain,
        "suffix": suffix,
    }


def analyze(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    p = urlparse(url)
    host = (p.hostname or "").lower()
    is_ip = _is_ip(host)

    split = _split_host(host)

    if is_ip:
        # IP → registered_domain = IP itu sendiri, tidak ada suffix
        registered = host
        num_subdomains = 0
    else:
        registered = (
            f"{split['domain']}.{split['suffix']}"
            if split["domain"] and split["suffix"] else ""
        )
        num_subdomains = len([s for s in split["subdomain"].split(".") if s])

    return {
        "url": url,
        "scheme": p.scheme,
        "host": host,
        "port": p.port,
        "path": p.path or "/",
        "query": p.query,
        "fragment": p.fragment,
        "subdomain": split["subdomain"],
        "domain": split["domain"],
        "suffix": split["suffix"],
        "registered_domain": registered,
        "flags": {
            "is_ip": is_ip,
            "is_shortener": host in SHORTENERS,
            "has_at": "@" in url,
            "num_subdomains": num_subdomains,
            "url_length": len(url),
            "is_https": p.scheme == "https",
            "has_port": p.port is not None,
        },
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python analyzers/url_parser.py "<url>"')
        sys.exit(1)
    print(json.dumps(analyze(sys.argv[1]), indent=2))
