"""
SSRF Guard — pastikan hostname tidak resolve ke IP internal/privat.

Fungsi publik:
    check_host(host) -> (ok, reason, ips, blocked)

    ok      : True kalau boleh di-fetch
    blocked : True kalau sengaja diblokir (IP internal)
              False kalau cuma tidak reachable (DNS gagal)
"""
import os
import sys
import socket
import ipaddress

_THIS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_THIS)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

ALLOW_PRIVATE = os.environ.get("PHISHSCAN_ALLOW_PRIVATE", "").lower() in ("1", "true", "yes")


def _is_blocked_ip(ip_obj) -> bool:
    if ALLOW_PRIVATE:
        return False
    if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
        return True
    if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
        return True
    for net in BLOCKED_NETWORKS:
        try:
            if ip_obj in net:
                return True
        except TypeError:
            continue
    return False


def check_host(host: str):
    """
    Return (ok, reason, ips, blocked).

    ok=True                 -> aman (publik)
    ok=False, blocked=True  -> diblokir (IP internal/privat)
    ok=False, blocked=False -> tidak reachable (DNS gagal), TIDAK diblokir
    """
    host = host.strip().lower()
    if not host:
        return False, "host kosong", [], False

    # Kalau host langsung berupa IP
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip):
            return False, f"IP {host} diblokir (internal/privat)", [str(ip)], True
        return True, "", [str(ip)], False
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        # DNS gagal → bukan SSRF, hanya tidak reachable
        return False, f"tidak bisa resolve: {e}", [], False

    ips = []
    for info in infos:
        addr = info[4][0].split("%")[0]
        try:
            ip_obj = ipaddress.ip_address(addr)
        except ValueError:
            continue
        ips.append(str(ip_obj))
        if _is_blocked_ip(ip_obj):
            return False, f"host resolve ke IP internal {ip_obj}", ips, True

    seen = set()
    uniq = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)

    if not uniq:
        return False, "tidak ada IP yang bisa dipakai", [], False

    return True, "", uniq, False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python analyzers/ssrf_guard.py "<host>"')
        sys.exit(1)
    ok, reason, ips, blocked = check_host(sys.argv[1])
    print(f"ok={ok}  blocked={blocked}  reason={reason!r}")
    print(f"ips={ips}")
