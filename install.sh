#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "-> cek Python ..."
PY=$(command -v python3 || command -v python) || {
    echo "x Python tidak ditemukan."
    exit 1
}
$PY --version

echo "-> cek dependency opsional ..."
$PY - <<'PYEOF'
try:
    import dns
    print("  [ok] dnspython sudah ada")
except ImportError:
    print("  [--] dnspython belum ada (opsional)")

try:
    import cryptography
    print("  [ok] cryptography sudah ada")
except ImportError:
    print("  [--] cryptography belum ada (opsional)")
PYEOF

echo "-> tes cepat ..."
$PY phishscan.py --no-color "https://example.com" | tail -5

echo
echo "Selesai. Pakai:"
echo '  python phishscan.py "<url>"'
