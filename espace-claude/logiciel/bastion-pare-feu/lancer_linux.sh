#!/usr/bin/env bash
# Lance Bastion avec les droits root (nécessaires pour nftables).
cd "$(dirname "$0")" || exit 1
command -v python3 >/dev/null || { echo "Python 3 est requis : sudo apt install python3"; exit 1; }
command -v nft >/dev/null || echo "Attention : nftables absent (sudo apt install nftables) — mode simulation seulement."
python3 -c "import psutil" 2>/dev/null || echo "Astuce : « sudo apt install python3-psutil » améliore la liste des connexions."
if [ "$(id -u)" -ne 0 ]; then
  exec sudo -E python3 pare_feu.py "$@"
fi
exec python3 pare_feu.py "$@"
