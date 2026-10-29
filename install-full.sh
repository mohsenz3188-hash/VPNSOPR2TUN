#!/usr/bin/env bash
# One invocation: panel + official engines + adapter registration.
set -euo pipefail
[[ "$(uname -s)" == Linux && "$EUID" == 0 ]] || { echo 'Run as root on Linux.'; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'A server booted with systemd is required.'; exit 1; }
command -v apt-get >/dev/null || { echo 'Automatic engine installation currently supports Debian/Ubuntu.'; exit 1; }
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export DEBIAN_FRONTEND=noninteractive
echo 'Installing distribution prerequisites...'
apt-get update
apt-get install -y --no-install-recommends ca-certificates python3 openssl openssh-client openvpn
if ! apt-get install -y --no-install-recommends kcptun; then
 echo 'kcptun distribution package unavailable; it will be listed as failed in the report.'
fi
bash "$source_dir/install-panel.sh"
echo 'Downloading and installing pinned official VPN/tunnel engines...'
status=0
python3 "$source_dir/install-engines.py" || status=$?
systemctl restart vpnsopr
systemctl is-active --quiet vpnsopr || { systemctl status vpnsopr --no-pager; exit 1; }
if [[ "$status" != 0 ]]; then
 echo 'Panel installed. Some engines were not installed; see /var/lib/vpnsopr/engine-install-report.json.'
 exit "$status"
fi
echo 'Panel and all engines available for this CPU were installed and registered.'
echo 'Create matching server/client configurations in the panel before starting tunnels.'
echo 'TUN/raw-socket tools still require interface, route and capability setup. No routes/firewall rules were changed.'
echo 'Panel on server: http://127.0.0.1:8080. Use SSH forwarding or configure HTTPS for remote access.'
