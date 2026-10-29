#!/usr/bin/env bash
set -euo pipefail
[[ "$(uname -s)" == Linux && "$EUID" == 0 ]] || { echo 'Run as root on Linux.'; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'A server booted with systemd is required.'; exit 1; }
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"; chmod 0700 "$work"; trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
(cd "$source_dir/dist" && sha256sum --check SHA256SUMS)
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; armv7l) arch=armv7;; *) echo 'Unsupported CPU architecture.'; exit 1;; esac
tar -xzf "$source_dir/dist/vpnsopr_linux_${arch}.tar.gz" --no-same-owner -C "$work/bin" vpnsopr
id vpnsopr >/dev/null 2>&1 || useradd --system --home-dir /var/lib/vpnsopr --shell /usr/sbin/nologin vpnsopr
install -d -m 0700 -o vpnsopr -g vpnsopr /var/lib/vpnsopr
install -d -m 0700 /etc/vpnsopr
if [[ ! -e /etc/vpnsopr/panel.env ]]; then
 token="$("$work/bin/vpnsopr" --generate-token)"
 (umask 077; printf 'VPNSOPR_ADMIN_TOKEN=%s\nVPNSOPR_ADAPTER_BINARIES={}\n' "$token" > /etc/vpnsopr/panel.env)
 printf '\nAdmin token (save privately): %s\n\n' "$token"
fi
if systemctl is-active --quiet vpnsopr; then systemctl stop vpnsopr; fi
install -m 0755 "$work/bin/vpnsopr" /usr/local/bin/vpnsopr
cat > /etc/systemd/system/vpnsopr.service <<'UNIT'
[Unit]
Description=VPNSOPR VPN and tunnel control
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=vpnsopr
Group=vpnsopr
EnvironmentFile=/etc/vpnsopr/panel.env
WorkingDirectory=/var/lib/vpnsopr
ExecStart=/usr/local/bin/vpnsopr --listen 127.0.0.1:8080 --data /var/lib/vpnsopr
Restart=on-failure
RestartSec=3
TimeoutStopSec=120
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/vpnsopr
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now vpnsopr
systemctl is-active --quiet vpnsopr || { systemctl status vpnsopr --no-pager; exit 1; }
echo 'VPNSOPR installed. Panel on the server: http://127.0.0.1:8080'
echo 'Access through SSH forwarding or configure HTTPS with your domain.'
echo 'For engine installation run install-full.sh.'
