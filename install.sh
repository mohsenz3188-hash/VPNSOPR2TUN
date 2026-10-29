#!/usr/bin/env bash
set -euo pipefail
# Usage: VPNSOPR_REPO=YOUR_ACCOUNT/VPNSOPR bash install.sh [v0.1.0]
repo="${VPNSOPR_REPO:-}"
version="${1:-latest}"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'Set VPNSOPR_REPO=OWNER/REPOSITORY'; exit 1; }
[[ "$version" == latest || "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Version must be latest or vX.Y.Z'; exit 1; }
[[ "$(uname -s)" == Linux ]] || { echo 'Installer supports Linux with systemd.'; exit 1; }
[[ "$EUID" -eq 0 ]] || { echo 'Run this installer as root.'; exit 1; }
for tool in curl tar sha256sum python3 systemctl useradd install; do command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool"; exit 1; }; done
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; armv7l) arch=armv7;; *) echo 'Unsupported architecture'; exit 1;; esac
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
if [[ "$version" == latest ]]; then
 curl --fail --silent --show-error --location --proto '=https' "https://api.github.com/repos/$repo/releases/latest" -o "$work/release.json"
 version="$(python3 - "$work/release.json" <<'PY'
import json,sys,re
v=json.load(open(sys.argv[1]))['tag_name']
if not re.fullmatch(r'v\d+\.\d+\.\d+',v): raise SystemExit('Latest release is not vX.Y.Z')
print(v)
PY
)"
fi
base="https://github.com/$repo/releases/download/$version"
archive="vpnsopr_linux_${arch}.tar.gz"
curl --fail --silent --show-error --location --proto '=https' "$base/$archive" -o "$work/$archive"
curl --fail --silent --show-error --location --proto '=https' "$base/SHA256SUMS" -o "$work/SHA256SUMS"
python3 - "$work/SHA256SUMS" "$archive" > "$work/selected.sha256" <<'PY'
import sys,re
lines=[line for line in open(sys.argv[1]) if line.split()[-1:]==[sys.argv[2]]]
if len(lines)!=1 or not re.match(r'^[a-fA-F0-9]{64}\s+',lines[0]): raise SystemExit('Missing/invalid checksum')
print(lines[0].strip())
PY
(cd "$work" && sha256sum --check selected.sha256)
tar -xzf "$work/$archive" -C "$work" vpnsopr
id vpnsopr >/dev/null 2>&1 || useradd --system --home-dir /var/lib/vpnsopr --shell /usr/sbin/nologin vpnsopr
install -d -m 0700 -o vpnsopr -g vpnsopr /var/lib/vpnsopr
install -d -m 0700 /etc/vpnsopr
if [[ ! -e /etc/vpnsopr/panel.env ]]; then
 token="$("$work/vpnsopr" --generate-token)"
 (umask 077; printf 'VPNSOPR_ADMIN_TOKEN=%s\nVPNSOPR_ADAPTER_BINARIES={}\n' "$token" > /etc/vpnsopr/panel.env)
 printf '\nAdmin token (save privately): %s\n\n' "$token"
fi
if systemctl is-active --quiet vpnsopr; then systemctl stop vpnsopr; fi
install -m 0755 "$work/vpnsopr" /usr/local/bin/vpnsopr
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
printf '\nInstalled %s. Panel: http://127.0.0.1:8080\n' "$version"
printf 'Use SSH forwarding or configure a trusted HTTPS reverse proxy.\n'
printf 'External engines (Xray, FRP, etc.) must be installed and enabled separately.\n'
