#!/usr/bin/env bash
# VPNSOPR source installer. Supports both flat browser uploads and the web/ layout.
set -euo pipefail
repo="${VPNSOPR_REPO:-}"
prepare_only=0
if [[ "${1:-}" == --prepare-only ]]; then prepare_only=1; shift; fi
[[ $# == 0 ]] || { echo 'Usage: bash install-direct.sh [--prepare-only]'; exit 1; }
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'Set VPNSOPR_REPO=YOUR_ACCOUNT/YOUR_REPOSITORY'; exit 1; }
[[ "$(uname -s)" == Linux ]] || { echo 'Linux is required.'; exit 1; }
if [[ "$prepare_only" == 0 && "$EUID" != 0 ]]; then echo 'Run this installer as root or with sudo.'; exit 1; fi
for tool in curl python3 tar sha256sum mktemp chmod; do command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool"; exit 1; }; done
if [[ "$prepare_only" == 0 ]]; then
 for tool in systemctl useradd install id; do command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool"; exit 1; }; done
 [[ -d /run/systemd/system ]] || { echo 'This server must be booted with systemd.'; exit 1; }
fi
case "$(uname -m)" in x86_64) go_arch=amd64;; aarch64|arm64) go_arch=arm64;; armv7l) go_arch=armv6l;; *) echo 'Unsupported CPU architecture'; exit 1;; esac
work="$(mktemp -d)"; chmod 0700 "$work"; trap 'rm -rf "$work"' EXIT
fetch() { curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 240 "$1" -o "$2"; }
echo 'VPNSOPR: resolving the current source commit...'
fetch "https://api.github.com/repos/$repo/commits/main" "$work/commit.json"
commit="$(python3 - "$work/commit.json" <<'PY'
import json,re,sys
value=json.load(open(sys.argv[1])).get('sha','')
if not re.fullmatch(r'[a-f0-9]{40}',value): raise SystemExit('Could not resolve the repository commit')
print(value)
PY
)"
echo "Downloading source commit ${commit:0:12}..."
fetch "https://api.github.com/repos/$repo/tarball/$commit" "$work/source.tar.gz"
mkdir -p "$work/source" "$work/bin"
tar -xzf "$work/source.tar.gz" --strip-components=1 --no-same-owner -C "$work/source"
source_dir="$work/source"
# A browser upload may place the supplied web files in the repository root.
mkdir -p "$source_dir/web"
for name in index.html style.css app.js brand.jpg; do
 if [[ ! -f "$source_dir/web/$name" && -f "$source_dir/$name" ]]; then mv "$source_dir/$name" "$source_dir/web/$name"; fi
done
for name in go.mod main.go server.go web/index.html web/style.css web/app.js; do
 [[ -f "$source_dir/$name" ]] || { echo "Required source file is missing: $name"; exit 1; }
done
required_go="$(python3 - "$source_dir/go.mod" <<'PY'
import re,sys
m=re.search(r'^go\s+(\d+)\.(\d+)',open(sys.argv[1]).read(),re.M)
if not m: raise SystemExit('Missing Go version in go.mod')
print(m.group(1)+'.'+m.group(2))
PY
)"
go_bin="$(command -v go || true)"
if [[ -n "$go_bin" ]]; then
 go_version="$("$go_bin" version 2>/dev/null || true)"
 if ! python3 - "$go_version" "$required_go" <<'PY'
import re,sys
m=re.search(r'go(\d+)\.(\d+)',sys.argv[1]);needed=tuple(map(int,sys.argv[2].split('.')))
raise SystemExit(0 if m and tuple(map(int,m.groups()))>=needed else 1)
PY
 then go_bin=''; fi
fi
if [[ -z "$go_bin" ]]; then
 echo 'Downloading a stable Go toolchain from go.dev...'
 fetch 'https://go.dev/dl/?mode=json' "$work/go-releases.json"
 python3 - "$work/go-releases.json" "$go_arch" "$required_go" > "$work/go-download.txt" <<'PY'
import json,re,sys
releases=json.load(open(sys.argv[1]));arch=sys.argv[2];required=tuple(map(int,sys.argv[3].split('.')))
for release in releases:
 m=re.match(r'^go(\d+)\.(\d+)',release.get('version',''))
 if not release.get('stable') or not m or tuple(map(int,m.groups()))<required: continue
 for f in release.get('files',[]):
  if f.get('os')=='linux' and f.get('arch')==arch and f.get('kind')=='archive':
   name=f['filename'];digest=f['sha256']
   if not re.fullmatch(r'go[0-9.]+\.linux-(amd64|arm64|armv6l)\.tar\.gz',name) or not re.fullmatch(r'[a-f0-9]{64}',digest): raise SystemExit('Invalid toolchain metadata')
   print(name);print(digest);raise SystemExit(0)
raise SystemExit('No stable Go toolchain is available for this CPU and go.mod version')
PY
 mapfile -t go_download < "$work/go-download.txt"
 fetch "https://go.dev/dl/${go_download[0]}" "$work/go.tar.gz"
 printf '%s  go.tar.gz\n' "${go_download[1]}" > "$work/go.sha256"
 (cd "$work" && sha256sum --check go.sha256)
 tar -xzf "$work/go.tar.gz" --no-same-owner -C "$work"
 go_bin="$work/go/bin/go"
 export GOROOT="$work/go"
fi
# Keep all build caches in the private temporary directory. Do not change system Go.
export GOCACHE="$work/go-cache" GOPATH="$work/go-path" GOTELEMETRY=off GOTOOLCHAIN=local CGO_ENABLED=0
echo 'Building VPNSOPR with the web theme from your repository...'
(cd "$source_dir" && "$go_bin" build -buildvcs=false -trimpath -ldflags='-s -w' -o "$work/bin/vpnsopr" .)
[[ -x "$work/bin/vpnsopr" ]] || { echo 'Build did not produce an executable.'; exit 1; }
if [[ "$prepare_only" == 1 ]]; then echo "Build check passed for source commit $commit; no service or system settings were changed."; exit 0; fi
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
printf '\nVPNSOPR installed from commit %s\n' "$commit"
printf 'Panel: http://127.0.0.1:8080 (on the server)\n'
printf 'From your computer: ssh -L 8080:127.0.0.1:8080 USER@SERVER_IP\n'
printf 'Then open http://127.0.0.1:8080 on that computer.\n'
printf 'For phone/browser access from outside the server, configure HTTPS and a domain.\n'
printf 'VPN engines such as Xray still need separate installation.\n'
