# Validation — VPNSOPR

Date: 2026-10-29

Executed in the build workspace:

- Go 1.25.3: build and `go test -race ./...` passed.
- `go vet ./...` passed.
- JavaScript syntax: `node --check web/app.js` passed.
- Installer syntax: `bash -n install.sh` passed.
- Real Xray 26.10.29: generated configuration validated; authenticated VLESS over WebSocket/TLS round trip to a local HTTP fixture passed. Official release download SHA-256 matched GitHub release metadata. The fixture has a narrow loopback allow rule only in the test; product defaults retain Xray's own target policy.
- Native TLS 1.3 TCP and UDP-over-TLS: three concurrent sources, successful echo round trips; incorrect token rejected.
- Session authentication, logout, cross-origin rejection, login throttling, credential expiration filtering, configuration persistence/permissions and adapter binary allowlisting passed.
- External-process lifecycle: operator-approved echo fixture, literal argument handling and admin credential exclusion passed. This does not establish protocol compatibility for any third-party tunnel binary.
- Built executable smoke test: server startup, embedded HTML/CSS/JS responses, login, 25-driver catalog, Persian user creation, backup, download test, cross-origin rejection and logout passed.
- Linux release cross-compilation: amd64, arm64, armv7. Only amd64 was executed in this environment.

Not verified here:

- All external-engine protocols and release versions, kernel/TUN/raw-socket configurations, third-party accounts, DNS and public TLS issuance.
- Installing/upgrading the service under systemd on a VPS.
- GitHub Actions running in an actual uploaded repository or published Release.
- A rendered browser UI: Chromium downloaded successfully but failed to launch in this environment. Embedded assets and JavaScript syntax were checked, but visual and browser interaction QA remain to be done.
- Internet throughput, traffic quotas, complete X-UI parity or production-scale reliability.

The package includes original source plus VPNSOPR binaries. External-engine executables and real administrator credentials are not included.

Theme update: uploaded blue/silver artwork embedded unchanged; HTML IDs and asset routes checked; themed Go build and existing tests passed. install-direct.sh passes bash syntax checking; full installation under systemd and its toolchain-download path have not been tested on a VPS.

Integrated engine installer update:
- Official release metadata was resolved into engines.lock.json for amd64/arm64/armv7. Missing native artifacts are recorded explicitly.
- SHA256 verification and real ELF extraction were tested using already downloaded Xray, Rathole and udp2raw official archives in a staging directory, without system changes.
- Attempts to run fresh engine downloads in this environment received HTTP 403 from the network proxy. End-to-end download of every engine and apt/systemd installation have NOT been verified here.
- Installer reports individual failures and returns a nonzero result instead of claiming that every engine installed.
