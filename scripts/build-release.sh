#!/bin/sh

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	printf '%s\n' "usage: scripts/build-release.sh VERSION [DIST_DIR]" >&2
	exit 2
fi

gate_version="$1"
gate_dist_dir="${2:-dist}"
gate_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gate_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/windmill-gate-release.XXXXXX")
trap 'rm -rf "$gate_tmp_dir"' EXIT HUP INT TERM

case "$gate_dist_dir" in
	/*) ;;
	*) gate_dist_dir="$gate_root/$gate_dist_dir" ;;
esac
mkdir -p "$gate_dist_dir"

for gate_target in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
	gate_os=${gate_target%_*}
	gate_arch=${gate_target#*_}
	gate_bundle="$gate_tmp_dir/$gate_target/windmill-gate"
	gate_archive="$gate_dist_dir/windmill-gate_${gate_os}_${gate_arch}.tar.gz"

	mkdir -p "$gate_bundle"
	(
		cd "$gate_root"
		CGO_ENABLED=0 GOOS="$gate_os" GOARCH="$gate_arch" \
			go build -trimpath -ldflags "-s -w -X main.version=$gate_version" \
			-o "$gate_bundle/gate" ./cmd/gate
		cp AGENTS.md PLAN.md README.md install.sh update-nethserver-admin "$gate_bundle/"
		cp -R .agents config skills "$gate_bundle/"
	)
	chmod 0755 "$gate_bundle/gate" "$gate_bundle/update-nethserver-admin"
	ln -s gate "$gate_bundle/gate-sh"
	tar -C "$gate_tmp_dir/$gate_target" -czf "$gate_archive" windmill-gate
done

if ! command -v zip >/dev/null 2>&1; then
	printf '%s\n' "release builder: zip is required for Windows archives" >&2
	exit 1
fi
for gate_target in windows_amd64 windows_arm64; do
	gate_arch=${gate_target#*_}
	gate_bundle="$gate_tmp_dir/$gate_target/windmill-gate"
	gate_archive="$gate_dist_dir/windmill-gate_${gate_target}.zip"

	mkdir -p "$gate_bundle"
	(
		cd "$gate_root"
		CGO_ENABLED=0 GOOS=windows GOARCH="$gate_arch" \
			go build -trimpath -ldflags "-s -w -X main.version=$gate_version" \
			-o "$gate_bundle/gate.exe" ./cmd/gate
		cp "$gate_bundle/gate.exe" "$gate_bundle/gate-sh.exe"
		cp AGENTS.md PLAN.md README.md install.ps1 update-nethserver-admin.ps1 "$gate_bundle/"
		cp -R .agents config skills "$gate_bundle/"
		cd "$gate_tmp_dir/$gate_target"
		zip -qr "$gate_archive" windmill-gate
	)
done

if command -v sha256sum >/dev/null 2>&1; then
	(
		cd "$gate_dist_dir"
		sha256sum windmill-gate_*.tar.gz windmill-gate_*.zip > checksums.txt
	)
elif command -v shasum >/dev/null 2>&1; then
	(
		cd "$gate_dist_dir"
		shasum -a 256 windmill-gate_*.tar.gz windmill-gate_*.zip > checksums.txt
	)
else
	printf '%s\n' "release builder: sha256sum or shasum is required" >&2
	exit 1
fi

printf '%s\n' "Release archives written to $gate_dist_dir"
