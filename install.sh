#!/bin/sh

set -eu

gate_repository="stell0/windmill-gate"
gate_version="${GATE_VERSION:-latest}"
gate_install_dir="${GATE_INSTALL_DIR:-windmill-gate}"

if ! command -v curl >/dev/null 2>&1; then
	printf '%s\n' "Gate installer: curl is required" >&2
	exit 1
fi
if ! command -v tar >/dev/null 2>&1; then
	printf '%s\n' "Gate installer: tar is required" >&2
	exit 1
fi
if [ -e "$gate_install_dir" ] || [ -L "$gate_install_dir" ]; then
	printf '%s\n' "Gate installer: $gate_install_dir already exists" >&2
	printf '%s\n' "Choose another directory with GATE_INSTALL_DIR=/path/to/gate" >&2
	exit 1
fi

case "$(uname -s)" in
	Linux) gate_os="linux" ;;
	Darwin) gate_os="darwin" ;;
	*)
		printf '%s\n' "Gate installer: only Linux and macOS are supported" >&2
		exit 1
		;;
esac

case "$(uname -m)" in
	x86_64 | amd64) gate_arch="amd64" ;;
	aarch64 | arm64) gate_arch="arm64" ;;
	*)
		printf '%s\n' "Gate installer: unsupported CPU architecture $(uname -m)" >&2
		exit 1
		;;
esac

if [ "$gate_version" = "latest" ]; then
	gate_release_base="https://github.com/$gate_repository/releases/latest/download"
else
	gate_release_base="https://github.com/$gate_repository/releases/download/$gate_version"
fi
gate_release_base="${GATE_RELEASE_BASE_URL:-$gate_release_base}"
gate_archive_name="windmill-gate_${gate_os}_${gate_arch}.tar.gz"

gate_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/windmill-gate-install.XXXXXX")
trap 'rm -rf "$gate_tmp_dir"' EXIT HUP INT TERM

printf '%s\n' "Downloading Gate ${gate_version} for ${gate_os}/${gate_arch}..."
curl -fsSL "$gate_release_base/$gate_archive_name" -o "$gate_tmp_dir/$gate_archive_name"
curl -fsSL "$gate_release_base/checksums.txt" -o "$gate_tmp_dir/checksums.txt"

gate_expected_checksum=$(awk -v name="$gate_archive_name" '$2 == name { print $1 }' "$gate_tmp_dir/checksums.txt")
if [ -z "$gate_expected_checksum" ]; then
	printf '%s\n' "Gate installer: release checksum is missing" >&2
	exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
	gate_actual_checksum=$(sha256sum "$gate_tmp_dir/$gate_archive_name" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
	gate_actual_checksum=$(shasum -a 256 "$gate_tmp_dir/$gate_archive_name" | awk '{ print $1 }')
else
	printf '%s\n' "Gate installer: sha256sum or shasum is required" >&2
	exit 1
fi

if [ "$gate_actual_checksum" != "$gate_expected_checksum" ]; then
	printf '%s\n' "Gate installer: checksum verification failed" >&2
	exit 1
fi

mkdir -p "$gate_tmp_dir/unpack"
tar -xzf "$gate_tmp_dir/$gate_archive_name" -C "$gate_tmp_dir/unpack"
if [ ! -x "$gate_tmp_dir/unpack/windmill-gate/gate" ]; then
	printf '%s\n' "Gate installer: release archive is invalid" >&2
	exit 1
fi

gate_install_parent=$(dirname "$gate_install_dir")
mkdir -p "$gate_install_parent"
mv "$gate_tmp_dir/unpack/windmill-gate" "$gate_install_dir"

if sh "$gate_install_dir/update-nethserver-admin"; then
	printf '%s\n' "NethServer admin skill installed."
else
	printf '%s\n' "Gate installed, but the NethServer admin skill could not be downloaded." >&2
	printf '%s\n' "Retry later with: cd $gate_install_dir && ./update-nethserver-admin" >&2
fi

printf '\n%s\n' "Gate is ready in $gate_install_dir"
printf '%s\n' "Next:"
printf '  cd %s\n' "$gate_install_dir"
printf '%s\n' "  ./gate --bastion operator@bastion.example --agent codex-1 --session '<SESSION ID>'"
