#!/bin/sh

set -eu

gate_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gate_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/windmill-gate-distribution-test.XXXXXX")
trap 'rm -rf "$gate_tmp_dir"' EXIT HUP INT TERM

case "$(uname -s)" in
	Linux) gate_os="linux" ;;
	Darwin) gate_os="darwin" ;;
	*) exit 0 ;;
esac
case "$(uname -m)" in
	x86_64 | amd64) gate_arch="amd64" ;;
	aarch64 | arm64) gate_arch="arm64" ;;
	*) exit 0 ;;
esac

gate_archive_name="windmill-gate_${gate_os}_${gate_arch}.tar.gz"
gate_bundle="$gate_tmp_dir/bundle/windmill-gate"
gate_release="$gate_tmp_dir/release"
gate_agents="$gate_tmp_dir/agents-main/skills/nethserver-admin"
mkdir -p "$gate_bundle/.agents/skills" "$gate_release" "$gate_agents/references"

printf '%s\n' '#!/bin/sh' 'printf "%s\n" "gate test binary"' > "$gate_bundle/gate"
chmod 0755 "$gate_bundle/gate"
ln -s gate "$gate_bundle/gate-sh"
cp "$gate_root/update-nethserver-admin" "$gate_bundle/update-nethserver-admin"
chmod 0755 "$gate_bundle/update-nethserver-admin"
printf '%s\n' '---' 'name: nethserver-admin' 'description: test fixture' '---' > "$gate_agents/SKILL.md"
printf '%s\n' '# Diagnostics' > "$gate_agents/references/diagnostics.md"

tar -C "$gate_tmp_dir/bundle" -czf "$gate_release/$gate_archive_name" windmill-gate
tar -C "$gate_tmp_dir" -czf "$gate_tmp_dir/agents.tar.gz" agents-main
if command -v sha256sum >/dev/null 2>&1; then
	(
		cd "$gate_release"
		sha256sum "$gate_archive_name" > checksums.txt
	)
else
	(
		cd "$gate_release"
		shasum -a 256 "$gate_archive_name" > checksums.txt
	)
fi

GATE_INSTALL_DIR="$gate_tmp_dir/installed" \
GATE_RELEASE_BASE_URL="file://$gate_release" \
GATE_NETHSERVER_SKILL_URL="file://$gate_tmp_dir/agents.tar.gz" \
	sh "$gate_root/install.sh" >/dev/null

test -x "$gate_tmp_dir/installed/gate"
test -L "$gate_tmp_dir/installed/gate-sh"
test -f "$gate_tmp_dir/installed/.agents/skills/nethserver-admin/SKILL.md"
test -f "$gate_tmp_dir/installed/.agents/skills/nethserver-admin/references/diagnostics.md"

printf '%s\n' "PASS: distribution installer"
