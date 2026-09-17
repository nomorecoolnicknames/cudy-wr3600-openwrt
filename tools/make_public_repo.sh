#!/bin/bash
# ---------------------------------------------------------------------------
# Assemble the PUBLIC git tree for the Cudy WR3600 6.6 port.
#
# The working repository carries the whole bring-up history (vendor drops,
# packet captures, lab addresses, thousands of commits); the public one gets
# a clean tree with only what a user or a contributor needs:
#   - the GPL sources and build inputs (same set as tools/make_source_tarball.sh)
#   - the installers (tools/install/)
#   - documentation: README, install guide, release notes, checklist, roadmap,
#     hardware notes, code review
#   - release/SHA256SUMS (the binaries themselves go to GitHub Releases)
#
#   tools/make_public_repo.sh [DEST]     default DEST=/mnt/ramdisk/cudy-public
#
# The script never pushes; it prints the git commands to run.
# ---------------------------------------------------------------------------
set -euo pipefail
R=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEST=${1:-/mnt/ramdisk/cudy-public}
VER=${VER:-$(sed -n 's/^version=//p' "$R/release/cudy-release" 2>/dev/null || date +%Y-%m-%d)}

say() { printf -- '--- %s\n' "$*"; }
EXCL=(--exclude '*.ko' --exclude '*.o' --exclude '*.mod' --exclude '*.mod.c'
      --exclude '.*.cmd' --exclude '*.d' --exclude 'modules.order'
      --exclude 'Module.symvers' --exclude '__pycache__' --exclude '.omc'
      --exclude '.git*' --exclude '*.bak*' --exclude '*.orig' --exclude '*.rej'
      --exclude '*.log' --exclude '*.itb' --exclude '*.pyc')

mkdir -p "$DEST"
# keep .git if the tree already exists (incremental updates), replace the rest
find "$DEST" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
mkdir -p "$DEST"/{kernel/port,port66,bsp-6.6/compat,tools/install,release}
rm -rf "$DEST/docs"

say "kernel side"
cp "$R/kernel-6.6/build.sh" "$R/kernel-6.6/initramfs.list" "$DEST/kernel/"
cp -a "$R/kernel-6.6/initramfs-release" "$DEST/kernel/"
cp -a "$R/kernel-6.6/rootfs-overlay-release" "$DEST/kernel/"
cp -a "$R/kernel-6.6/pkgs" "$DEST/kernel/"          # vendored OpenWrt ipks (wifi-scripts, iwinfo) + checksums
rsync -a "${EXCL[@]}" "$R/kernel-6.6/port/" "$DEST/kernel/port/"

say "out-of-tree modules"
for d in enet66 enet66b cascade66 leds66 reboot66 shim66 vpcie66; do
	mkdir -p "$DEST/port66/$d"
	rsync -a "${EXCL[@]}" "$R/port66/$d/" "$DEST/port66/$d/"
done
rsync -a "${EXCL[@]}" "$R/bsp-6.6/compat/" "$DEST/bsp-6.6/compat/"

say "tools"
for t in build_release.sh clean_release_rootfs.sh make_source_tarball.sh \
         make_public_repo.sh insmodf.c ubiwrite.c ubimkvol.c wl66ctl.c wl66ctl_test.sh modvermagic.py modpvfix.py \
         module_header_fix.py erom_decode.py; do
	[ -f "$R/tools/$t" ] && cp "$R/tools/$t" "$DEST/tools/"
done
cp "$R/tools/install/"*.py "$R/tools/install/"*.sh "$R/tools/install/"*.md "$DEST/tools/install/"

say "documentation"
cp "$R/docs/PUBLIC_README.md" "$DEST/README.md"
cp "$R/release/SHA256SUMS" "$DEST/release/"
# no docs/ in the public tree: README.md + INSTALL.md (Russian install/update guide)
cp "$R/tools/install/README.md" "$DEST/INSTALL.md"

cat > "$DEST/LICENSE" <<'EOF'
This repository is licensed under the GNU General Public License, version 2
only (GPL-2.0-only). See https://www.gnu.org/licenses/old-licenses/gpl-2.0.html

The Broadcom Wi-Fi driver binaries used by the release images (wl.ko, hnd.ko,
wlshared.ko) are proprietary, are not part of this repository, and are taken
from the factory firmware of the device itself.
EOF
# Build outputs only.  Do NOT put "*.d" or "modules.order" here: gitignore
# patterns match directories too, so "*.d" swallowed etc/init.d/ whole (the
# wifi66 init script and the LuCI updater's menu.d/acl.d files were missing
# from the published tree until 2026-09-17), and "modules.order" is a real
# source file in kernel/initramfs-release/.  Kernel dependency files never
# reach this tree anyway - rsync drops them on the way in.
cat > "$DEST/.gitignore" <<'EOF'
*.ko
*.o
*.mod
*.mod.c
*.cmd
Module.symvers
__pycache__/
*.pyc
*.itb
*.sq
*.tar.gz
EOF

say "hygiene check"
bad=$(grep -rIl -E 'CudyRoot2026|192\.168\.1\.(88|119|120)|192\.168\.2\.(39|54|231)|gunwest|n8nagent|/home/gun|id_ed25519_gunwest|9000baf720c98d03' "$DEST" --exclude=make_public_repo.sh --exclude=make_source_tarball.sh --exclude=clean_release_rootfs.sh 2>/dev/null || true)
if [ -n "$bad" ]; then
	echo "PERSONAL DATA in public tree:"; echo "$bad"; exit 1
fi
echo "sizes: $(du -sh "$DEST" | cut -f1), files: $(find "$DEST" -type f ! -path '*/.git/*' | wc -l)"
# commits in the public tree are made by the project owner, not the build user
[ -d "$DEST/.git" ] && {
	git -C "$DEST" config user.name nomorecoolnicknames
	git -C "$DEST" config user.email 78512247+nomorecoolnicknames@users.noreply.github.com
}
echo
echo "next:"
echo "  cd $DEST && git init -b main 2>/dev/null; git add -A && git commit -m 'release $VER'"
echo "  gh repo create <name> --public --source=$DEST --push"
