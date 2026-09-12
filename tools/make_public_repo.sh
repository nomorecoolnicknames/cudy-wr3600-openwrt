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
mkdir -p "$DEST"/{kernel/port,port66,bsp-6.6/compat,tools/install,docs,release}

say "kernel side"
cp "$R/kernel-6.6/build.sh" "$R/kernel-6.6/initramfs.list" "$DEST/kernel/"
cp -a "$R/kernel-6.6/initramfs-release" "$DEST/kernel/"
cp -a "$R/kernel-6.6/rootfs-overlay-release" "$DEST/kernel/"
cp -a "$R/kernel-6.6/pkgs" "$DEST/kernel/"          # vendored OpenWrt ipks (wifi-scripts, iwinfo) + checksums
rsync -a "${EXCL[@]}" "$R/kernel-6.6/port/" "$DEST/kernel/port/"

say "out-of-tree modules"
for d in enet66 enet66b leds66 reboot66 shim66 vpcie66; do
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
cp "$R/tools/install/README.md" "$DEST/docs/INSTALL.ru.md"
cp "$R/docs/SOURCE_README.md" "$DEST/docs/"
cp "$R/docs/ROADMAP.md" "$DEST/docs/"
cp "$R/docs/RELEASE_CHECKLIST.md" "$DEST/docs/"
[ -f "$R/docs/RELEASE_CODE_REVIEW.md" ] && cp "$R/docs/RELEASE_CODE_REVIEW.md" "$DEST/docs/"
cp "$R/BUILD_GUIDE.md" "$DEST/docs/BUILD_GUIDE.md"
cp "$R/WIFI_CORE_MAP.md" "$DEST/docs/HARDWARE_RADIO.md"
cp "$R/release/RELEASE_NOTES.md" "$DEST/docs/"
cp "$R/release/ROOTFS_PACKAGES.md" "$DEST/docs/"
cp "$R/release/SHA256SUMS" "$DEST/release/"
[ -f "$R/docs/4PDA_POST.txt" ] && cp "$R/docs/4PDA_POST.txt" "$DEST/docs/"
# Wi-Fi research reports (our own analysis of the stock firmware; bench MAC and
# host paths scrubbed)
mkdir -p "$DEST/docs/wifi-width"
for f in STOCK_WIFI_BRINGUP.md WL_IOCTL_SPEC.md; do
	[ -f "$R/triaging/wifi-width/$f" ] && sed -E 's#/home/[a-z0-9_]+/cudy_be3600/#<repo>/#g; s/d4:0d:ab:46:c4:5[0-9a-f]/xx:xx:xx:xx:xx:xx/g' \
		"$R/triaging/wifi-width/$f" > "$DEST/docs/wifi-width/$f"
done

cat > "$DEST/LICENSE" <<'EOF'
This repository is licensed under the GNU General Public License, version 2
only (GPL-2.0-only). See https://www.gnu.org/licenses/old-licenses/gpl-2.0.html

The Broadcom Wi-Fi driver binaries used by the release images (wl.ko, hnd.ko,
wlshared.ko) are proprietary, are not part of this repository, and are taken
from the factory firmware of the device itself.
EOF
cat > "$DEST/.gitignore" <<'EOF'
*.ko
*.o
*.mod
*.mod.c
*.cmd
*.d
modules.order
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
echo
echo "next:"
echo "  cd $DEST && git init -b main 2>/dev/null; git add -A && git commit -m 'release $VER'"
echo "  gh repo create <name> --public --source=$DEST --push"
