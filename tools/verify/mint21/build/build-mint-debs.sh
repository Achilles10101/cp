#!/bin/bash
# build-mint-debs.sh OUTDIR  - TEST HARNESS: build Linux Mint 21.3's own packages from github.com/linuxmint
# at the exact versions the 2026-10-21 image used, plus stub packages for what is not on GitHub.
# Runs everything in a throwaway container (cp-jammy-base); writes *.deb into OUTDIR on the host.
set -euo pipefail
OUT="${1:?OUTDIR}"; HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${SRC:-/home/claude/T-src}"        # clones live here (untrusted download dir, separate from scripts)
mkdir -p "$OUT" "$SRC/export"
# repo version commit  (commit = the one whose debian/changelog top entry is that version)
cat > "$SRC/versions.txt" <<'V'
mintsystem 8.5.8 f8c1cb1373052e76b3e37578a87dd7ac92e47cd3
mintupdate 6.0.9 72593db4d35d4f0dcdbcf851efcdb52c3dc4f078
mintsources 2.2.9 ab446bb8d3e02c0815f1d3ebf8e34fc7d473761c
mint-common 2.3.1 3fdd1ceebd501e73d365bb14f552d7695c97600c
lightdm-settings 2.0.2 63d0744adb5d39acfe2bc9b00965088e8daa083e
mint-upgrade-info 1.3.0 62711a5c12604dd02862c00e2a19f33a74ff0b4d
V
while read -r r v h; do
  [ -d "$SRC/$r" ] || git clone -q --filter=blob:none --no-checkout "https://github.com/linuxmint/$r" "$SRC/$r"
  rm -rf "$SRC/export/$r-$v"; mkdir -p "$SRC/export/$r-$v"
  git -C "$SRC/$r" archive "$h" | tar -x -C "$SRC/export/$r-$v"
done < "$SRC/versions.txt"

C=T-debbuild
docker rm -f $C >/dev/null 2>&1 || true
docker run -d --name $C cp-jammy-base sleep infinity >/dev/null
trap 'docker rm -f $C >/dev/null 2>&1 || true' EXIT
docker exec $C bash -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends debhelper gettext python3 >/dev/null'
docker cp "$SRC/export" $C:/build
docker exec $C bash -c 'umask 022; cd /build && for d in */; do (cd "$d" && dpkg-buildpackage -b -us -uc -d >"/build/${d%/}.buildlog" 2>&1) || { echo "BUILD FAILED: $d"; tail -20 "/build/${d%/}.buildlog"; }; done; ls /build/*.deb'

# ---- stubs (Mint package server unreachable): same names/versions as the 2026-10-21 image
docker cp "$HERE/files" $C:/files
docker exec -i $C bash -s <<'S'
set -e; umask 022
stub() {  # stub NAME VERSION "DEPENDS" [extra-tree-dir]
  local n="$1" v="$2" dep="$3" tree="/stub/$1"
  mkdir -p "$tree/DEBIAN" "$tree/usr/share/doc/$n"
  { echo "Package: $n"; echo "Version: $v"; echo "Architecture: all"; echo "Maintainer: CP test harness <root@localhost>"
    [ -n "$dep" ] && echo "Depends: $dep"
    echo "Section: misc"; echo "Priority: optional"
    echo "Description: STUB for CP test container - stands in for the real Linux Mint package"
    echo " Built by tools/verify/mint21/build/build-mint-debs.sh (Mint package server unreachable)."; } > "$tree/DEBIAN/control"
  echo "stub" > "$tree/usr/share/doc/$n/README.stub"
  dpkg-deb --root-owner-group -b "$tree" "/build/${n}_${v}_all.deb" >/dev/null
}
# mint-info: like the real one it owns /etc/linuxmint/info and applies the Mint identity through
# mintsystem's adjustment mechanism (/usr/share/linuxmint/adjustments/*.overwrite).
mkdir -p /stub/mint-info/etc/linuxmint /stub/mint-info/usr/share/linuxmint/mint-info /stub/mint-info/usr/share/linuxmint/adjustments /stub/mint-info/etc/upstream-release
cp /files/info /stub/mint-info/etc/linuxmint/info
cp /files/os-release /files/lsb-release /files/issue /files/issue.net /stub/mint-info/usr/share/linuxmint/mint-info/
cp /files/upstream-lsb-release /stub/mint-info/etc/upstream-release/lsb-release
cat > /stub/mint-info/usr/share/linuxmint/adjustments/10-mint-info.overwrite <<'O'
/usr/share/linuxmint/mint-info/os-release /usr/lib/os-release
/usr/share/linuxmint/mint-info/lsb-release /etc/lsb-release
/usr/share/linuxmint/mint-info/issue /etc/issue
/usr/share/linuxmint/mint-info/issue.net /etc/issue.net
O
mkdir -p /stub/mint-info/DEBIAN; printf '#!/bin/sh\nset -e\n[ "$1" = configure ] && [ -x /usr/lib/linuxmint/mintsystem/mint-adjust.py ] && /usr/lib/linuxmint/mintsystem/mint-adjust.py || true\n' > /stub/mint-info/DEBIAN/postinst; chmod 755 /stub/mint-info/DEBIAN/postinst
stub mint-info 2023.12.1 ""
stub mint-translations 2024.01.07 ""
stub mint-mirrors 1.2.6 ""
stub iso-flag-png 1.0.2 ""
# metapackages: dependencies approximated from the real 21.3 ones (packages present on the 2026-10-21 image)
stub mint-meta-core 2021.11.29 "mintsystem, mintupdate, mintsources, mint-common, mint-info, mint-mirrors, mint-translations, mint-upgrade-info, lightdm-settings, sudo, lsb-release, network-manager, lightdm, slick-greeter, xserver-xorg, policykit-1, dbus-x11, apt, synaptic, inxi"
stub mint-meta-cinnamon 2021.11.29 "mint-meta-core, cinnamon, cinnamon-core, cinnamon-common, cinnamon-control-center, cinnamon-desktop-data, cinnamon-screensaver, cinnamon-session, cinnamon-settings-daemon, muffin, nemo, nemo-data, network-manager-gnome, xapp, xapps-common, python3-xapp, gir1.2-xapp-1.0, lightdm, slick-greeter, zenity"
ls -la /build/*.deb
S
docker cp $C:/build/. /tmp/T-debout
cp /tmp/T-debout/*.deb "$OUT"/; rm -rf /tmp/T-debout
ls -la "$OUT"
