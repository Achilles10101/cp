#!/bin/bash
# install-clean.sh - runs INSIDE a cp-jammy-base container (files in /tmp/cpbuild): installs the exact package set of
# the 2026-10-21 Mint 21.3 image (jammy-packages.txt, current jammy versions) + Mint's own packages / stubs (debs/).
set -e; umask 022
B=/tmp/cpbuild
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod 755 /usr/sbin/policy-rc.d   # no service starts during the build
: > /etc/apt/sources.list
install -m644 $B/official-package-repositories.list /etc/apt/sources.list.d/official-package-repositories.list
# arm64 host (Apple Silicon): same suites from ports.ubuntu.com
[ "$(dpkg --print-architecture)" = amd64 ] || sed -i -E 's#http://(archive|security)\.ubuntu\.com/ubuntu/?#http://ports.ubuntu.com/ubuntu-ports#' /etc/apt/sources.list.d/official-package-repositories.list
echo 'APT::Install-Recommends "false";' > /etc/apt/apt.conf.d/00cptest-norecommends   # exact package set; removed again
apt-get update -qq
# shellcheck disable=SC2046  # one argument per package name
# packages without an installable version on this architecture (arm64: grub-pc-bin, libdrm-intel1, libmfx1,
# libquadmath0) are skipped: keep only names that have a real package record
# shellcheck disable=SC2046  # one argument per package name
PKGS="$(apt-cache --no-all-versions show $(cat $B/jammy-packages.txt) 2>/dev/null | sed -n 's/^Package: //p' | sort -u)"
echo "skipped (no $(dpkg --print-architecture) package): $(sort -u $B/jammy-packages.txt | comm -23 - <(echo "$PKGS") | tr '\n' ' ')"
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $PKGS > /root/bulk-install.log 2>&1 \
    || { tail -30 /root/bulk-install.log; exit 1; }
tail -2 /root/bulk-install.log
# Mint packages: mintupdate overwrites icons of Ubuntu's software-properties-gtk, which mintsources' transitional
# software-properties-gtk replaces -> the first pass can stop on that file conflict; the second pass completes it.
cd $B/debs
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends ./*.deb > /root/mint-install.log 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt-get -f install -y -q >> /root/mint-install.log 2>&1
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends ./*.deb >> /root/mint-install.log 2>&1
dpkg-query -W mintsystem mintupdate mintsources mint-common lightdm-settings mint-upgrade-info mint-meta-cinnamon mint-meta-core mint-info
bad="$(dpkg -l | awk 'NR>5 && $1 != "ii"')"; [ -z "$bad" ] || { echo "NOT CLEANLY INSTALLED:"; echo "$bad"; exit 1; }
rm -f /root/mint-install.log
