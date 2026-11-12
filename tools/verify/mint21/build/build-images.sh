#!/bin/bash
# build-images.sh [clean|services|planted|svcplanted|all]...   TEST HARNESS (host side, needs docker + cp-jammy-base)
#   cp-mint-clean      Linux Mint 21.3 Cinnamon identity on Ubuntu jammy (package set of the 2026-10-21 image)
#   cp-mint-services   clean + every critical service at defaults (+ test-only no-IPv6 overrides, ftpuser)
#   cp-mint-planted    clean + OpenSSH/vsftpd/apache2/hacking tools + plant-mint.sh (planted intro image)
#   cp-mint-svcplanted services + tools/verify/plant.sh
# Every image is a `docker commit` of a systemd container (hostname mint-cptest, like 2026-10-21).
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"; M="$(dirname "$H")"; V="$(dirname "$M")"
DEBS="${DEBS:-/home/claude/testenv/mint-debs}"
RUN=(docker run -d --hostname mint-cptest --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock)
C=T-build
boot() { docker rm -f $C >/dev/null 2>&1 || true; "${RUN[@]}" --name $C "$1" /sbin/init >/dev/null
         for _ in $(seq 30); do docker exec $C systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && return; sleep 1; done; }
commit() {  # commit IMAGE MESSAGE
    docker exec $C bash -c 'journalctl --rotate >/dev/null 2>&1; journalctl --vacuum-time=1s >/dev/null 2>&1; rm -rf /tmp/* 2>/dev/null; sync' || true
    # docker commit drops POSIX ACLs here: save them in a label (restored by ../restore-acls.sh / run-pipeline.sh) and
    # give each such file the group mode bits of its group:: entry (else the ACL mask would remain as group bits)
    local acl; acl="$(docker exec $C bash -c 'd=$(getfacl -R -s -p /etc /usr /home /root /srv /opt /var/www 2>/dev/null)
        [ -n "$d" ] || exit 0
        echo "$d" | awk "/^# file: /{f=substr(\$0,9)} /^group::/{split(\$0,a,\":\"); g=a[3]; gsub(/-/,\"\",g); print \"g=\" g \"\t\" f}" |
            while IFS="$(printf "\t")" read -r m f; do [ -g "$f" ] && m="${m}s"; chmod "$m" "$f"; done
        echo "$d" | gzip -9 | base64 -w0')"
    docker commit -c 'CMD ["/sbin/init"]' -c 'STOPSIGNAL SIGRTMIN+3' ${acl:+-c "LABEL cptest.acls=$acl"} -m "$2" $C "$1" >/dev/null
    [ -n "$acl" ] && echo "  saved POSIX ACLs of $(echo "$acl" | base64 -d | gunzip | grep -c '^# file:') file(s) in label cptest.acls"
    docker rm -f $C >/dev/null; echo "built $1"; }
trap 'docker rm -f $C >/dev/null 2>&1 || true' EXIT

build_clean() {
    [ -f "$DEBS/mintsystem_8.5.8_all.deb" ] || "$H/build-mint-debs.sh" "$DEBS"
    boot cp-jammy-base
    docker exec $C mkdir -p /tmp/cpbuild/debs
    docker cp "$H/files/official-package-repositories.list" $C:/tmp/cpbuild/
    docker cp "$H/jammy-packages.txt" $C:/tmp/cpbuild/
    docker cp "$DEBS/." $C:/tmp/cpbuild/debs/
    docker cp "$H/install-clean.sh" $C:/tmp/cpbuild/; docker cp "$H/finalize-clean.sh" $C:/tmp/cpbuild/
    docker exec $C bash /tmp/cpbuild/install-clean.sh
    docker exec $C bash /tmp/cpbuild/finalize-clean.sh
    commit cp-mint-clean "cp-mint-clean: Mint 21.3 Cinnamon identity on jammy (tools/verify/mint21/build)"
}
build_services() {
    boot cp-mint-clean
    docker cp "$H/install-services.sh" $C:/tmp/; docker exec $C bash /tmp/install-services.sh
    commit cp-mint-services "cp-mint-services: clean + every critical service at defaults"
}
build_planted() {
    boot cp-mint-clean
    docker cp "$H/install-planted.sh" $C:/tmp/; docker cp "$M/plant-mint.sh" $C:/tmp/plant-mint.sh
    docker exec $C bash /tmp/install-planted.sh
    commit cp-mint-planted "cp-mint-planted: clean + intro-round plants (plant-mint.sh)"
}
build_svcplanted() {
    boot cp-mint-services
    docker cp "$V/plant.sh" $C:/tmp/plant.sh
    docker exec $C bash -c 'umask 022; bash /tmp/plant.sh; rm -f /tmp/plant.sh'
    commit cp-mint-svcplanted "cp-mint-svcplanted: services + tools/verify/plant.sh"
}
[ $# -gt 0 ] || set -- all
for t in "$@"; do
    case "$t" in
        all) build_clean; build_services; build_planted; build_svcplanted ;;
        clean|services|planted|svcplanted) "build_$t" ;;
        *) echo "unknown target $t"; exit 2 ;;
    esac
done
docker image ls 'cp-mint-*'
