#!/bin/bash
H=/home/claude/work/tools/verify/mint21; R=$H/results/2026-11-11-r5/manual; mkdir -p "$R"
boot() {
    docker rm -f "$1" >/dev/null 2>&1
    docker run -d --name "$1" --hostname mint-cptest --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock "$2" /sbin/init >/dev/null
    for i in $(seq 1 60); do st=$(docker exec "$1" systemctl is-system-running 2>/dev/null); case "$st" in running|degraded) break;; esac; sleep 1; done
    "$H/restore-acls.sh" "$1" "$2" >/dev/null 2>&1
    docker exec "$1" bash -c 'rm -rf /root/competition; mkdir -p /root/harness /root/logs' 2>/dev/null
    docker cp -q /home/claude/work/competition "$1:/root/competition"
    for f in drive2.py mintchecks.py checks_cp.py 1984-scoring.json svccheck.sh fakebin; do docker cp -q "$H/$f" "$1:/root/harness/"; done
    docker cp -q /home/claude/V/forensics_probe.py "$1:/root/harness/"
}
drv() {  # drv C JSON LOG SUDOUSER CMD...
    local c="$1" rj="$2" ln="$3" su="$4"; shift 4
    docker exec -e RULES="$(cat "$rj")" -e SUDO_USER="$su" -e TERM=xterm -e PAGER=cat -e IDLE=2.5 -e HARD=1800 \
        -e PATH="/root/harness/fakebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" -w /root/competition "$c" \
        python3 /root/harness/drive2.py "/root/logs/$ln.log" -- "$@" >/dev/null 2>&1
    docker cp -q "$c:/root/logs/$ln.log" "$R/"; docker cp -q "$c:/root/logs/$ln.log.answers" "$R/"
}
X() { docker exec "$1" bash -c "$2" 2>&1 | grep -v 'cannot be preloaded'; }

# A: forensics first, nothing changed before it (both images)
for img in planted svcplanted; do
    boot V5-fp cp-mint-$img; sleep 30
    X V5-fp 'python3 /root/harness/forensics_probe.py' > "$R/forensics-probe-$img.txt"
    docker rm -f V5-fp >/dev/null
done
echo "A done"
# B: each script on its own with an EMPTY /root/cp-state (planted image; README pasted into usersandsudo)
boot V5-empty cp-mint-planted; sleep 60
for s in usersandsudo.sh systemconfig.sh fileandpackage.sh services/critical.sh; do
    n="empty-$(basename $s .sh)"
    X V5-empty 'rm -rf /root/cp-state' >/dev/null
    drv V5-empty /home/claude/V/r5-empty-planted.json "$n" cpuser bash $s
done
X V5-empty 'sysctl --system >/dev/null 2>&1; python3 /root/harness/mintchecks.py empty | tail -1; bash /root/harness/svccheck.sh' > "$R/empty-score.txt"
docker rm -f V5-empty >/dev/null
echo "B done"
# C: real Debian 12 README pasted into usersandsudo inside speedrun.sh (cp-jammy-base + B's plant, os-release not faked)
boot V5-deb12 cp-jammy-base
docker cp -q /home/claude/V/b-plant-deb12-noos.sh V5-deb12:/root/plant.sh; docker cp -q /home/claude/notes/B-tests/b-check-deb12.sh V5-deb12:/root/check.sh
X V5-deb12 'bash /root/plant.sh' > "$R/deb12-plant.txt"
drv V5-deb12 /home/claude/V/r5-deb12-speedrun.json deb12-speedrun pparker bash speedrun.sh
X V5-deb12 'bash /root/check.sh; tail -5 /root/logs/deb12-speedrun.log | sed "s/\x1b\[[0-9;]*m//g"' > "$R/deb12-check.txt"
docker rm -f V5-deb12 >/dev/null
echo "C done"
