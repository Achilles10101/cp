#!/bin/bash
# V round 2 manual tests: B2 paste through start.sh, readme "none" path, S1 human typing, S3 critical.sh on a TTY.
H=/home/claude/work/tools/verify/mint21; R=$H/results/2026-11-10-new-scripts-r2/manual; mkdir -p "$R"
boot() {  # boot NAME IMAGE
    docker rm -f "$1" >/dev/null 2>&1
    docker run -d --name "$1" --hostname mint-cptest --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock "$2" /sbin/init >/dev/null
    for i in $(seq 1 60); do st=$(docker exec "$1" systemctl is-system-running 2>/dev/null); case "$st" in running|degraded) break;; esac; sleep 1; done
    "$H/restore-acls.sh" "$1" "$2" >/dev/null
    docker exec "$1" bash -c 'rm -rf /root/competition; mkdir -p /root/harness /root/logs' 2>/dev/null
    docker cp -q /home/claude/work/competition "$1:/root/competition"
    for f in drive2.py mintchecks.py checks_cp.py 1984-scoring.json svccheck.sh fakebin; do docker cp -q "$H/$f" "$1:/root/harness/"; done
    docker cp -q /home/claude/V/drive_human.py "$1:/root/harness/"; docker cp -q /home/claude/V/paste "$1:/root/harness/"
}
drv() {  # drv CONTAINER RULESJSON LOGNAME DRIVER CMD...
    local c="$1" rj="$2" ln="$3" d="$4"; shift 4
    docker exec -e RULES="$(cat "$rj")" -e SUDO_USER=cpuser -e TERM=xterm -e PAGER=cat -e IDLE=2.5 -e HARD=900 -e KEYGAP=0.25 \
        -e PATH="/root/harness/fakebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" -w /root/competition "$c" \
        python3 "/root/harness/$d" "/root/logs/$ln.log" -- "$@" >/dev/null 2>&1
    docker cp -q "$c:/root/logs/$ln.log" "$R/" ; docker cp -q "$c:/root/logs/$ln.log.answers" "$R/"
}
X() { docker exec "$1" bash -c "$2" 2>&1 | grep -v 'cannot be preloaded'; }

# --- A: B2, user-section-only paste, whole round through start.sh (Enter at the services question first)
boot V2-paste cp-mint-planted; sleep 60
drv V2-paste /home/claude/V/paste/r2-users-fullround.json b2-fullround drive2.py bash start.sh
{ echo "### B2 full round (user-section paste)"; grep -E 'Critical services|Correct|Remove all|Remove these too|SSH server|STATS' "$R/b2-fullround.log.answers"
  X V2-paste 'bash /root/competition/readme.sh --show; sysctl --system >/dev/null 2>&1; python3 /root/harness/mintchecks.py b2 | tail -1; python3 /root/harness/mintchecks.py b2 | grep -E "OpenSSH|LD_PRELOAD|Desktop"; bash /root/harness/svccheck.sh; dpkg -l openssh-server | tail -1
    echo "--- README passwords on disk:"; grep -rlsE "Alic3-Adm1n|Cyb3rP@triot" /root/cp-state /root/cp-backups /root/baseline /tmp /var/tmp /var/log || echo none
    echo "--- readme.log:"; cat /root/cp-state/logs/readme.log'
} > "$R/b2-fullround.txt"
docker rm -f V2-paste >/dev/null

# --- B: readme.sh alone: typed "none" + Enter at the confirm; then the whole page
boot V2-readme cp-mint-planted
drv V2-readme /home/claude/V/paste/r2-users-none.json b2-none drive2.py bash readme.sh
{ echo "### typed none"; cat "$R/b2-none.log.answers"; X V2-readme 'bash /root/competition/readme.sh --show; rm -rf /root/cp-state'; } > "$R/b2-readme.txt"
drv V2-readme /home/claude/V/paste/r2-whole.json b2-whole drive2.py bash readme.sh
{ echo "### whole page"; cat "$R/b2-whole.log.answers"; X V2-readme 'bash /root/competition/readme.sh --show'; } >> "$R/b2-readme.txt"
docker rm -f V2-readme >/dev/null

# --- C: S1 human typing (s + 0.25 s + Enter for every finding, y to the REVIEW question), S3 critical.sh on a TTY
boot V2-human cp-mint-planted; sleep 60
X V2-human 'cd /root/competition && bash services/baseline.sh >/dev/null 2>&1; grep -m1 "FIX NOW:" /root/baseline/FINDINGS.txt' > "$R/s1-human.txt"
echo '[["Also go through the \\d+ REVIEW item","y"],["d=show|d=diff","s"]]' > /tmp/V-s1.json
drv V2-human /tmp/V-s1.json s1-human drive_human.py bash services/baseline.sh --review
{ cat "$R/s1-human.log.answers"; sed 's/\x1b\[[0-9;]*[A-Za-z]//g' "$R/s1-human.log" | grep -E 'Triage done|quarantined|Enter='; X V2-human 'cat /root/cp-quarantine/INDEX.txt 2>/dev/null || echo "no quarantine"'; } >> "$R/s1-human.txt"
echo '[["Run readme.sh now","n"],["Critical services listed in the README","SEQ:,,"]]' > /tmp/V-s3.json
drv V2-human /tmp/V-s3.json s3-critical drive2.py bash services/critical.sh
{ echo "### S3 critical.sh on a TTY, Enter x3"; cat "$R/s3-critical.log.answers"; X V2-human 'echo "readme.conf: $(cat /root/cp-state/readme.conf 2>/dev/null)"; grep critical.sh /root/cp-state/TODO.txt'; } > "$R/s3-critical.txt"
docker rm -f V2-human >/dev/null
echo manual-done
