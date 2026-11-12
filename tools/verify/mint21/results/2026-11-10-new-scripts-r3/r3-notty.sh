#!/bin/bash
# V: no-TTY safety test. Fresh cp-mint-planted container, NO README answers, every entry point run with </dev/null.
H=/home/claude/work/tools/verify/mint21; OUT=$H/results/2026-11-10-new-scripts-r3/notty-planted; mkdir -p "$OUT"
C=V-notty; docker rm -f $C >/dev/null 2>&1
docker run -d --name $C --hostname mint-cptest --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock cp-mint-planted /sbin/init >/dev/null
for i in $(seq 1 60); do st=$(docker exec $C systemctl is-system-running 2>/dev/null); case "$st" in running|degraded) break;; esac; sleep 1; done
"$H/restore-acls.sh" $C cp-mint-planted >/dev/null
docker exec $C bash -c 'rm -rf /root/competition; mkdir -p /root/harness /root/logs' 2>/dev/null
docker cp -q /home/claude/work/competition $C:/root/competition
for f in mintchecks.py checks_cp.py 1984-scoring.json svccheck.sh; do docker cp -q "$H/$f" $C:/root/harness/; done
docker cp -q /home/claude/V/postcheck.sh $C:/root/postcheck.sh
X() { docker exec -e SUDO_USER=cpuser -w /root/competition $C bash -c "$1" 2>&1 | grep -v 'cannot be preloaded'; }
snap() { X 'echo "users: $(awk -F: "\$3>=1000&&\$3<65534{printf \"%s \",\$1}" /etc/passwd)| toor: $(getent passwd toor | cut -d: -f1)"; echo "pkgs: $(dpkg-query -W -f="\${db:Status-Abbrev}\${Package} " john hydra nmap wireshark openssh-server vsftpd apache2 2>/dev/null)"; echo "media: $(ls /home/bob/Music/never_gonna.mp3 /home/carol/Videos/movie.mp4 2>/dev/null | wc -l)/2 ssh=$(systemctl is-active ssh) ufw=$(ufw status | head -1) readme.conf: $(tr "\n" " " < /root/cp-state/readme.conf 2>/dev/null)"'; }
{
echo "### before"; snap
for cmd in "bash start.sh" "sleep 20; bash start.sh --status" "bash readme.sh" "bash services/baseline.sh --review" "bash usersandsudo.sh" \
           "bash systemconfig.sh" "bash fileandpackage.sh" "bash portandmisc.sh" "bash services/ssh.sh" "bash services/critical.sh"; do
    echo; echo "################ $cmd </dev/null"
    t0=$(date +%s); X "$cmd </dev/null; echo \"[exit \$?]\"" > "$OUT/$(echo "$cmd" | tr -c 'A-Za-z0-9.' '_').log"
    tail -4 "$OUT/$(echo "$cmd" | tr -c 'A-Za-z0-9.' '_').log"; echo "($(( $(date +%s) - t0 )) s)"; snap
done
echo; echo "### path with spaces (detection-only entry points)"
X 'mkdir -p "/root/CP stuff" && cp -a /root/competition "/root/CP stuff/" && cd "/root/CP stuff/competition" && for c in "services/baseline.sh ssh" "fileandpackage.sh --scan" "portandmisc.sh --scan" "start.sh --status" "readme.sh --show"; do echo "-- $c"; bash $c </dev/null 2>&1 | grep -iE "No such file|not found|syntax error|cannot|ERROR" | grep -v preload | head -3; echo "   exit ${PIPESTATUS[0]}"; done'
echo; echo "### TODO"; X 'cat /root/cp-state/TODO.txt'
echo; echo "### score"; X 'sysctl --system >/dev/null 2>&1; python3 /root/harness/mintchecks.py notty | tail -1; bash /root/harness/svccheck.sh'
echo; echo "### postcheck"; X 'bash /root/postcheck.sh'
} > "$OUT/notty.txt" 2>&1
echo done
