#!/bin/bash
H=/home/claude/work/tools/verify/mint21; R=$H/results/2026-11-10-new-scripts-r3; NEW=/home/claude/work/competition
cd "$H"
run() {  # run NAME IMAGE RULES [env...]
    local name="$1" img="$2" rules="$3"; shift 3
    echo "[$(date +%T)] start $name"
    env "$@" NAME="V3-$name" KEEP=1 ./run-pipeline.sh "$img" "$NEW" "$rules" "$R/$name" > "$R/$name.out" 2>&1
    docker cp -q /home/claude/V/postcheck.sh "V3-$name:/root/postcheck.sh" 2>/dev/null && \
        docker exec "V3-$name" bash /root/postcheck.sh 2>&1 | grep -v 'cannot be preloaded' > "$R/$name/postcheck.txt"
    docker exec "V3-$name" bash -c 'ls -l /usr/src/evil_rabbit.so 2>&1; chage -l ftpuser 2>/dev/null | head -2; cat /root/cp-state/readme.conf 2>/dev/null' > "$R/$name/extra.txt" 2>&1
    docker rm -f "V3-$name" >/dev/null 2>&1
    echo "[$(date +%T)] done  $name: $(grep -E '^checks|^services' "$R/$name/summary.txt" | tr '\n' ' ')"
}
run start-planted       cp-mint-planted    rules-2026-11-10-new-r3-start.txt
run start-enterreview   cp-mint-planted    rules-2026-11-10-new-r3-start-enterreview.txt
run svc-start           cp-mint-svcplanted rules-2026-11-10-new-r3-svc-start.txt
for i in clean services planted; do run baseline-$i cp-mint-$i rules-baseline-only.txt NOSCORE=1; done
run merge-planted       cp-mint-planted    rules-2026-11-10-new-r3-merge.txt
echo "[$(date +%T)] start notty"; sed 's#2026-11-10-new-scripts-r2/notty-planted#2026-11-10-new-scripts-r3/notty-planted#' /home/claude/V/r2-notty.sh > /home/claude/V/r3-notty.sh; chmod +x /home/claude/V/r3-notty.sh; /home/claude/V/r3-notty.sh; docker rm -f V-notty >/dev/null 2>&1
echo "[$(date +%T)] ALL DONE"
