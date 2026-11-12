#!/bin/bash
# V round 2: all harness scenarios, sequentially. Postcheck in each kept container, then remove it.
H=/home/claude/work/tools/verify/mint21; R=$H/results/2026-11-10-new-scripts-r2; NEW=/home/claude/work/competition
cd "$H"
run() {  # run NAME IMAGE RULES [env...]
    local name="$1" img="$2" rules="$3"; shift 3
    echo "[$(date +%T)] start $name"
    env "$@" NAME="V2-$name" KEEP=1 ./run-pipeline.sh "$img" "$NEW" "$rules" "$R/$name" > "$R/$name.out" 2>&1
    docker cp -q /home/claude/V/postcheck.sh "V2-$name:/root/postcheck.sh" 2>/dev/null && \
        docker exec "V2-$name" bash /root/postcheck.sh 2>&1 | grep -v 'cannot be preloaded' > "$R/$name/postcheck.txt"
    docker exec "V2-$name" bash -c 'ls -l /usr/src/evil_rabbit.so 2>&1; chage -l ftpuser 2>/dev/null | head -2; cat /root/cp-state/readme.conf 2>/dev/null' > "$R/$name/extra.txt" 2>&1
    docker rm -f "V2-$name" >/dev/null 2>&1
    echo "[$(date +%T)] done  $name: $(grep -E '^checks|^services' "$R/$name/summary.txt" | tr '\n' ' ')"
}
run start-planted          cp-mint-planted    rules-2026-11-10-new-r2-start.txt
run start-enterreview      cp-mint-planted    rules-2026-11-10-new-r2-start-enterreview.txt
run standalone-planted     cp-mint-planted    rules-2026-11-10-new-r2-standalone.txt
run svc-l4l                cp-mint-svcplanted rules-2026-11-10-new-r2-svc.txt
run svc-start              cp-mint-svcplanted rules-2026-11-10-new-r2-svc-start.txt
for i in clean services planted; do run baseline-$i cp-mint-$i rules-baseline-only.txt NOSCORE=1; done
run review-enter-planted   cp-mint-planted    rules-2026-11-10-new-r2-review-enter.txt
run clean                  cp-mint-clean      rules-2026-11-10-new-r2-clean.txt
echo "[$(date +%T)] ALL DONE"
