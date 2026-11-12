#!/bin/bash
H=/home/claude/work/tools/verify/mint21; R=$H/results/2026-11-11-r5; NEW=/home/claude/work/competition
cd "$H"
run() {  # run NAME IMAGE RULES [env...]
    local name="$1" img="$2" rules="$3"; shift 3
    echo "[$(date +%T)] start $name"
    env "$@" NAME="V5-$name" KEEP=1 ./run-pipeline.sh "$img" "$NEW" "$rules" "$R/$name" > "$R/$name.out" 2>&1
    docker cp -q /home/claude/V/postcheck.sh "V5-$name:/root/postcheck.sh" 2>/dev/null && \
        docker exec "V5-$name" bash /root/postcheck.sh 2>&1 | grep -v 'cannot be preloaded' > "$R/$name/postcheck.txt"
    docker exec "V5-$name" bash -c 'ls -l /usr/src/evil_rabbit.so 2>&1; chage -l ftpuser 2>/dev/null | head -2; cat /root/cp-state/readme.conf 2>/dev/null' > "$R/$name/extra.txt" 2>&1
    docker rm -f "V5-$name" >/dev/null 2>&1
    echo "[$(date +%T)] done  $name: $(grep -E '^checks|^services' "$R/$name/summary.txt" | tr '\n' ' ')"
}
run modular-planted   cp-mint-planted    rules-2026-11-11-V5-modular-planted.txt
run speedrun-planted  cp-mint-planted    rules-2026-11-11-V5-speedrun-planted.txt
run modular-svc       cp-mint-svcplanted rules-2026-11-11-V5-modular-svc.txt
run speedrun-svc      cp-mint-svcplanted rules-2026-11-11-V5-speedrun-svc.txt
for i in clean services planted; do run baseline-$i cp-mint-$i rules-baseline-only.txt NOSCORE=1; done
echo "[$(date +%T)] ALL DONE"
