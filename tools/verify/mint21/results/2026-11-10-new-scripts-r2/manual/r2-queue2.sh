#!/bin/bash
L=/home/claude/work/tools/verify/mint21/results/2026-11-10-new-scripts-r2
while ! grep -q 'ALL DONE' $L/runall.log; do sleep 10; done
H=/home/claude/work/tools/verify/mint21; cd $H
echo "[$(date +%T)] start svcnone"
NAME=V2-svcnone KEEP=1 ./run-pipeline.sh cp-mint-planted /home/claude/work/competition rules-2026-11-10-new-r2-start-svcnone.txt $L/start-svcnone > $L/start-svcnone.out 2>&1
docker cp -q /home/claude/V/postcheck.sh V2-svcnone:/root/postcheck.sh; docker exec V2-svcnone bash /root/postcheck.sh 2>&1 | grep -v 'cannot be preloaded' > $L/start-svcnone/postcheck.txt
docker exec V2-svcnone bash -c 'dpkg -l openssh-server | tail -1; systemctl is-active ssh; systemctl is-enabled ssh; ufw status' > $L/start-svcnone/extra.txt 2>&1
docker rm -f V2-svcnone >/dev/null
echo "[$(date +%T)] done svcnone: $(grep -E '^checks|^services' $L/start-svcnone/summary.txt | tr '\n' ' ')"
echo "[$(date +%T)] start manual"; /home/claude/V/r2-manual.sh; echo "[$(date +%T)] done manual"
echo "[$(date +%T)] start notty"; /home/claude/V/r2-notty.sh; echo "[$(date +%T)] done notty"
echo "[$(date +%T)] QUEUE2 DONE"
