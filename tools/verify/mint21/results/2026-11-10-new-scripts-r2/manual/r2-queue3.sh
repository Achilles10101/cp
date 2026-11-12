#!/bin/bash
L=/home/claude/work/tools/verify/mint21/results/2026-11-10-new-scripts-r2
while ! grep -q 'QUEUE2 DONE' $L/queue2.log 2>/dev/null; do sleep 10; done
H=/home/claude/work/tools/verify/mint21; cd $H
echo "[$(date +%T)] start old-planted (same post-reboot conditions)"
NAME=V2-old NOSCORE=0 ./run-pipeline.sh cp-mint-planted /home/claude/orig/competition rules-2026-10-21.txt $L/old-planted > $L/old-planted.out 2>&1
echo "[$(date +%T)] done old: $(grep -E '^checks|^TOTAL' $L/old-planted/summary.txt | tr '\n' ' ')"
echo "[$(date +%T)] start start-planted-rep (timing repeat, warm caches)"
NAME=V2-rep ./run-pipeline.sh cp-mint-planted /home/claude/work/competition rules-2026-11-10-new-r2-start.txt $L/start-planted-rep > $L/start-planted-rep.out 2>&1
echo "[$(date +%T)] done rep: $(grep -E '^checks|^TOTAL' $L/start-planted-rep/summary.txt | tr '\n' ' ')"
echo "[$(date +%T)] QUEUE3 DONE"
