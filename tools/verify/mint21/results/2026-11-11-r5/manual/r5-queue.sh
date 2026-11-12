#!/bin/bash
L=/home/claude/work/tools/verify/mint21/results/2026-11-11-r5
while ! grep -q 'ALL DONE' $L/runall.log; do sleep 10; done
echo "[$(date +%T)] manual"; /home/claude/V/r5-manual.sh
echo "[$(date +%T)] notty"; /home/claude/V/r5-notty.sh; docker rm -f V-notty >/dev/null 2>&1
echo "[$(date +%T)] QUEUE DONE"
