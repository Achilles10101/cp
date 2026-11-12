#!/bin/bash
# run-pipeline.sh IMAGE COMPETITION_DIR RULES_FILE OUTDIR      (TEST HARNESS - runs on the host, scripts run in docker)
#
# Starts a fresh systemd container from IMAGE, copies COMPETITION_DIR to /root/competition, runs every step of
# RULES_FILE through drive2.py (pseudo-terminal, regex -> answer rules), times each step, then scores the result
# (mintchecks.py = checks_cp.py + planted-Mint checks), checks that services still answer (svccheck.sh), writes
# OUTDIR/summary.txt (+ summary.json, timings.tsv, score.txt, svccheck.txt, logs/) and removes the container.
#
# env: NAME=container name (default T-run-<pid>)   KEEP=1 keep the container afterwards
#      NOSCORE=1 skip mintchecks/svccheck          PACK=dir copied to competition/baseline/<basename> if missing there
#      DOCKER_RUN_OPTS=extra docker run options
#      RESYSCTL=0 do NOT re-apply the container's sysctl config before scoring (default 1: kernel.* values are global,
#                 shared by every privileged container on this host; another container booting resets e.g.
#                 kernel.kptr_restrict / randomize_va_space, which made 1984's two live-/proc checks flaky)
set -uo pipefail
[ $# -eq 4 ] || { sed -n '2,12p' "$0"; exit 2; }
IMAGE="$1"; COMP="$(cd "$2" && pwd)"; RULES="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"; OUT="$4"
H="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C="${NAME:-T-run-$$}"
mkdir -p "$OUT/logs" || exit 1; OUT="$(cd "$OUT" && pwd)"
PLAN="$OUT/plan.json"
python3 "$H/rules.py" "$RULES" > "$PLAN" || { echo "bad rules file"; exit 2; }
cp "$RULES" "$OUT/rules.txt"
# host may be macOS (colima): no /proc/loadavg, BSD date has no %N
now() { python3 -c 'import time; print("%.3f" % time.time())'; }
load() { cut -d' ' -f1 /proc/loadavg 2>/dev/null || docker exec "$C" cut -d' ' -f1 /proc/loadavg 2>/dev/null; }
log() { echo "[$(date +%T)] $*" | tee -a "$OUT/run.log"; }
cleanup() { [ "${KEEP:-0}" = 1 ] && { log "container kept: $C"; return; }; docker rm -f "$C" >/dev/null 2>&1; }
trap cleanup EXIT

# ---------------------------------------------------------------- container --
docker rm -f "$C" >/dev/null 2>&1
# shellcheck disable=SC2086
docker run -d --name "$C" --hostname "${HOSTNAME_C:-mint-cptest}" --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
    ${DOCKER_RUN_OPTS:-} "$IMAGE" /sbin/init >/dev/null || { echo "docker run failed"; exit 1; }
for _ in $(seq 1 60); do
    st="$(docker exec "$C" systemctl is-system-running 2>/dev/null)"; case "$st" in running|degraded) break ;; esac; sleep 1
done
log "container $C from $IMAGE: systemd $st"
r="$("$H/restore-acls.sh" "$C" "$IMAGE")"; [ -n "$r" ] && log "$r"   # docker commit drops POSIX ACLs (see build-images.sh)
# docker base-image apt files (docker-clean, docker-no-languages, ...) are not on a real image: the baseline would list them
docker exec "$C" bash -c 'rm -f /etc/apt/apt.conf.d/docker-*; rm -rf /root/competition /root/harness; mkdir -p /root/logs /root/harness'
docker cp -q "$COMP" "$C:/root/competition"
for f in drive2.py mintchecks.py checks_cp.py 1984-scoring.json svccheck.sh statedump.sh fakebin; do docker cp -q "$H/$f" "$C:/root/harness/"; done
if [ -n "${PACK:-}" ] && ! docker exec "$C" test -d "/root/competition/baseline/$(basename "$PACK")"; then
    docker exec "$C" mkdir -p /root/competition/baseline; docker cp -q "$PACK" "$C:/root/competition/baseline/"
fi
docker exec "$C" bash -c 'chown -R root:root /root/competition /root/harness'
echo -e "step\twall_s\tscript_elapsed_s\tharness_wait_s\tprompts\trule\tdefault\tstall\texit\tfindings\tload_start\tload_end\tfindings_detail" > "$OUT/timings.tsv"

findings() {  # findings STEP -> prints the count; details in findings-count-STEP.txt
    # new baseline.sh (2026-11): header of /root/baseline/FINDINGS.txt "FIX NOW: n   REVIEW: n   info: n" -> FIX NOW + REVIEW
    # old baseline.sh: number of "!!" lines in /root/baseline/*/report.txt (always recorded too, as bang=)
    docker exec "$C" bash -c 'for f in /root/baseline/*/report.txt; do [ -f "$f" ] || continue; echo "$(grep -c "^!!" "$f") $(basename "$(dirname "$f")")"; done
        h=$(grep -m1 "FIX NOW:" /root/baseline/FINDINGS.txt 2>/dev/null); [ -n "$h" ] && echo "HEADER $h"' > "$OUT/findings-count-$1.txt" 2>/dev/null
    docker exec "$C" bash -c 'cat /root/baseline/FINDINGS.txt 2>/dev/null' > "$OUT/FINDINGS-$1.txt"; [ -s "$OUT/FINDINGS-$1.txt" ] || rm -f "$OUT/FINDINGS-$1.txt"
    python3 - "$OUT/findings-count-$1.txt" <<'PY'
import re, sys
bang = 0; hdr = None
for l in open(sys.argv[1]):
    if l.startswith("HEADER "): hdr = l
    elif l.split() and l.split()[0].isdigit(): bang += int(l.split()[0])
if hdr:
    g = lambda k: int((re.search(k + r":\s*(\d+)", hdr, re.I) or [0, 0])[1])
    print(f"{g('FIX NOW') + g('REVIEW')}\tfix={g('FIX NOW')} review={g('REVIEW')} info={g('info')} bang={bang}")
else:
    print(f"{bang}\tbang={bang}")
PY
}

# ---------------------------------------------------------------- steps --
NSTEPS="$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["steps"]))' "$PLAN")"
T_ALL0=$(now)
for i in $(seq 0 $((NSTEPS - 1))); do
    # one step -> NAME, RULES json, settings, env (as docker -e args), command
    eval "$(python3 - "$PLAN" "$i" <<'PY'
import json, shlex, sys
st = json.load(open(sys.argv[1]))["steps"][int(sys.argv[2])]
s = st["set"]
print("S_NAME=%s" % shlex.quote(st["name"]))
print("S_RULES=%s" % shlex.quote(json.dumps(st["rules"])))
for k in ("IDLE", "HARD", "UMASK", "SUDO_USER", "DEBIAN_FRONTEND", "SSH_PORT", "FINDINGS"):
    print("S_%s=%s" % (k, shlex.quote(s[k])))
envargs = []
for k, v in st["env"].items():
    envargs += ["-e", "%s=%s" % (k, v)]
print("S_ENV=(%s)" % " ".join(shlex.quote(a) for a in envargs))
print("S_CMD=(%s)" % " ".join(shlex.quote(a) for a in st["cmd"]))
PY
)"
    SSH_PORT="$S_SSH_PORT"
    log "step $S_NAME: ${S_CMD[*]}"
    PRE=(); [ -n "$S_UMASK" ] && PRE=(bash -c "umask $S_UMASK; exec \"\$@\"" umask)
    l0="$(load)"; t0=$(now)
    docker exec -e RULES="$S_RULES" -e SUDO_USER="$S_SUDO_USER" -e TERM=xterm -e DEBIAN_FRONTEND="$S_DEBIAN_FRONTEND" \
        -e PAGER=cat -e SYSTEMD_PAGER= -e IDLE="$S_IDLE" -e HARD="$S_HARD" ${S_ENV[@]+"${S_ENV[@]}"} \
        -e PATH="/root/harness/fakebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" -w /root/competition "$C" \
        ${PRE[@]+"${PRE[@]}"} python3 /root/harness/drive2.py "/root/logs/$S_NAME.log" -- "${S_CMD[@]}"
    t1=$(now); l1="$(load)"
    docker cp -q "$C:/root/logs/$S_NAME.log" "$OUT/logs/" ; docker cp -q "$C:/root/logs/$S_NAME.log.answers" "$OUT/logs/"
    stats="$(grep '^STATS' "$OUT/logs/$S_NAME.log.answers" | tail -1)"; ex="$(grep '^EXIT' "$OUT/logs/$S_NAME.log.answers" | tail -1 | cut -d' ' -f2)"
    grep -q '^!!' "$OUT/logs/$S_NAME.log.answers" && log "  !! $(grep '^!!' "$OUT/logs/$S_NAME.log.answers")"
    kv() { echo "$stats" | tr ' ' '\n' | sed -n "s/^$1=//p" | tr -d s; }
    fnd="-"; fdet="-"; if [ "$S_FINDINGS" = 1 ]; then fl="$(findings "$S_NAME")"; fnd="${fl%%$'\t'*}"; fdet="${fl#*$'\t'}"; fi
    wall="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')"
    printf '%s\t%.1f\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$S_NAME" "$wall" "$(kv elapsed)" "$(kv wait)" "$(kv prompts)" "$(kv rule)" \
        "$(kv default)" "$(kv stall)" "${ex:-?}" "$fnd" "$l0" "$l1" "$fdet" >> "$OUT/timings.tsv"
    log "  done in ${wall%.*}s  $stats  exit=${ex:-?}  findings=$fnd ($fdet)"
done
T_ALL1=$(now)

# ---------------------------------------------------------------- scoring --
if [ "${NOSCORE:-0}" != 1 ]; then
    [ "${RESYSCTL:-1}" = 1 ] && docker exec "$C" sysctl --system >/dev/null 2>&1
    docker exec "$C" python3 /root/harness/mintchecks.py final > "$OUT/score.txt" 2>&1
    docker cp -q "$C:/root/logs/score-final.json" "$OUT/score.json" 2>/dev/null
    docker exec "$C" bash /root/harness/svccheck.sh "${SSH_PORT:-22}" > "$OUT/svccheck.txt" 2>&1
    docker exec "$C" bash -c 'cat /root/harness.log 2>/dev/null' > "$OUT/logs/harness.log"
    docker exec "$C" bash -c 'cat /root/cp-state/TODO.txt 2>/dev/null' > "$OUT/todo.txt"
    docker exec "$C" bash /root/harness/statedump.sh > "$OUT/state.txt" 2>/dev/null   # diff two runs' state.txt
fi

# ---------------------------------------------------------------- summary --
python3 - "$OUT" "$IMAGE" "$COMP" "$RULES" "$(awk -v a="$T_ALL0" -v b="$T_ALL1" 'BEGIN{printf "%.1f", b-a}')" <<'PY'
import csv, json, os, sys
out, image, comp, rules, total = sys.argv[1:6]
rows = list(csv.DictReader(open(os.path.join(out, "timings.tsv")), delimiter="\t"))
res = {"image": image, "competition": comp, "rules": rules, "steps": rows, "total_wall_s": round(float(total), 1)}
num = lambda k: sum(float(r[k]) for r in rows if r[k] not in ("", "-", "?"))
res["total_prompts"] = int(num("prompts")); res["total_harness_wait_s"] = round(num("harness_wait_s"), 1)
sj = os.path.join(out, "score.json")
if os.path.exists(sj):
    sc = json.load(open(sj))
    vals = [v[0] for v in sc.values()]
    pl = [v[0] for k, v in sc.items() if k.startswith("PLANTED-MINT|")]
    res["checks_pass"], res["checks_total"] = vals.count("PASS"), len(vals)
    res["planted_pass"], res["planted_total"] = pl.count("PASS"), len(pl)
sv = os.path.join(out, "svccheck.txt")
if os.path.exists(sv):
    lines = open(sv).read().splitlines()
    res["services_ok"] = [l.split()[1] for l in lines if l.startswith("  OK")]
    res["services_fail"] = [l.split()[1] for l in lines if l.startswith("  FAIL")]
f = [r for r in rows if r["findings"] not in ("-", "")]
if f: res["baseline_findings"] = int(f[-1]["findings"]); res["baseline_findings_detail"] = f[-1]["findings_detail"]
json.dump(res, open(os.path.join(out, "summary.json"), "w"), indent=1)
with open(os.path.join(out, "summary.txt"), "w") as o:
    o.write(f"image {image}\ncompetition {comp}\nrules {rules}\n\n")
    o.write(f"{'step':<16}{'wall s':>8}{'script s':>10}{'wait s':>8}{'net s':>8}{'prompts':>9}{'rule':>6}{'dflt':>6}{'stall':>6}{'exit':>6}{'findings':>9}{'load':>12}\n")
    for r in rows:
        try: net = f"{float(r['script_elapsed_s']) - float(r['harness_wait_s']):.1f}"
        except ValueError: net = "?"
        o.write(f"{r['step']:<16}{r['wall_s']:>8}{r['script_elapsed_s']:>10}{r['harness_wait_s']:>8}{net:>8}{r['prompts']:>9}{r['rule']:>6}{r['default']:>6}{r['stall']:>6}{r['exit']:>6}{r['findings']:>9}{r['load_start']+'>'+r['load_end']:>12}\n")
    o.write(f"{'TOTAL':<16}{res['total_wall_s']:>8}{'':>10}{res['total_harness_wait_s']:>8}{res['total_wall_s'] - res['total_harness_wait_s']:>8.1f}{res['total_prompts']:>9}\n\n")
    o.write("wall = host wall-clock for the step; script = drive2 elapsed; wait = seconds the harness waited for quiet output\n"
            "before answering (IDLE per prompt, 40 s per stall; stands in for the human reading + typing); net = script - wait\n"
            "(time the scripts themselves run). load = host 1-min loadavg at start>end (2 CPUs shared with other agents).\n\n")
    if "checks_total" in res:
        o.write(f"checks: {res['checks_pass']}/{res['checks_total']} PASS   planted: {res['planted_pass']}/{res['planted_total']} PASS\n")
    if "services_ok" in res:
        o.write(f"services answering: {len(res['services_ok'])} OK {' '.join(res['services_ok'])} | FAIL: {' '.join(res['services_fail']) or '-'}\n")
    if "baseline_findings" in res:
        o.write(f"baseline findings: {res['baseline_findings']}  ({res['baseline_findings_detail']}; new baseline.sh: FIX NOW + REVIEW from FINDINGS.txt, old: '!!' lines)\n")
print(open(os.path.join(out, "summary.txt")).read())
PY
