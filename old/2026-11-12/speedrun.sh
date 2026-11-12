#!/bin/bash
# speedrun.sh - intro-round speedrun: the modular scripts one after another, nothing passed between them.
#
#     sudo bash speedrun.sh           (from inside competition/)
#     sudo bash speedrun.sh --reset   forget which steps are done (logs and the TODO list are kept)
#
#   1. Starts ONLY the read-only baseline scan in the background, then the first stop:
#      "Do the Forensics Questions now - nothing has been changed yet. Press Enter when done."
#   2. Starts apt-get update + a download-only run of the upgrades in the background
#      (/var/cache/apt/cp-upgrades/ - its own folder, so it never blocks the scripts' apt-get calls).
#   3. Runs usersandsudo.sh, services/baseline.sh --review, systemconfig.sh, fileandpackage.sh,
#      portandmisc.sh, services/critical.sh, upgrades.sh. Every script asks its own questions and takes its
#      own score snapshot. Changes wait for the baseline scan; the apt steps wait for the apt-get update.
#   4. Ends with the lockout-policy reminder (faillock, then nullok - checklist), the TODO list and the
#      time per step.
# Each step's output: /root/cp-state/logs/<step>.log (the users step is not logged: it may hold README
# passwords). Ctrl-C stops the run; run it again and finished steps are skipped.

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
HERE="$(dirname "$SELF")"
# shellcheck disable=SC2034  # used by cp-common.sh (cp_todo tag)
CP_SCRIPT_NAME=speedrun.sh
# shellcheck source=cp-common.sh
source "$HERE/cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found next to speedrun.sh"; exit 1; }
cp_require_root
cd "$HERE" || exit 1

ST="$CP_STATE_DIR/speedrun"
JOBS="$ST/jobs"
LOGS="$CP_STATE_DIR/logs"
UPG_DIR=/var/cache/apt/cp-upgrades
mkdir -p "$JOBS" "$LOGS" && chmod 700 "$CP_STATE_DIR" "$ST" "$LOGS"

STEPS=(forensics users review system packages ports critical upgrades)
declare -A SCMD=(
    [users]="usersandsudo.sh" [review]="services/baseline.sh --review" [system]="systemconfig.sh"
    [packages]="fileandpackage.sh" [ports]="portandmisc.sh" [critical]="services/critical.sh" [upgrades]="upgrades.sh" )
APT_STEPS=" system packages ports critical upgrades "   # wait for the background apt-get update

step_done() { [ -f "$ST/step.$1" ]; }
step_set()  { echo "$2 $3 $(date +%s)" > "$ST/step.$1"; }        # rc duration epoch
fmt_dur() {
    local s="${1:-0}"
    if [ "$s" -ge 3600 ]; then printf '%dh%02dm' $((s / 3600)) $((s % 3600 / 60))
    elif [ "$s" -ge 60 ]; then printf '%dm%02ds' $((s / 60)) $((s % 60))
    else printf '%ds' "$s"; fi
}

# ---------------------------------------------------------- background jobs --
# Each job runs as `bash speedrun.sh --job NAME` in its own session (survives quitting speedrun.sh) and
# leaves NAME.{start,pid,phase,rc,end} in $JOBS.
job_state() {   # none | running | done | failed | died
    local n="$1" pid
    [ -f "$JOBS/$n.start" ] || { echo none; return; }
    if [ -f "$JOBS/$n.end" ]; then
        if [ "$(cat "$JOBS/$n.rc" 2>/dev/null)" = 0 ]; then echo "done"; else echo failed; fi
        return
    fi
    pid="$(cat "$JOBS/$n.pid" 2>/dev/null)"
    if [ -n "$pid" ] && grep -qa -- "--job" "/proc/$pid/cmdline" 2>/dev/null; then echo running; else echo died; fi
}
job_secs() {
    local n="$1" s e
    s="$(cat "$JOBS/$n.start" 2>/dev/null)"; [ -n "$s" ] || { echo 0; return; }
    e="$(cat "$JOBS/$n.end" 2>/dev/null)"; [ -n "$e" ] || e="$(date +%s)"
    echo $(( e - s ))
}
job_spawn() {
    local n="$1"
    rm -f "$JOBS/$n".{end,rc,phase,pid,update_rc,note}
    date +%s > "$JOBS/$n.start"
    ( umask 077; : > "$LOGS/bg-$n.log" )
    if command -v setsid >/dev/null 2>&1; then
        setsid bash "$SELF" --job "$n" > "$LOGS/bg-$n.log" 2>&1 < /dev/null 9>&- &
    else
        nohup bash "$SELF" --job "$n" > "$LOGS/bg-$n.log" 2>&1 < /dev/null 9>&- &
    fi
    disown 2>/dev/null
    for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$JOBS/$n.pid" ] && break; sleep 0.1; done
}
job_stop() {   # stop a running job (its whole session), record it as stopped
    local n="$1" pid
    pid="$(cat "$JOBS/$n.pid" 2>/dev/null)"
    [ -n "$pid" ] && { kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null; }
    sleep 1
    echo 143 > "$JOBS/$n.rc"; echo "$2" > "$JOBS/$n.note"; date +%s > "$JOBS/$n.end"
}

job_apt() {
    local rc=1 rc2 tmp="$JOBS/apt.out"
    echo update > "$JOBS/apt.phase"
    for _ in $(seq 1 60); do      # apt-daily / mintupdate may hold the lists lock right after boot
        LC_ALL=C timeout 600 /usr/bin/apt-get -q update > "$tmp" 2>&1; rc=$?
        cat "$tmp"
        if [ "$rc" -ne 0 ] && grep -q 'Could not get lock' "$tmp"; then
            echo "[speedrun.sh] apt lists are locked by another apt process - retrying in 5 s"; sleep 5; continue
        fi
        break
    done
    rm -f "$tmp"
    echo "$rc" > "$JOBS/apt.update_rc"
    [ "$rc" -eq 0 ] && date +%s > "$CP_STATE_DIR/apt-updated"   # scripts may skip their own apt-get update
    echo download > "$JOBS/apt.phase"
    mkdir -p "$UPG_DIR/partial"
    echo "[speedrun.sh] downloading upgrades into $UPG_DIR (download only - nothing is installed)"
    LC_ALL=C /usr/bin/apt-get -q -d -y -o Dir::Cache::archives="$UPG_DIR/" full-upgrade; rc2=$?
    echo "[speedrun.sh] $(ls "$UPG_DIR"/*.deb 2>/dev/null | wc -l) package files downloaded"
    [ "$rc" -eq 0 ] && return "$rc2"
    return "$rc"
}
job_baseline() {
    [ -f "$HERE/services/baseline.sh" ] || { echo "services/baseline.sh not found"; return 127; }
    bash "$HERE/services/baseline.sh"
}

if [ "${1:-}" = "--job" ]; then
    n="${2:-}"; echo $$ > "$JOBS/$n.pid"
    case "$n" in
        apt) job_apt ;; baseline) job_baseline ;;
        *) echo "unknown job $n"; false ;;
    esac
    rc=$?
    echo "$rc" > "$JOBS/$n.rc"; date +%s > "$JOBS/$n.end"
    exit "$rc"
fi

debs_count() { ls "$UPG_DIR"/*.deb 2>/dev/null | wc -l; }


wait_job() {   # wait_job NAME TEXT [phase] - plain live counter until the job (phase) is over
    local n="$1" phase="${3:-}"
    busy() { [ "$(job_state "$n")" = running ] && { [ -z "$phase" ] || [ "$(cat "$JOBS/$n.phase" 2>/dev/null)" = "$phase" ]; }; }
    busy || return 0
    cp_info "$2"
    while busy; do
        [ -t 1 ] && printf '\r    %s: %s ...   ' "$n" "$(fmt_dur "$(job_secs "$n")")"
        sleep 1
    done
    [ -t 1 ] && printf '\r    %s finished after %s.          \n' "$n" "$(fmt_dur "$(job_secs "$n")")"
    return 0
}

clean_log() {   # strip colours/cursor codes so the log reads well with less/grep
    [ -f "$1" ] || return 0
    sed -i -E -e 's/\x1b\[[0-9;?]*[ -\/]*[@-~]//g' -e 's/\x1b\][^\x07]*\x07//g' -e 's/\x1b[()][A-Z0-9]//g' \
        -e 's/\x1b[=>]//g' -e 's/^.*\r([^\r])/\1/' -e 's/\r$//' "$1" 2>/dev/null
}

INTERRUPTED=0
run_step() {   # run_step ID -> 0 done, 1 skipped (script missing), 130 interrupted
    local id="$1" log="$LOGS/$1.log" t0 rc
    # shellcheck disable=SC2206
    local cmd=(${SCMD[$id]})
    [ -f "$HERE/${cmd[0]}" ] || { cp_warn "${cmd[0]} is not in this folder - step skipped"; return 1; }
    [ "$id" = review ] || wait_job baseline "Waiting for the baseline scan (it must see the image before anything changes)"
    [ "$id" = review ] && [ "$(job_state baseline)" != "done" ] && { cp_warn "The background baseline scan did not finish - running it again (detection only)"; job_spawn baseline; wait_job baseline "Baseline scan"; }
    [[ "$APT_STEPS" == *" $id "* ]] && wait_job apt "Waiting for the background apt-get update (an apt-get update now would fail on its lock)" update
    if [ "$id" = upgrades ] && [ "$(job_state apt)" = running ]; then   # upgrades.sh needs the download folder
        cp_info "Stopping the background upgrade download ($(debs_count) files so far) - upgrades.sh fetches the rest"
        job_stop apt "download stopped for upgrades.sh"
    fi
    ( umask 077; : > "$log" )
    t0="$(date +%s)"
    INTERRUPTED=0; trap 'INTERRUPTED=1' INT
    if [ "$id" = users ] || [ ! -t 0 ] || ! command -v script >/dev/null 2>&1; then
        # users: NOT logged - the README paste it may ask for contains passwords
        cp_hdr "${cmd[*]}   $([ "$id" = users ] && echo "(not logged: may contain README passwords)" || echo "log: $log")"
        [ "$id" = users ] && echo "not logged (may contain README passwords)" > "$log"
        if [ "$id" = users ]; then bash "${cmd[@]}"; rc=$?
        else bash "${cmd[@]}" < /dev/null 2>&1 | tee "$log"; rc="${PIPESTATUS[0]}"; fi
    else
        cp_hdr "${cmd[*]}   log: $log"
        SHELL=/bin/bash script -qefc "$(printf '%q ' bash "${cmd[@]}")" "$log"; rc=$?
    fi
    trap - INT
    clean_log "$log"
    if [ "$INTERRUPTED" = 1 ] || [ "$rc" -eq 130 ] || [ "$rc" -gt 128 ]; then
        echo; cp_warn "${cmd[0]} was interrupted (exit $rc) - not done"; return 130
    fi
    step_set "$id" "$rc" $(( $(date +%s) - t0 ))
    if [ "$rc" -eq 0 ]; then cp_ok "${cmd[0]} done in $(fmt_dur $(( $(date +%s) - t0 )))"
    else cp_warn "${cmd[0]} ended with exit $rc after $(fmt_dur $(( $(date +%s) - t0 ))) - check the end of its output"; fi
    return 0
}

summary() {
    local id line=""
    for id in "${STEPS[@]}"; do
        step_done "$id" && [ "$id" != forensics ] && line+=" $id $(fmt_dur "$(awk '{print $2}' "$ST/step.$id")")"
    done
    echo
    cp_ok "Speedrun $1 in $(fmt_dur $(( $(date +%s) - $(cat "$ST/t0") ))) |$line"
}

# -------------------------------------------------------------------- main --
case "${1:-}" in
    --reset)
        for j in apt baseline; do
            [ "$(job_state "$j")" = running ] && { cp_err "$j job still running - wait for it first"; exit 1; }
        done
        rm -rf "$ST"; cp_ok "speedrun.sh state cleared (logs and the TODO list kept)."; exit 0 ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    "") ;;
    *) echo "Unknown option $1 (see: bash speedrun.sh --help)"; exit 1 ;;
esac

if [ ! -t 0 ] || [ ! -t 1 ]; then
    cp_err "speedrun.sh needs a terminal: every script asks questions (README facts, y/N decisions). Run it in a terminal window."
    exit 1
fi
exec 9> "$ST/lock"
if ! flock -n 9; then echo "speedrun.sh is already running in another terminal - use that one."; exit 1; fi
[ -f "$ST/t0" ] || date +%s > "$ST/t0"

# 1. read-only baseline scan first (or keep a scan that already ran by hand)
s="$(job_state baseline)"
if [ "$s" = none ] && ls "$CP_BASELINE_DIR"/*/report.txt >/dev/null 2>&1; then
    date +%s > "$JOBS/baseline.start"; cp "$JOBS/baseline.start" "$JOBS/baseline.end"; echo 0 > "$JOBS/baseline.rc"
elif [ "$s" = none ] || [ "$s" = died ]; then
    job_spawn baseline; cp_info "Baseline scan started in the background (read-only, log: $LOGS/bg-baseline.log)"
fi
done_list=""
for id in "${STEPS[@]}"; do step_done "$id" && done_list+="${done_list:+, }$id"; done
[ -n "$done_list" ] && cp_info "Already done, skipped: $done_list"

# 2. forensics - before anything is changed
if ! step_done forensics; then
    t0="$(date +%s)"
    cp_hdr "Forensics"
    read -r -p "  ? Do the Forensics Questions now - nothing has been changed yet. Press Enter when done. " _
    step_set forensics 0 $(( $(date +%s) - t0 ))
fi

# 3. only now: apt-get update + upgrade download in the background
s="$(job_state apt)"
if ! step_done upgrades && { [ "$s" = none ] || [ "$s" = died ]; }; then
    job_spawn apt; cp_info "apt-get update + upgrade download started in the background (log: $LOGS/bg-apt.log)"
fi

# 4. the scripts, in order
for id in "${STEPS[@]}"; do
    step_done "$id" && continue
    run_step "$id"; rc=$?
    if [ "$rc" = 130 ]; then summary "stopped (Ctrl-C) - run speedrun.sh again to continue"; exit 130; fi
done

echo
cp_warn "LAST: set the lockout policy now - faillock, then nullok (checklist: LOCKOUT POLICY)."
cp_hdr "TODO - things only you can finish ($CP_TODO_FILE)"
if [ -s "$CP_TODO_FILE" ]; then awk '{ printf "  %2d. %s\n", NR, $0 }' "$CP_TODO_FILE"; else cp_info "No TODO items."; fi
summary "done"
exit 0
