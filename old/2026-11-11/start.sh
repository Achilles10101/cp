#!/bin/bash
# start.sh - THE entry point for a CyberPatriot Linux round. From inside competition/:
#
#     sudo bash start.sh            run the whole round, straight through
#     sudo bash start.sh --reset    forget which steps are done (README answers, TODO list and logs are kept)
#
# What it does, in order (no menu - the only stops are the scripts' own questions):
#   1. Starts the slow work in the background (logs: /root/cp-state/logs/bg-*.log):
#        apt-get update, then a DOWNLOAD-ONLY run of every upgrade into /var/cache/apt/cp-upgrades/ (its own
#        folder, so it never holds the lock the scripts' apt-get calls need), and the baseline scan.
#   2. README intake (readme.sh --if-missing; not logged - the paste contains passwords).
#   3. Forensics reminder + the EARLY MANUAL list, then ONE pause ("Press Enter to continue"):
#      forensics must happen before anything changes.
#   4. Baseline review, usersandsudo, systemconfig, fileandpackage, portandmisc, critical.sh, upgrades (one
#      y/N, installs in the background keeping your config files), then the LATE MANUAL list, the TODO
#      list and a one-line summary. Steps that change the system wait for the baseline scan; the apt steps
#      wait for the background apt-get update (plain live counter).
# Always CP_AUTO=1. Each step's output: /root/cp-state/logs/<step>.log. Before each script step the scoring
# report is snapshotted (cp_screenshot_prompt). Resumable: finished steps are skipped on a re-run; Ctrl-C
# stops the run and the interrupted step stays undone. Every script still works on its own.

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
HERE="$(dirname "$SELF")"
# shellcheck disable=SC2034  # used by cp-common.sh (cp_todo tag)
CP_SCRIPT_NAME=start.sh
# shellcheck source=cp-common.sh
source "$HERE/cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found next to start.sh"; exit 1; }
cp_require_root
cd "$HERE" || exit 1

ST="$CP_STATE_DIR/start"
JOBS="$ST/jobs"
LOGS="$CP_STATE_DIR/logs"
UPG_DIR=/var/cache/apt/cp-upgrades
CHECKLIST="$HERE/CP Linux Checklist.txt"
mkdir -p "$JOBS" "$LOGS" && chmod 700 "$CP_STATE_DIR" "$ST" "$LOGS"

# ------------------------------------------------------------------ steps --
STEPS=(readme forensics review users system packages ports critical upgrades manual todo)
declare -A SNAME SCMD
SNAME[readme]="README intake";                 SCMD[readme]="readme.sh"
SNAME[forensics]="Forensics + EARLY MANUAL list"
SNAME[review]="Baseline review";               SCMD[review]="services/baseline.sh --review"
SNAME[users]="Users + sudo";                   SCMD[users]="usersandsudo.sh"
SNAME[system]="System config";                 SCMD[system]="systemconfig.sh"
SNAME[packages]="Packages + files";            SCMD[packages]="fileandpackage.sh"
SNAME[ports]="Ports";                          SCMD[ports]="portandmisc.sh"
SNAME[critical]="Critical services";           SCMD[critical]="services/critical.sh"
SNAME[upgrades]="Upgrades (install downloaded)"
SNAME[manual]="LATE MANUAL list"
SNAME[todo]="Final TODO list"
CHANGE_STEPS=" users system packages ports critical upgrades "   # wait for the baseline scan
APT_STEPS=" system packages ports critical upgrades "     # wait for the background apt-get update
SHOT_STEPS=" review users system packages ports critical "

# README intake only counts as done while the answers are saved (a failed/aborted intake must come back)
readme_ok() { [ -n "$(cp_cfg_get ADMINS)" ]; }
step_done() { [ -f "$ST/step.$1" ] && { [ "$1" != readme ] || readme_ok; }; }
step_set()  { echo "$2 $3 $(date +%s)" > "$ST/step.$1"; }        # rc|m  duration  epoch

fmt_dur() {
    local s="${1:-0}"
    if [ "$s" -ge 3600 ]; then printf '%dh%02dm' $((s / 3600)) $((s % 3600 / 60))
    elif [ "$s" -ge 60 ]; then printf '%dm%02ds' $((s / 60)) $((s % 60))
    else printf '%ds' "$s"; fi
}

# ---------------------------------------------------------- background jobs --
# Each job runs as `bash start.sh --job NAME` in its own session (survives quitting start.sh) and
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
            echo "[start.sh] apt lists are locked by another apt process - retrying in 5 s"; sleep 5; continue
        fi
        break
    done
    rm -f "$tmp"
    echo "$rc" > "$JOBS/apt.update_rc"
    [ "$rc" -eq 0 ] && date +%s > "$CP_STATE_DIR/apt-updated"   # scripts may skip their own apt-get update
    echo download > "$JOBS/apt.phase"
    mkdir -p "$UPG_DIR/partial"
    echo "[start.sh] downloading upgrades into $UPG_DIR (download only - nothing is installed)"
    LC_ALL=C /usr/bin/apt-get -q -d -y -o Dir::Cache::archives="$UPG_DIR/" full-upgrade; rc2=$?
    echo "[start.sh] $(ls "$UPG_DIR"/*.deb 2>/dev/null | wc -l) package files downloaded"
    [ "$rc" -eq 0 ] && return "$rc2"
    return "$rc"
}
job_baseline() {
    [ -f "$HERE/services/baseline.sh" ] || { echo "services/baseline.sh not found"; return 127; }
    CP_AUTO=1 bash "$HERE/services/baseline.sh"
}
job_upgrade() {
    local rc
    # keep every config file the scripts hardened (dpkg conffiles AND ucf-managed ones like sshd_config)
    DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l \
    UCF_FORCE_CONFFOLD=1 LC_ALL=C /usr/bin/apt-get -q -y -o DPkg::Lock::Timeout=600 -o Dir::Cache::archives="$UPG_DIR/" \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade
    rc=$?
    [ "$rc" -eq 0 ] && /usr/bin/apt-get -q -o Dir::Cache::archives="$UPG_DIR/" clean
    return "$rc"
}

if [ "${1:-}" = "--job" ]; then
    n="${2:-}"; echo $$ > "$JOBS/$n.pid"
    case "$n" in
        apt) job_apt ;; baseline) job_baseline ;; upgrade) job_upgrade ;;
        *) echo "unknown job $n"; false ;;
    esac
    rc=$?
    echo "$rc" > "$JOBS/$n.rc"; date +%s > "$JOBS/$n.end"
    exit "$rc"
fi

findings_count() {   # "FIX NOW n, REVIEW n" from FINDINGS.txt (baseline.sh), else the number of "!!" report lines
    local h; h="$(grep -m1 -oE 'FIX NOW: *[0-9]+ +REVIEW: *[0-9]+' "$CP_BASELINE_DIR/FINDINGS.txt" 2>/dev/null)"
    if [ -n "$h" ]; then echo "$h" | sed -E 's/FIX NOW: *([0-9]+) +REVIEW: *([0-9]+)/FIX NOW \1, REVIEW \2/'
    else echo "$(cat "$CP_BASELINE_DIR"/*/report.txt 2>/dev/null | grep -cE '^[[:space:]]*!!') !!"; fi
}
debs_count() { ls "$UPG_DIR"/*.deb 2>/dev/null | wc -l; }

job_text() {   # one short status phrase per job
    local n="$1" s t; s="$(job_state "$n")"; t="$(fmt_dur "$(job_secs "$n")")"
    case "$n:$s" in
        apt:running)   if [ "$(cat "$JOBS/apt.phase" 2>/dev/null)" = download ]; then echo "apt: update ok, downloading upgrades $t"
                       else echo "apt: apt-get update running $t"; fi ;;
        apt:done)      echo "apt: done $t" ;;
        apt:failed)    if [ -s "$JOBS/apt.note" ]; then echo "apt: $(cat "$JOBS/apt.note")"
                       else echo "apt: ${CP_C_RED}failed${CP_C_OFF} (log: $LOGS/bg-apt.log)"; fi ;;
        baseline:running) echo "baseline scan: running $t" ;;
        baseline:done) if [ -s "$JOBS/baseline.note" ]; then echo "baseline scan: done ($(cat "$JOBS/baseline.note"))"
                       else echo "baseline scan: done $t, $(findings_count)"; fi ;;
        baseline:failed) echo "baseline scan: ${CP_C_RED}failed${CP_C_OFF} (log: $LOGS/bg-baseline.log)" ;;
        upgrade:running) echo "upgrades: installing in the background $t (log: $LOGS/bg-upgrade.log)" ;;
        upgrade:done)  echo "upgrades: installed $t" ;;
        upgrade:failed) echo "upgrades: ${CP_C_RED}install failed${CP_C_OFF} (log: $LOGS/bg-upgrade.log)" ;;
        *)             echo "$n: $s" ;;
    esac
}

start_jobs() {   # start what has not run yet (or died, e.g. after a reboot)
    local s
    s="$(job_state apt)"
    if [ "$s" = none ] || [ "$s" = died ]; then job_spawn apt; fi
    s="$(job_state baseline)"
    if [ "$s" = none ] && ls "$CP_BASELINE_DIR"/*/report.txt >/dev/null 2>&1; then
        # baseline.sh already ran before start.sh (by hand) - a re-run now would compare a changed image
        date +%s > "$JOBS/baseline.start"; cp "$JOBS/baseline.start" "$JOBS/baseline.end"
        echo 0 > "$JOBS/baseline.rc"; echo "earlier run, $(findings_count)" > "$JOBS/baseline.note"
    elif [ "$s" = none ] || [ "$s" = died ]; then
        job_spawn baseline
    fi
}

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
run_script() {   # run_script ID FILE [ARGS...] -> 0 done (ticked), 1 not done, 130 interrupted
    local id="$1" f="$2"; shift
    local log="$LOGS/$id.log" t0 rc
    [ -f "$HERE/$f" ] || { cp_warn "$f is not in this folder - step skipped (copy the whole competition folder)"; return 1; }
    if [[ "$SHOT_STEPS" == *" $id "* ]]; then
        cp_screenshot_prompt "$id"
        echo "$id" > "$ST/shot-pending"   # the script's own cp_screenshot_prompt call is then skipped
    fi
    ( umask 077; : > "$log" )
    t0="$(date +%s)"
    INTERRUPTED=0; trap 'INTERRUPTED=1' INT
    export CP_AUTO=1 CP_START_STEP="$id" CP_SHOT_ASKED="$id" CP_FROM_START=1
    if [ "$id" = readme ]; then
        # NO transcript: the README paste contains the admin passwords (readme.sh keeps them in memory only)
        echo "README intake output is not logged (the paste contains passwords). Saved answers: sudo bash readme.sh --show" > "$log"
        cp_hdr "${SNAME[$id]}  (not logged: the README paste contains passwords)"
        if [ -t 0 ]; then bash "$@"; else bash "$@" < /dev/null; fi
        rc=$?
    elif [ -t 0 ] && command -v script >/dev/null 2>&1; then
        cp_hdr "${SNAME[$id]}  ($*)   log: $log"
        SHELL=/bin/bash script -qefc "$(printf '%q ' bash "$@")" "$log"; rc=$?
    else
        cp_hdr "${SNAME[$id]}  ($*)   log: $log"
        if [ -t 0 ]; then bash "$@" 2>&1 | tee "$log"; else bash "$@" < /dev/null 2>&1 | tee "$log"; fi
        rc="${PIPESTATUS[0]}"
    fi
    unset CP_START_STEP CP_SHOT_ASKED
    trap - INT
    rm -f "$ST/shot-pending"
    clean_log "$log"
    if [ "$INTERRUPTED" = 1 ] || [ "$rc" -eq 130 ] || [ "$rc" -gt 128 ]; then
        echo; cp_warn "${SNAME[$id]} was interrupted (exit $rc) - not done. Output so far: $log"; return 130
    fi
    if [ "$id" = readme ] && ! readme_ok; then
        echo; cp_warn "README answers were not saved (exit $rc) - run start.sh again."; return 1
    fi
    step_set "$id" "$rc" $(( $(date +%s) - t0 ))
    if [ "$rc" -eq 0 ]; then cp_ok "${SNAME[$id]} done in $(fmt_dur $(( $(date +%s) - t0 )))"
    else cp_warn "${SNAME[$id]} ended with exit $rc after $(fmt_dur $(( $(date +%s) - t0 ))) - check the end of $log"; fi
    return 0
}

print_section() {   # print_section NAME -> the checklist section "==== NAME (...) ====" without the dividers
    [ -f "$CHECKLIST" ] || { cp_warn "Checklist not found: $CHECKLIST"; return 1; }
    awk -v name="$1" -v b="$CP_C_CYN" -v o="$CP_C_OFF" '
        /^=+/ { insec = (index($0, "= " name) > 0); next }
        insec && /^\* / { print b $0 o; next }
        insec { print }' "$CHECKLIST" | sed 's/[[:space:]]*$//'
}

step_forensics() {   # the ONE start.sh pause: forensics before anything changes
    local f found=0 t0; t0="$(date +%s)"
    cp_hdr "Forensics questions - answer them BEFORE anything is removed or changed"
    for f in /home/*/Desktop/*[Ff]orensic* /root/Desktop/*[Ff]orensic*; do
        [ -e "$f" ] || continue
        found=1; cp_info "$f"
    done
    [ "$found" = 1 ] || cp_info "(no Forensics Question files found on any Desktop - check the README)"
    cp_hdr "EARLY MANUAL - from CP Linux Checklist.txt (copy the commands from the tracker or below)"
    print_section "EARLY MANUAL"
    echo
    [ -t 0 ] && read -r -p "  ? Forensics + early manual items done? Press Enter to continue " _
    step_set forensics m $(( $(date +%s) - t0 ))
}

step_review() {
    [ -f "$HERE/services/baseline.sh" ] || { cp_warn "services/baseline.sh is not in this folder - step skipped"; return 1; }
    case "$(job_state baseline)" in
        running) wait_job baseline "Waiting for the background baseline scan (the review needs its results)" ;;
        done) ;;
        *)  cp_warn "The background baseline scan did not finish - running it now (detection only; log: $LOGS/bg-baseline.log)"
            job_spawn baseline; wait_job baseline "Baseline scan" ;;
    esac
    run_script review services/baseline.sh --review
}

step_critical() {
    local s ran=0 rc
    if [ -f "$HERE/services/critical.sh" ]; then run_script critical services/critical.sh; return; fi
    cp_warn "services/critical.sh not found - running services/<name>.sh for each README critical service"
    for s in $(cp_cfg_get SERVICES); do
        [ "$s" = none ] && continue
        [ -f "$HERE/services/$s.sh" ] || { cp_warn "services/$s.sh not found"; continue; }
        run_script critical "services/$s.sh"; rc=$?; [ "$rc" = 130 ] && return 130; ran=1
    done
    [ "$ran" = 1 ] || { cp_info "No critical services to harden."; step_set critical 0 0; }
}

step_upgrades() {
    local sim n_inst n_rem def=y repos r bad=0 notable
    cp_hdr "${SNAME[upgrades]}"
    case "$(job_state apt):$(cat "$JOBS/apt.phase" 2>/dev/null)" in
        running:update) wait_job apt "Waiting for the background apt-get update" update ;;
        running:download)
            cp_info "The upgrade download is still running ($(debs_count) files so far) - stopping it; the install fetches the rest."
            job_stop apt "download stopped for the install ($(debs_count) files ready)" ;;
    esac
    if [ "$(cat "$JOBS/apt.update_rc" 2>/dev/null)" != 0 ]; then
        cp_warn "The background apt-get update did not succeed (log: $LOGS/bg-apt.log) - running it now."
        cp_info "Linux Mint: if it keeps failing, Update Manager -> Edit -> Software Sources -> restore the default settings, then refresh."
        LC_ALL=C /usr/bin/apt-get -q update 2>&1 | tail -n 5
    fi
    cp_info "Repositories apt uses (anything that is not Ubuntu/Mint/Canonical: check /etc/apt/sources.list*):"
    repos="$(LC_ALL=C /usr/bin/apt-cache policy 2>/dev/null | grep -oE '(https?|ftp|file|cdrom):[^ ]+' | sort -u)"
    for r in $repos; do
        if [[ "$r" =~ (ubuntu|linuxmint|canonical|debian) ]]; then echo "      $r"
        else echo "      ${CP_C_YEL}$r${CP_C_OFF}  <- check"; bad=1
             cp_todo "APT repository that is not Ubuntu/Mint: $r - check /etc/apt/sources.list(.d) (keep it only if the README needs it)"; fi
    done
    [ "$bad" = 1 ] && cp_warn "Upgrades from an unknown repository can install anything - check it before saying yes."
    sim="$(LC_ALL=C /usr/bin/apt-get -s -o Dir::Cache::archives="$UPG_DIR/" full-upgrade 2>&1)"
    n_inst="$(grep -c '^Inst ' <<<"$sim")"; n_rem="$(grep -c '^Remv ' <<<"$sim")"
    if [ "$n_inst" -eq 0 ] && [ "$n_rem" -eq 0 ]; then cp_ok "Nothing to upgrade."; step_set upgrades 0 0; return 0; fi
    notable="$(grep '^Inst ' <<<"$sim" | awk '{print $2}' | grep -E '^(bash|sudo|linux-image|linux-generic|firefox|libreoffice-core|thunderbird|openssh-server|openssl|apache2|nginx|vsftpd|mysql-server|mariadb-server|postgresql|samba|bind9|postfix|dovecot-core|php[0-9.]*|openvpn|squid|cinnamon|policykit-1|pkexec)' | head -12 | tr '\n' ' ')"
    cp_info "$n_inst package(s) to upgrade/install ($(debs_count) already downloaded)${notable:+ - includes: $notable}"
    if [ "$n_rem" -gt 0 ]; then cp_warn "It would also REMOVE: $(grep '^Remv ' <<<"$sim" | awk '{print $2}' | tr '\n' ' ')"; def=n; fi
    [[ "$(cp_os_id)" == linuxmint* ]] && cp_info "Linux Mint: Update Manager automation is done by systemconfig.sh - this installs the upgrades now."
    if cp_ask "Install them now in the background (keeps your config files; log: $LOGS/bg-upgrade.log)?" "$def"; then
        job_spawn upgrade; cp_ok "Installing in the background."
    else
        cp_info "Not installed (sudo bash start.sh --reset, or apt full-upgrade by hand, to install later)."
    fi
    step_set upgrades 0 0
}

step_late() {   # LATE MANUAL list + TODO list (printed, no pause)
    cp_hdr "LATE MANUAL - from CP Linux Checklist.txt"
    print_section "LATE MANUAL"
    step_set manual m 0
    cp_hdr "TODO - things only you can finish ($CP_TODO_FILE)"
    if [ -s "$CP_TODO_FILE" ]; then awk '{ printf "  %2d. %s\n", NR, $0 }' "$CP_TODO_FILE"; else cp_info "No TODO items."; fi
    step_set todo m 0
}

run_step() {   # -> 130 when interrupted
    local id="$1"
    [[ "$CHANGE_STEPS" == *" $id "* ]] && wait_job baseline "Waiting for the baseline scan (it must see the image before anything changes)"
    [[ "$APT_STEPS" == *" $id "* ]] && [ "$id" != upgrades ] && wait_job apt "Waiting for the background apt-get update (an apt-get update now would fail on its lock)" update
    case "$id" in
        readme)    if [ -f "$HERE/readme.sh" ]; then run_script readme readme.sh --if-missing
                   else cp_err "readme.sh is not in this folder - copy the whole competition folder"; return 1; fi ;;
        forensics) step_forensics ;;
        review)    step_review ;;
        critical)  step_critical ;;
        upgrades)  step_upgrades ;;
        manual)    step_late ;;
        todo)      : ;;
        *)         # shellcheck disable=SC2086
                   run_script "$id" ${SCMD[$id]} ;;
    esac
}

summary() {
    local id line=""
    for id in "${STEPS[@]}"; do
        step_done "$id" || continue
        case "$id" in manual|todo|forensics|readme|upgrades) continue ;; esac
        line+=" $id $(fmt_dur "$(awk '{print $2}' "$ST/step.$id")")"
    done
    echo
    cp_ok "Round $1 in $(fmt_dur $(( $(date +%s) - $(cat "$ST/t0") ))) |$line"
    if [ "$(job_state upgrade)" = running ]; then cp_info "$(job_text upgrade)"; fi
}

# -------------------------------------------------------------------- main --
case "${1:-}" in
    --reset)
        for j in apt baseline upgrade; do
            [ "$(job_state "$j")" = running ] && { cp_err "$j job still running - wait for it first"; exit 1; }
        done
        rm -rf "$ST"; cp_ok "start.sh state cleared (README answers, TODO list and logs kept)."; exit 0 ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    "") ;;
    *) echo "Unknown option $1 (see: bash start.sh --help)"; exit 1 ;;
esac

exec 9> "$ST/lock"
if ! flock -n 9; then echo "start.sh is already running in another terminal - use that one."; exit 1; fi
[ -f "$ST/t0" ] || date +%s > "$ST/t0"
if readme_ok && [ ! -f "$ST/step.readme" ]; then step_set readme m 0; fi   # README answers saved earlier
# an older start.sh logged the README step with `script` (pasted passwords in the transcript) - drop it
grep -qs "Script started" "$LOGS/readme.log" && rm -f "$LOGS/readme.log"

start_jobs
cp_ok "Background: $(job_text apt) | $(job_text baseline)"
done_list=""
for id in "${STEPS[@]}"; do step_done "$id" && done_list+="${done_list:+, }${SNAME[$id]}"; done
[ -n "$done_list" ] && cp_info "Already done, skipped: $done_list"
for id in "${STEPS[@]}"; do
    step_done "$id" && continue
    run_step "$id"; rc=$?
    if [ "$rc" = 130 ]; then summary "stopped (Ctrl-C) - run start.sh again to continue"; exit 130; fi
    if [ "$id" = readme ] && ! readme_ok; then exit 1; fi
done
summary "done"
exit 0
