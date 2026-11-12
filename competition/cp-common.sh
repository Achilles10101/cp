#!/bin/bash
# cp-common.sh - shared helpers for the CP19 Linux scripts.
# Sourced by systemconfig.sh and every script in services/. Not meant to be run directly.
#
# Main ideas (from the research doc):
#   G1  edit settings IN PLACE and remove conflicting duplicates (never blind-append)
#   G2  functionally test a service after changing it
#   G3  use UFW application profiles when they exist
#   B-4 refuse to harden a service until it has been baselined (services/baseline.sh)

# Directory that contains this file (repo root) - works no matter where the caller lives.
CP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CP_BASELINE_DIR="${CP_BASELINE_DIR:-/root/baseline}"
CP_TS="$(date +%Y%m%d_%H%M%S)"

# Shared state that survives between scripts (README answers, TODO list, dpkg index).
# /root/cp-state/: readme.conf (each script's own remembered answers), dpkg-owned.idx,
#   logs/ + speedrun/ (speedrun.sh only), score.last. CP_SCORE_REPORT = scoring report path override.
# CP_BASELINE_JOBS = parallel baseline scans (default 3).
CP_STATE_DIR="${CP_STATE_DIR:-/root/cp-state}"
CP_CFG="$CP_STATE_DIR/readme.conf"
CP_SCRIPT_NAME="${CP_SCRIPT_NAME:-$(basename "${0:-cp}")}"

# ---------------------------------------------------------------- output --
# Colour only the tag, only on a terminal (logs and the test harness see plain text).
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    CP_C_RED=$'\e[1;31m'; CP_C_GRN=$'\e[1;32m'; CP_C_YEL=$'\e[1;33m'; CP_C_CYN=$'\e[1;36m'; CP_C_OFF=$'\e[0m'
else
    CP_C_RED=""; CP_C_GRN=""; CP_C_YEL=""; CP_C_CYN=""; CP_C_OFF=""
fi
cp_info() { echo "  [*] $*"; }
cp_ok()   { echo "  ${CP_C_GRN}[+]${CP_C_OFF} $*"; }
cp_warn() { echo "  ${CP_C_YEL}[!]${CP_C_OFF} $*"; }
cp_err()  { echo "  ${CP_C_RED}[x]${CP_C_OFF} $*" >&2; }
cp_hdr()  { echo; echo "${CP_C_CYN}=== $* ===${CP_C_OFF}"; }

# cp_todo "text" -> something the script found and LISTS for you to act on (a forbidden file, a README-only
# decision, a fix you declined). Printed immediately, and repeated in one list when the script exits so it
# can't scroll away. Nothing is kept after the script ends: the terminal output is the record.
CP_TODO_RUN="$(mktemp /tmp/cp-todo.XXXXXX 2>/dev/null)"
cp_todo() {
    echo "  ${CP_C_YEL}[act]${CP_C_OFF} $*"
    [ -n "$CP_TODO_RUN" ] && { grep -qxF -- "$*" "$CP_TODO_RUN" 2>/dev/null || echo "$*" >> "$CP_TODO_RUN"; }
}
cp_todo_recap() {   # runs on exit (trap below); scripts with their own EXIT trap call it from there
    [ -n "$CP_TODO_RUN" ] && [ -f "$CP_TODO_RUN" ] || return 0
    if [ -s "$CP_TODO_RUN" ]; then
        echo
        echo "${CP_C_YEL}=== $CP_SCRIPT_NAME finished - listed for you ($(wc -l < "$CP_TODO_RUN")): ===${CP_C_OFF}"
        awk '{ printf "  %2d. %s\n", NR, $0 }' "$CP_TODO_RUN"
    fi
    rm -f "$CP_TODO_RUN"
}
trap cp_todo_recap EXIT

# ------------------------------------------------- remembered answers --
# A script may remember ITS OWN answers for its own re-run ($CP_CFG, KEY=value lines). No script reads
# another script's keys: every script asks for the README facts it needs itself.
# Keys in use: US_* (usersandsudo.sh), SSH_* FTP_* APACHE_* PHP_* MYSQL_* PG_* SMB_* DNS_* MAIL_* WP_* VPN_*
# (service scripts; `services/<svc>.sh --reask` forgets that script's keys).
cp_cfg_get() { [ -f "$CP_CFG" ] && sed -n "s/^$1=//p" "$CP_CFG" | tail -1; }
cp_cfg_has() { [ -f "$CP_CFG" ] && grep -q "^$1=" "$CP_CFG"; }
cp_cfg_set() {
    local key="$1"; shift
    local val="$*" tmp
    mkdir -p "$CP_STATE_DIR" && chmod 700 "$CP_STATE_DIR"
    tmp="$(mktemp)"
    { [ -f "$CP_CFG" ] && grep -v "^$key=" "$CP_CFG"; echo "$key=$val"; } > "$tmp"
    cat "$tmp" > "$CP_CFG"; rm -f "$tmp"; chmod 600 "$CP_CFG"
}
# cp_apt ARGS... -> apt-get that waits for the dpkg/apt lock instead of failing (background jobs).
# Full path: a planted /usr/local/bin/apt-get (earlier in root's PATH) must never run.
# DPkg::Lock::Timeout only covers the dpkg lock: while another `apt-get update` (speedrun.sh's background job,
# apt-daily, mintupdate) rewrites the package lists, an install would read half-written lists, so wait for it.
cp_apt() {
    local n=0
    while pgrep -f '(^|/)apt-get( .*)? update' >/dev/null 2>&1 || pgrep -x apt.systemd.daily >/dev/null 2>&1; do
        # to the terminal: callers often send cp_apt's own output to /dev/null
        [ $n -eq 0 ] && { { cp_info "waiting for another apt update to finish (up to 5 min)..." > /dev/tty; } 2>/dev/null || cp_info "waiting for another apt update to finish (up to 5 min)..." >&2; }
        n=$((n + 1)); [ $n -ge 300 ] && break; sleep 1
    done
    /usr/bin/apt-get -o DPkg::Lock::Timeout=600 "$@"
}

# ----------------------------------------------------- dpkg ownership --
# dpkg-query -S re-reads every *.list file on each call (~0.1-0.3 s). Scripts that check hundreds of
# files use this index instead: built once from /var/lib/dpkg/info/*.list, usr-merge aware
# (/lib/x == /usr/lib/x, /bin == /usr/bin, /sbin == /usr/sbin), rebuilt when dpkg's database changes.
CP_OWNED_IDX="$CP_STATE_DIR/dpkg-owned.idx"
cp_owned_index() {
    if [ -s "$CP_OWNED_IDX" ] && [ "$CP_OWNED_IDX" -nt /var/lib/dpkg/status ]; then return 0; fi
    mkdir -p "$CP_STATE_DIR" && chmod 700 "$CP_STATE_DIR"
    cat /var/lib/dpkg/info/*.list 2>/dev/null | awk '
        { print }
        /^\/(lib|lib32|lib64|libx32|bin|sbin)\// { print "/usr" $0 }
        /^\/usr\/(lib|lib32|lib64|libx32|bin|sbin)\// { print substr($0, 5) }' \
        | LC_ALL=C sort -u > "$CP_OWNED_IDX.tmp" && mv -f "$CP_OWNED_IDX.tmp" "$CP_OWNED_IDX"
    unset CP_OWNED_LOADED
}
# cp_owned PATH -> 0 if some package ships PATH (any usr-merge spelling). Loads the index into memory once.
declare -gA CP_OWNED_MAP 2>/dev/null
cp_owned() {
    if [ -z "${CP_OWNED_LOADED:-}" ]; then
        cp_owned_index
        CP_OWNED_MAP=()
        local l; while IFS= read -r l; do CP_OWNED_MAP["$l"]=1; done < "$CP_OWNED_IDX"
        CP_OWNED_LOADED=1
    fi
    [ -n "${CP_OWNED_MAP["$1"]+x}" ]
}
# cp_unowned < paths  -> prints the paths (one per line) that NO package ships. One pass, for big lists.
cp_unowned() { cp_owned_index; awk 'NR == FNR { own[$0] = 1; next } !($0 in own)' "$CP_OWNED_IDX" -; }

# ---------------------------------------------------------------- basics --
cp_require_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        echo "ERROR: This script must be run as root (use sudo)"
        exit 1
    fi
}

# cp_screenshot_prompt [LABEL]   (owner: agent E) - called at the start of every script.
# The point of the per-script screenshot is knowing WHICH script cost points. The CCS scoring client
# (CCS) on CyberPatriot Linux images is installed in /opt/CyberPatriot and writes its report there as
# ScoringReport.html (CCS config: InstallPath /opt/CyberPatriot, HtmlReport ScoringReport). Also tried:
# other *Scor*Report*.html there, aeacus practice images (/opt/aeacus/assets/ScoringReport.html) and
# *Scor* desktop shortcuts (.desktop launchers are followed to their .html). When the report is found it is
# copied to /root/cp-backups/score-<label>-<time>.html and the score is printed together with the change
# since the previous snapshot - nothing is asked. A drop becomes a TODO. Without a report: ONE [Y/n]
# reminder (Enter = yes, never exits). One snapshot or reminder per script run. No terminal: nothing is asked.
#   cp_screenshot_prompt --score  -> one-line score summary (or nothing), no snapshot
#   CP_SCORE_REPORT=/path/file    -> use this report file instead of searching
cp_screenshot_prompt() {
    local label="${1:-${CP_SCRIPT_NAME%.sh}}" rep="" f d txt score="" gain="" loss="" summary="" age last ts dst
    for f in "${CP_SCORE_REPORT:-}" /opt/CyberPatriot/ScoringReport.html \
             /opt/[Cc]yber[Pp]atriot/*[Ss]cor*[Rr]eport*.htm* /opt/aeacus/assets/ScoringReport.html; do
        if [ -n "$f" ] && [ -f "$f" ]; then rep="$f"; break; fi
    done
    if [ -z "$rep" ]; then   # desktop shortcut (.desktop launcher or a copy of the report)
        for f in /home/*/Desktop/*[Ss]cor* /root/Desktop/*[Ss]cor*; do
            [ -f "$f" ] || continue
            case "$f" in
                *.desktop) d="$(grep -m1 -oE '(file://)?/[^"'\'' ]+\.html?' "$f" 2>/dev/null)"; d="${d#file://}"
                           if [ -n "$d" ] && [ -f "$d" ]; then rep="$d"; break; fi ;;
                *.htm|*.html) rep="$f"; break ;;
            esac
        done
    fi
    if [ -n "$rep" ]; then
        txt="$(tr '\r\n' '  ' < "$rep" 2>/dev/null | sed -e 's/<[^>]*>/\n/g' | sed -e 's/&nbsp;/ /g; s/&amp;/\&/g; s/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$')"
        # aeacus-style "N out of M points received"; CCS "x out of y scored security issues fixed, for a
        # gain of G points" / "n penalties assessed, for a loss of L points"; else any "score ... N"
        score="$(sed -nE 's/^([0-9]+) out of [0-9]+ points received.*/\1/p' <<<"$txt" | head -1)"
        gain="$(sed -nE 's/.*for a gain of (-?[0-9]+) point.*/\1/p' <<<"$txt" | head -1)"
        loss="$(sed -nE 's/.*for a loss of (-?[0-9]+) point.*/\1/p' <<<"$txt" | head -1)"
        [ -z "$score" ] && [ -n "$gain" ] && score=$(( gain - ${loss:-0} ))
        [ -z "$score" ] && score="$(grep -iE 'score' <<<"$txt" | grep -viE 'scoring' | grep -m1 -oE '[0-9]+' | head -1)"
        summary="$(grep -iE 'issues fixed|penalties assessed' <<<"$txt" | sed 's/:$//' | paste -sd ';' - | sed 's/;/; /g')"
        age=$(( $(date +%s) - $(stat -c %Y "$rep" 2>/dev/null || date +%s) ))
        if [ "$age" -ge 120 ]; then age="$(( age / 60 ))m"; else age="${age}s"; fi
        if [ "$label" = "--score" ]; then
            if [ -n "$score" ]; then echo "$score pts (report ${age} old)"; else echo "report found, score unreadable"; fi
            return 0
        fi
        ts="$(date +%Y%m%d_%H%M%S)"
        dst="$CP_BACKUP_ROOT/score-${label//[^A-Za-z0-9_.-]/_}-$ts.html"
        mkdir -p "$CP_BACKUP_ROOT" && chmod 700 "$CP_BACKUP_ROOT" 2>/dev/null && cp -f "$rep" "$dst" 2>/dev/null
        if [ -n "$score" ]; then
            cp_info "Score before $label: ${CP_C_CYN}$score${CP_C_OFF} pts${summary:+ ($summary)} - report updated ${age} ago, saved: $dst"
            last="$(cat "$CP_STATE_DIR/score.last" 2>/dev/null)"   # "score|label|epoch"
            if [ -n "$last" ] && [ "$score" -lt "${last%%|*}" ] 2>/dev/null; then
                d="${last#*|}"; d="${d%%|*}"
                cp_warn "Score went DOWN ${last%%|*} -> $score since the snapshot before '$d' (the report can lag 1-2 min)"
                cp_todo "Score dropped ${last%%|*} -> $score between the snapshots before '$d' and '$label' - find the penalty in the scoring report (snapshots: $CP_BACKUP_ROOT/score-*.html, step logs: $CP_STATE_DIR/logs/)"
            elif [ -n "$last" ] && [ "$score" -gt "${last%%|*}" ] 2>/dev/null; then
                d="${last#*|}"; d="${d%%|*}"
                cp_ok "+$(( score - ${last%%|*} )) pts since the snapshot before '$d'"
            fi
            mkdir -p "$CP_STATE_DIR" && echo "$score|$label|$(date +%s)" > "$CP_STATE_DIR/score.last"
        else
            cp_info "Scoring report saved: $dst (could not read the score from it - open $rep)"
        fi
        return 0
    fi
    [ "$label" = "--score" ] && return 0
    [ -t 0 ] || return 0
    cp_ask "Have you taken a screenshot of the score (shows which script cost points)?" y \
        || cp_warn "OK - continuing. Take one when you can."
    return 0
}

# cp_ask "Question" [default y|n]  -> returns 0 for yes, 1 for no.
# Non-interactive runs (no TTY) silently take the default.
cp_ask() {
    local q="$1" def="${2:-n}" ans hint
    if [ "$def" = "y" ]; then hint="[Y/n]"; else hint="[y/N]"; fi
    if [ ! -t 0 ]; then
        [ "$def" = "y" ]; return
    fi
    read -r -p "  ? $q $hint: " ans
    ans="${ans:-$def}"
    [[ "$ans" =~ ^[Yy] ]]
}

# cp_read "Prompt" "default" -> echoes the answer (default when empty / non-interactive)
cp_read() {
    local q="$1" def="${2:-}" ans
    if [ ! -t 0 ]; then echo "$def"; return; fi
    read -r -p "  ? $q${def:+ [$def]}: " ans
    echo "${ans:-$def}"
}

# Back up files/dirs into /root/cp-backups/<timestamp>/<original path>.
# Backups are deliberately NOT kept next to the original: include dirs such as apt.conf.d,
# nginx sites-enabled or sshd_config.d would load a "file.bak" copy (planted vuln and all).
CP_BACKUP_ROOT="${CP_BACKUP_ROOT:-/root/cp-backups}"
cp_backup() {
    local f dest
    for f in "$@"; do
        [ -e "$f" ] || continue
        f="$(readlink -f "$f")"
        dest="$CP_BACKUP_ROOT/$CP_TS$f"
        [ -e "$dest" ] && continue
        mkdir -p "$(dirname "$dest")" && cp -a "$f" "$dest" && cp_info "Backup: $dest"
    done
}

cp_restore() {
    local f src
    for f in "$@"; do
        f="$(readlink -f "$f" 2>/dev/null || echo "$f")"
        src="$CP_BACKUP_ROOT/$CP_TS$f"
        if [ -e "$src" ]; then
            rm -rf "$f" && cp -a "$src" "$f" && cp_warn "Restored $f from $src"
        fi
    done
}

cp_os_id() { ( . /etc/os-release 2>/dev/null; echo "${ID:-unknown}-${VERSION_ID:-0}" ); }
cp_pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }

# ------------------------------------------------- in-place config editing --
# Core awk engine used by cp_set / cp_unset.
#   mode: space   -> "Key value"          (sshd, apache, openvpn, login.defs, squid)
#         eq      -> "key=value"          (vsftpd, gdm/lightdm, sysctl-style without spaces)
#         eqs     -> "key = value"        (php, mysql, samba, postgres, dovecot, sysctl)
#   ci=1         -> key comparison is case-insensitive
#   norm=1       -> key comparison ignores spaces, '-' and '_' (samba "server min protocol",
#                   mysql "local-infile" == "local_infile")
#   section      -> only act inside [section] (ini files); empty = whole file
#   stopre       -> regex; lines from the first match onward are out of scope and new
#                   lines are inserted BEFORE it (sshd: "^[ \t]*Match[ \t]")
#   action: set | unset
_cp_conf_awk() {
    local file="$1" key="$2" newline="$3" mode="$4" ci="$5" norm="$6" section="$7" stopre="$8" action="$9"
    awk -v key="$key" -v newline="$newline" -v mode="$mode" -v ci="$ci" -v norm="$norm" \
        -v section="$section" -v stopre="$stopre" -v action="$action" '
    function nk(s) { if (ci == "1") s = tolower(s); if (norm == "1") { gsub(/[ \t_-]/, "", s); s = tolower(s) }; return s }
    # Parse a line -> sets K (key) and C (1 if commented). K="" when not a key line.
    function parse(l,   t, p) {
        K = ""; C = 0; t = l
        sub(/^[ \t]+/, "", t)
        if (t ~ /^[#;]/) { C = 1; sub(/^[#;]+[ \t]*/, "", t) }
        if (t == "" || t ~ /^\[/) return
        if (mode == "space") {
            if (match(t, /^[^ \t=]+/)) K = substr(t, RSTART, RLENGTH)
        } else {
            p = index(t, "=")
            if (p == 0) return
            K = substr(t, 1, p - 1); sub(/[ \t]+$/, "", K)
            if (mode == "eq" && K ~ /[ \t]/ && norm != "1") { K = ""; return }
        }
    }
    FNR == NR {
        n = FNR
        if ($0 ~ /^[ \t]*\[[^]]*\][ \t]*$/) { cur = $0; gsub(/^[ \t]*\[|\][ \t]*$/, "", cur); cur = tolower(cur); if (cur == tolower(section)) secidx++ }
        insec = (section == "" || cur == tolower(section))
        if (stopre != "" && !stopline && $0 ~ stopre) stopline = n
        inscope = insec && !(stopline && n >= stopline)
        if (section != "" && insec && secidx <= 1) { secfound = 1; if ($0 !~ /^[ \t]*$/ && $0 !~ /^[ \t]*[#;]/) lastsec = n; else if (!lastsec) lastsec = n }
        if (!inscope) next
        parse($0)
        if (K != "" && nk(K) == nk(key)) {
            if (!C) unc[++u] = n
            else if (!firstc && action == "set") {
                # only reuse a commented line if it looks like "key<sep>value" (not prose)
                firstc = n
            }
        }
        next
    }
    {
        n = FNR
        if (action == "unset") { for (i = 1; i <= u; i++) if (unc[i] == n) next; print; next }
        match($0, /^[ \t]*/); ind = substr($0, 1, RLENGTH)
        if (u > 0) {
            if (n == unc[1]) { print ind newline; next }
            for (i = 2; i <= u; i++) if (unc[i] == n) next
            print; next
        }
        if (firstc) { if (n == firstc) { print ind newline; next }; print; next }
        # insertion
        if (section != "") {
            print
            if (secfound && n == lastsec) { if ($0 ~ /^[ \t]*\[/) print newline; else print ind newline }
            next
        }
        if (stopline && n == stopline) { print newline; print; next }
        print
    }
    END {
        if (action == "set" && u == 0 && !firstc) {
            if (section != "" && !secfound) { print ""; print "[" section "]"; print newline }
            else if (section == "" && !stopline) print newline
        }
    }' "$file" "$file"
}

# cp_set FILE KEY VALUE [mode=eqs] [ci=0] [norm=0] [section=] [stopre=]
# VALUE "__FLAG__" writes the bare key (e.g. mysql "skip-symbolic-links", openvpn "persist-key").
cp_set() {
    local file="$1" key="$2" value="$3" mode="${4:-eqs}" ci="${5:-0}" norm="${6:-0}" section="${7:-}" stopre="${8:-}"
    local line tmp
    [ -f "$file" ] || { mkdir -p "$(dirname "$file")"; touch "$file"; }
    if [ "$value" = "__FLAG__" ]; then line="$key"
    else case "$mode" in
        space) line="$key $value" ;;
        eq)    line="$key=$value" ;;
        *)     line="$key = $value" ;;
    esac; fi
    tmp="$(mktemp)"
    if _cp_conf_awk "$file" "$key" "$line" "$mode" "$ci" "$norm" "$section" "$stopre" set > "$tmp"; then
        cat "$tmp" > "$file"   # keep inode, owner and mode of the original
    fi
    rm -f "$tmp"
}

# cp_unset FILE KEY [mode] [ci] [norm] [section]   -> deletes every uncommented KEY line
cp_unset() {
    local file="$1" key="$2" mode="${3:-eqs}" ci="${4:-0}" norm="${5:-0}" section="${6:-}" tmp
    [ -f "$file" ] || return 0
    tmp="$(mktemp)"
    if _cp_conf_awk "$file" "$key" "" "$mode" "$ci" "$norm" "$section" "" unset > "$tmp"; then
        if ! cmp -s "$tmp" "$file"; then cat "$tmp" > "$file"; cp_info "Removed '$key' from $file"; fi
    fi
    rm -f "$tmp"
}

# cp_get FILE KEY [mode] [ci] [norm] [section]  -> prints value of first uncommented KEY
cp_get() {
    local file="$1" key="$2" mode="${3:-eqs}" ci="${4:-0}" norm="${5:-0}" section="${6:-}"
    [ -f "$file" ] || return 0
    awk -v key="$key" -v mode="$mode" -v ci="$ci" -v norm="$norm" -v section="$section" '
    function nk(s) { if (ci == "1") s = tolower(s); if (norm == "1") { gsub(/[ \t_-]/, "", s); s = tolower(s) }; return s }
    /^[ \t]*\[[^]]*\][ \t]*$/ { cur = $0; gsub(/^[ \t]*\[|\][ \t]*$/, "", cur); cur = tolower(cur); next }
    section != "" && cur != tolower(section) { next }
    /^[ \t]*[#;]/ { next }
    {
        t = $0; sub(/^[ \t]+/, "", t)
        if (mode == "space") { if (match(t, /^[^ \t]+/)) { k = substr(t, 1, RLENGTH); v = substr(t, RLENGTH + 1) } else next }
        else { p = index(t, "="); if (!p) next; k = substr(t, 1, p - 1); v = substr(t, p + 1); sub(/[ \t]+$/, "", k) }
        sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v)
        if (nk(k) == nk(key)) { print v; exit }
    }' "$file"
}

# Remove KEY from every file in a list of drop-in files/dirs (G1 / B3 conflicts).
cp_unset_in_dropins() {
    local key="$1" mode="$2" ci="$3" norm="$4"; shift 4
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        if [ -n "$(cp_get "$f" "$key" "$mode" "$ci" "$norm")" ] || grep -qiE "^[[:space:]]*${key}[[:space:]]*$" "$f" 2>/dev/null; then
            cp_backup "$f"
            cp_unset "$f" "$key" "$mode" "$ci" "$norm"
        fi
    done
}

# -------------------------------------------------------------- firewall --
# cp_ufw_allow PROFILE FALLBACK...   (G3) e.g. cp_ufw_allow "OpenSSH" 22/tcp
cp_ufw_allow() {
    local profile="$1"; shift
    command -v ufw >/dev/null 2>&1 || { cp_warn "ufw not installed - skipping firewall rule"; return 0; }
    if ufw app list 2>/dev/null | sed 's/^[[:space:]]*//' | grep -qxF "$profile"; then
        ufw allow "$profile" >/dev/null && cp_ok "UFW: allowed application profile '$profile'"
    else
        local p
        for p in "$@"; do ufw allow "$p" >/dev/null && cp_ok "UFW: allowed $p (no '$profile' profile found)"; done
    fi
}

# ------------------------------------------------------------- services --
cp_first_unit() {  # prints the first unit name that exists
    local u
    for u in "$@"; do
        if systemctl list-unit-files "$u.service" "$u" 2>/dev/null | grep -q "^$u"; then echo "$u"; return 0; fi
    done
    return 1
}

# cp_restart UNIT -> restart and confirm active; returns non-zero on failure
cp_restart() {
    local unit="$1"
    if systemctl restart "$unit" 2>/dev/null; then
        sleep 1
        if systemctl is-active --quiet "$unit"; then cp_ok "$unit restarted and active"; return 0; fi
    fi
    cp_err "$unit failed to (re)start - check: journalctl -xeu $unit"
    return 1
}

# ------------------------------------------------------ baseline gate (B-4) --
# Every service script calls this first. Hardening is refused until the service has a baseline, which
# enforces the blog's order: baseline -> review -> harden. No baseline yet -> it is scanned now (no question).
# Then only this service's FIX NOW / REVIEW lines are shown; it pauses only when there is a FIX NOW finding.
cp_baseline_gate() {
    local svc="$1" dir="$CP_BASELINE_DIR/$1" log t0 n1 n2
    if [ ! -d "$dir/before" ]; then
        mkdir -p "$CP_BASELINE_DIR" && chmod 700 "$CP_BASELINE_DIR"
        log="$CP_BASELINE_DIR/gate-$svc.log"; t0="$(date +%s)"
        flock -n "$CP_BASELINE_DIR/.scan.lock" true 2>/dev/null || cp_info "A baseline scan is running - waiting for it..."
        cp_info "No baseline for '$svc' yet - scanning it now (detection only, changes nothing)..."
        bash "$CP_ROOT/services/baseline.sh" "$svc" > "$log" 2>&1
        if [ ! -d "$dir/before" ]; then
            tail -3 "$log" 2>/dev/null | sed 's/^/      /'
            cp_err "Baseline scan for '$svc' failed (log: $log) - refusing to harden. Run: sudo bash services/baseline.sh $svc"
            exit 1
        fi
        cp_ok "Baseline for '$svc' saved in $(( $(date +%s) - t0 ))s ($dir)"
    else
        # drop findings that --review or an earlier script already fixed, so only open ones are shown / asked about
        bash "$CP_ROOT/services/baseline.sh" --prune "$svc" >/dev/null 2>&1
    fi
    if [ -f "$dir/findings.tsv" ]; then
        n1="$(awk -F'\t' '$1 == 1' "$dir/findings.tsv" | wc -l)"; n2="$(awk -F'\t' '$1 == 2' "$dir/findings.tsv" | wc -l)"
        if [ $((n1 + n2)) -eq 0 ]; then cp_ok "Baseline '$svc': no open findings"; return 0; fi
        echo "  Baseline findings for $svc: FIX NOW $n1, REVIEW $n2   (all: $CP_BASELINE_DIR/FINDINGS.txt)"
        awk -F'\t' -v R="$CP_C_RED" -v Y="$CP_C_YEL" -v O="$CP_C_OFF" '$1 <= 2 {
                if (++n > 12) { more++; next }
                printf "    %s %s\n", ($1 == 1 ? R "FIX NOW" O : Y "REVIEW " O), $8
                if ($10 != "-") { k = split($10, d, "\037"); for (i = 1; i <= k && i <= 2; i++) printf "              %s\n", d[i] } }
            END { if (more) printf "    ... %d more (sudo bash services/baseline.sh --review)\n", more }' "$dir/findings.tsv"
        if [ "$n1" -gt 0 ]; then
            if cp_ask "Triage the $n1 FIX NOW finding(s) for $svc now (baseline.sh --review $svc)?" n; then
                bash "$CP_ROOT/services/baseline.sh" --review "$svc"
            fi
        else
            cp_info "Review later: sudo bash services/baseline.sh --review $svc"
        fi
    elif [ -f "$dir/report.txt" ]; then   # baseline made by an older baseline.sh
        grep -E '^!!' "$dir/report.txt" | head -20 | sed 's/^/    /'
    fi
}

# ------------------------------------------------------ web content scan --
# Used by apache2.sh / nginx.sh (B8 findings -> WEB10 action). Nothing is deleted: files are MOVED to
# /root/cp-quarantine/<original path> (undo: INDEX.txt there). One question per list ("e" = ask each).
cp_web_scan() {
    local r f ans qdir=/root/cp-quarantine phpi=() shells=()
    local re='(eval[[:space:]]*\(|base64_decode[[:space:]]*\(|shell_exec[[:space:]]*\(|passthru[[:space:]]*\(|system[[:space:]]*\(\$_|assert[[:space:]]*\(\$_|\$_(GET|POST|REQUEST)\[[^]]*\][[:space:]]*\()'
    _cp_web_quar() {
        local d="$qdir$1"; [ -e "$d" ] && d="$d.$CP_TS"
        mkdir -p "$(dirname "$d")" && chmod 700 "$qdir" && mv -- "$1" "$d" || { cp_err "could not move $1"; return 1; }
        echo "$(date '+%F %T')  $1 -> $d" >> "$qdir/INDEX.txt"; cp_ok "Quarantined $1 -> $d"
    }
    _cp_web_batch() {  # _cp_web_batch "what" default file...
        local what="$1" def="$2"; shift 2
        ans="$(cp_read "Quarantine $what to $qdir? (y = all, n = none, e = ask each)" "$def")"
        case "$ans" in
            [Yy]*) for f in "$@"; do _cp_web_quar "$f"; done ;;
            [Ee]*) for f in "$@"; do cp_ask "Quarantine $f ?" y && _cp_web_quar "$f"; done ;;
            *) for f in "$@"; do cp_todo "Check / remove $what: $f"; done ;;
        esac
    }
    cp_hdr "Web content scan (phpinfo / webshell indicators)"
    mapfile -t phpi < <(for r in "$@"; do [ -d "$r" ] && grep -rlsiE 'phpinfo[[:space:]]*\(' "$r" --include='*.php' --include='*.phtml' --include='*.inc'; done 2>/dev/null | sort -u)
    mapfile -t shells < <(for r in "$@"; do [ -d "$r" ] && grep -rlsE "$re" "$r" --include='*.php' --include='*.phtml' --include='*.inc'; done 2>/dev/null | sort -u \
                          | grep -vxF -f <(printf '%s\n' "${phpi[@]}"))
    if [ ${#phpi[@]} -eq 0 ] && [ ${#shells[@]} -eq 0 ]; then cp_ok "No phpinfo() files or webshell indicators"; return 0; fi
    if [ ${#phpi[@]} -gt 0 ]; then
        cp_warn "phpinfo() file(s) - leak server details, safe to remove:"; printf '      %s\n' "${phpi[@]}"
        _cp_web_batch "these phpinfo() file(s)" y "${phpi[@]}"
    fi
    if [ ${#shells[@]} -gt 0 ]; then
        cp_warn "Possible webshell(s) - pattern match, real site code (WordPress core) can match too:"
        for f in "${shells[@]}"; do printf '      %s\n          %s\n' "$f" "$(grep -m1 -anE "$re" "$f" | cut -c1-100)"; done
        _cp_web_batch "these possible webshell(s)" n "${shells[@]}"
    fi
}
