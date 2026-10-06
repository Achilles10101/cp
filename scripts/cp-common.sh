#!/bin/bash
# cp-common.sh - shared helpers for the CP19 Linux scripts.
# Sourced by systemconfig.sh and every script in scripts/services/. Not meant to be run directly.
#
# Main ideas (from the research doc):
#   G1  edit settings IN PLACE and remove conflicting duplicates (never blind-append)
#   G2  functionally test a service after changing it
#   G3  use UFW application profiles when they exist
#   B-4 refuse to harden a service until it has been baselined (scripts/services/baseline.sh)

# Directory that contains this file (repo root) - works no matter where the caller lives.
CP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CP_BASELINE_DIR="${CP_BASELINE_DIR:-/root/baseline}"
CP_TS="$(date +%Y%m%d_%H%M%S)"

# ---------------------------------------------------------------- output --
cp_info() { echo "  [*] $*"; }
cp_ok()   { echo "  [+] $*"; }
cp_warn() { echo "  [!] $*"; }
cp_err()  { echo "  [x] $*" >&2; }
cp_hdr()  { echo; echo "=== $* ==="; }

# ---------------------------------------------------------------- basics --
cp_require_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        echo "ERROR: This script must be run as root (use sudo)"
        exit 1
    fi
}

cp_screenshot_prompt() {
    if [ -t 0 ]; then
        local yn
        while true; do
            read -r -p "Have you taken a screenshot of the points? (y/n): " yn
            case "$yn" in
                [Yy]*) break ;;
                [Nn]*) echo "Please take a screenshot first. Exiting."; exit 1 ;;
                *) echo "Please answer y or n." ;;
            esac
        done
    fi
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
# Every service script calls this first. Hardening is refused until the service has been
# baselined, which enforces the blog's order: baseline -> review -> harden.
cp_baseline_gate() {
    local svc="$1" dir="$CP_BASELINE_DIR/$1"
    if [ -d "$dir/before" ]; then
        cp_ok "Baseline for '$svc' exists ($dir)"
    else
        cp_warn "No baseline found for '$svc' ($dir/before missing)."
        cp_warn "The service must be baselined before it is hardened (research doc, section B)."
        if cp_ask "Run scripts/services/baseline.sh $svc now?" y; then
            bash "$CP_ROOT/services/baseline.sh" "$svc" || { cp_err "baseline.sh failed"; exit 1; }
        else
            echo "Refusing to continue without a baseline. Run: sudo bash scripts/services/baseline.sh $svc"
            exit 1
        fi
    fi
    if [ -f "$dir/report.txt" ]; then
        echo
        echo "----- Baseline findings for $svc (full report: $dir/report.txt) -----"
        grep -E '^\s*(!!|##)' "$dir/report.txt" | head -60
        echo "-----------------------------------------------------------------------"
        if [ -t 0 ]; then read -r -p "  Review the findings above, then press Enter to continue... " _; fi
    fi
}

# ------------------------------------------------------ web content scan --
# Used by apache2.sh / nginx.sh (B8 findings -> WEB10 action)
cp_web_scan() {
    local roots=("$@") r f
    cp_hdr "Web content scan (phpinfo / webshell indicators)"
    for r in "${roots[@]}"; do
        [ -d "$r" ] || continue
        while IFS= read -r f; do
            cp_warn "phpinfo() file: $f"
            if cp_ask "Delete $f ?" y; then rm -f -- "$f" && cp_ok "Deleted $f"; fi
        done < <(grep -rlsiE 'phpinfo[[:space:]]*\(' "$r" --include='*.php' --include='*.phtml' --include='*.inc' 2>/dev/null)
        grep -rlsE '(eval[[:space:]]*\(|base64_decode[[:space:]]*\(|shell_exec[[:space:]]*\(|passthru[[:space:]]*\(|system[[:space:]]*\(\$_|assert[[:space:]]*\(\$_|\$_(GET|POST|REQUEST)\[[^]]*\][[:space:]]*\()' \
            "$r" --include='*.php' --include='*.phtml' --include='*.inc' 2>/dev/null | while IFS= read -r f; do
            cp_warn "Possible webshell (review manually, not deleted): $f"
        done
    done
}
