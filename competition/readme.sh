#!/bin/bash
# readme.sh - README paste parser for usersandsudo.sh (admins, users, your account, weak README passwords).
# usersandsudo.sh sources this file and calls rd_intake itself on every run; no other script reads its results
# (2026-11-11 redesign: each script asks for the README facts it needs). Critical services are NOT detected here.
#
#   bash readme.sh                    preview: paste the README, see what is parsed (saves nothing)
#   bash readme.sh --file F           same, from a saved README file (.txt or .html)
#   bash readme.sh --parse [F]        parse only (stdin or F), print the result; no root, changes nothing (tests)
#   Test harness only: CP_ADMINS="a b" CP_USERS="c d" [CP_ME=a] skip the paste in rd_intake.
#
# Paste = click in the README page, Ctrl-A, Ctrl-C, then Ctrl-Shift-V into the terminal (the whole page is fine).
# README passwords are held in memory only, to flag insecure ones as user:reason[,reason] (blank, common,
# has-username, short (< 12 chars, the policy systemconfig.sh sets), letters-only, word+digits, reused; for an
# otherwise strong-looking one: no-symbol / no-digit / no-upper / no-lower). No password is ever written to disk.
# When sourced by usersandsudo.sh, cp-common.sh is already loaded: do not reload it (that would reset CP_TS,
# the backup folder of the run, and relabel usersandsudo's TODOs).
if ! declare -F cp_info >/dev/null; then
    # shellcheck disable=SC2034  # used by cp-common.sh (cp_todo tag)
    CP_SCRIPT_NAME=readme.sh
    # shellcheck source=cp-common.sh
    source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/cp-common.sh"
fi


# ------------------------------------------------------------------ parser --
# stdin = README text (any part of it). Prints records, one per line:
#   A name | U name | DUP name (listed as admin AND user) | YOU name | W name reasons
# Rules: "Authorized Administrators:" / "Authorized Users:" headings (also "Administrators:", "Users:",
# "Standard users:"); one lowercase account name per line ("name (you)", "- name", "1. name", "a, b, c" all
# work); "password: X" (own line or after the name) belongs to the name before it; blank lines are ignored
# inside a list; any other line (a sentence, "Something:") ends the list. CRLF, tabs, NBSP, bracketed-paste
# escapes are cleaned. POSIX awk only (Mint ships mawk).
rd_parse() {
    awk '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function isname(s) { return s ~ /^[a-z_][a-z0-9_.-]*[$]?$/ && length(s) <= 32 }
    function addname(n, you) {
        if (sec == "admins") { if (!(n in A)) { A[n] = 1; AO[++NA] = n } }
        else                 { if (!(n in U)) { U[n] = 1; UO[++NU] = n } }
        last = n
        if (you) YOU = n
    }
    # 1 = took name(s), 0 = nothing there, -1 = not a name line (nothing taken)
    function takenames(str,   parts, n, i, p, you, got, cand, cy) {
        n = split(str, parts, ","); got = 0
        for (i = 1; i <= n; i++) {
            p = parts[i]; you = 0
            if (tolower(p) ~ /\( *you *\)/) { you = 1; gsub(/\( *[Yy][Oo][Uu] *\)/, "", p) }
            p = trim(p); sub(/^([-*+>]+|[0-9]+[.)]) */, "", p); sub(/[ ;:|\/-]+$/, "", p); p = trim(p)
            if (p == "") continue
            if (!isname(p)) return -1
            cand[++got] = p; cy[got] = you
        }
        for (i = 1; i <= got; i++) addname(cand[i], cy[i])
        return got ? 1 : 0
    }
    BEGIN {
        nc = split("password password1 password12 password123 passw0rd p@ssw0rd p@ssword pa55word 123456 1234567 12345678 123456789 1234567890 12345 1234 111111 000000 654321 qwerty qwerty123 qwertyuiop asdf asdfgh zxcvbn abc123 abcd1234 letmein welcome welcome1 admin admin123 administrator root toor changeme changeme123 iloveyou monkey dragon football baseball sunshine princess master shadow superman batman hunter2 trustno1 secret default guest login test test123 linux ubuntu mint debian cyberpatriot security computer internet summer winter spring autumn starwars pokemon spiderman ironman avengers", CW, " ")
        for (i = 1; i <= nc; i++) COMMON[CW[i]] = 1
    }
    { L[++NL] = $0 }
    END {
        sec = ""; blanks = 0
        for (i = 1; i <= NL; i++) {
            raw = L[i]
            gsub(/\r/, "", raw); gsub(/\033\[[0-9;?]*[~A-Za-z]/, "", raw)
            gsub(/\302\240/, " ", raw); gsub(/\342\200\242/, "-", raw); gsub(/\t/, " ", raw)
            t = trim(raw); gsub(/  +/, " ", t)
            l = tolower(t); lb = l; sub(/^[-*+># ]+/, "", lb)
            # heading with a note in brackets: "Authorized Users (Minions):" -> "authorized users:"
            if (lb ~ /^(authori[sz]ed |standard |normal |regular |other )*(administrators?|admins?|users?) *\(/) gsub(/ *\([^)]*\)/, "", lb)
            if (t == "") continue
            rest = ""; c = index(t, ":"); if (c) rest = trim(substr(t, c + 1))
            # ---- headings
            if (lb ~ /^(authori[sz]ed )?(administrators?|admins?) ?:/ || lb ~ /^(authori[sz]ed )?(administrators?|admins?)$/) {
                sec = "admins"; last = ""; if (rest != "") takenames(rest); continue
            }
            if (lb ~ /^(authori[sz]ed )?((standard|normal|regular|other) )?users? ?:/ || lb ~ /^(authori[sz]ed )?((standard|normal|regular|other) )?users?$/) {
                sec = "users"; last = ""; if (rest != "") takenames(rest); continue
            }
            # ---- inside a list
            if (sec == "admins" || sec == "users") {
                p = index(l, "password")
                if (p > 0 && substr(l, p) ~ /^passwords? ?[:=]/) {
                    pre = substr(t, 1, p - 1); post = substr(t, p); q = index(post, ":"); if (!q) q = index(post, "=")
                    pw = trim(substr(post, q + 1))
                    if (trim(pre) != "" && takenames(pre) < 0) continue
                    if (last != "") { PW[last] = pw; HP[last] = 1 }
                    continue
                }
                if (t ~ /:$/) { sec = ""; continue }
                if (takenames(t) >= 0) continue
                sec = ""
            }
        }
        for (i = 1; i <= NA; i++) print "A " AO[i]
        for (i = 1; i <= NU; i++) print ((UO[i] in A) ? "DUP " : "U ") UO[i]
        if (YOU != "") print "YOU " YOU
        for (i = 1; i <= NA + NU; i++) {
            u = (i <= NA) ? AO[i] : UO[i - NA]
            if (!(u in HP) || (u in DONE)) continue
            DONE[u] = 1
            pw = PW[u]; lp = tolower(pw); lu = tolower(u); r = ""
            if (pw == "") r = ",blank"
            else {
                if (lp in COMMON) r = r ",common"
                if (lp == lu || (length(lu) >= 3 && index(lp, lu))) r = r ",has-username"
                # dictionary word under leetspeak / trailing digits+symbols: "S3curity1!" -> "security"
                b = lp; sub(/[0-9!@#$%^&*.?_-]+$/, "", b)
                gsub(/0/, "o", b); gsub(/1/, "i", b); gsub(/3/, "e", b); gsub(/4/, "a", b); gsub(/5/, "s", b); gsub(/7/, "t", b); gsub(/@/, "a", b); gsub(/[$]/, "s", b)
                if (!(lp in COMMON) && b != "" && length(b) <= 8 && (b in COMMON)) r = r ",common"
                if (length(pw) < 12) r = r ",short"
                if (pw ~ /^[A-Za-z]+$/) r = r ",letters-only"
                else if (pw ~ /^[A-Za-z]+[0-9]+[!.?]?$/) r = r ",word+digits"
                # otherwise strong-looking but missing a class the policy (systemconfig.sh) requires
                if (r == "") {
                    if (pw !~ /[^A-Za-z0-9]/) r = r ",no-symbol"
                    if (pw !~ /[0-9]/) r = r ",no-digit"
                    if (pw !~ /[A-Z]/) r = r ",no-upper"
                    if (pw !~ /[a-z]/) r = r ",no-lower"
                }
                for (v in HP) if (v != u && PW[v] == pw) { r = r ",reused"; break }
            }
            if (r != "") print "W " u " " substr(r, 2)
        }
    }'
}

# Parse $1 (README text) into P_ADMINS P_USERS P_DUPS P_YOU P_WEAK.
# The text goes to awk through a pipe (no temp file: it holds the README passwords).
rd_parse_text() {
    local rec tag a b
    P_ADMINS=""; P_USERS=""; P_DUPS=""; P_YOU=""; P_WEAK=""
    rec="$(printf '%s\n' "$1" | rd_parse)"
    while read -r tag a b; do
        case "$tag" in
            A) P_ADMINS+=" $a" ;; U) P_USERS+=" $a" ;; DUP) P_DUPS+=" $a" ;; YOU) P_YOU="$a" ;;
            W) P_WEAK+=" $a:$b" ;;
        esac
    done < <(printf '%s\n' "$rec")
    P_ADMINS="${P_ADMINS# }"; P_USERS="${P_USERS# }"; P_DUPS="${P_DUPS# }"; P_WEAK="${P_WEAK# }"
}

# HTML -> text (for --file with a saved README page)
rd_html2text() {
    sed -e 's/<[bB][rR][^>]*>/\n/g' -e 's#</\?\([pP]\|[dD][iI][vV]\|[lL][iI]\|[hH][1-6]\|[tT][rR]\|[pP][rR][eE]\)\b[^>]*>#\n#g' \
        -e 's/<[^>]*>//g' -e 's/&nbsp;/ /g' -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&quot;/"/g' -e "s/&#39;/'/g" -e 's/&amp;/\&/g' "$1"
}

# -------------------------------------------------------------- helpers --
# typed list -> valid account names (commas ok, "(you)" dropped)
rd_names() {
    local w out=""
    for w in $(echo "$*" | sed -E 's/\( *[Yy][Oo][Uu] *\)//g; s/[,;]/ /g'); do
        if [[ "$w" =~ ^[a-z_][a-z0-9_.-]*\$?$ ]]; then [[ " $out " == *" $w "* ]] || out+=" $w"
        else cp_warn "Ignored '$w' (not a valid account name)" >&2; fi
    done
    echo "${out# }"
}

# Your account: SUDO_USER, else whoever logged in (logname / login UID).
rd_me_live() {
    local u="${SUDO_USER:-}" luid
    [ -z "$u" ] || [ "$u" = root ] && u="$(logname 2>/dev/null)"
    if [ -z "$u" ] || [ "$u" = root ]; then
        luid="$(cat /proc/self/loginuid 2>/dev/null)"
        [ -n "$luid" ] && [ "$luid" != 4294967295 ] && u="$(getent passwd "$luid" | cut -d: -f1)"
    fi
    [ "$u" = root ] && u=""
    echo "$u"
}

rd_summary() {
    local na nu
    na=$(wc -w <<< "$ADMINS"); nu=$(wc -w <<< "$USERS")
    cp_hdr "README summary"
    printf '  Admins (%s): %s\n' "$na" "${ADMINS:--}"
    printf '  Users  (%s): %s\n' "$nu" "${USERS:--}"
    printf '  You       : %s%s\n' "${ME:-?}" "$( [ -n "$P_YOU" ] && [ "$P_YOU" != "$ME" ] && echo "   (README marks $P_YOU as (you)!)")"
    [ -n "$WEAK" ] && printf '  Insecure README passwords: %s\n' "$WEAK"
    [ -n "$P_DUPS" ] && cp_warn "Listed as admin AND user (kept as admin): $P_DUPS"
    return 0
}

# Read the paste. Ends at an empty line after the users list, two empty lines in a row, or Ctrl-D.
# Whatever else was pasted (rest of a whole-page paste) is drained so it cannot answer later prompts.
rd_read_paste() {
    local line low n=0 users_head=0 users_n=0 prev_blank=0
    PASTE=""
    if [ -t 0 ]; then
        cp_hdr "README users (paste the README)"
        echo "  1. Click anywhere in the README page, press Ctrl-A (select all), then Ctrl-C."
        echo "  2. Paste it here (Ctrl-Shift-V), then press Enter (twice if it does not continue, or Ctrl-D)."
        printf '  ? Paste the README now: '
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        PASTE+="$line"$'\n'
        n=$((n + 1)); [ "$n" -gt 5000 ] && break
        [ -t 0 ] || continue                         # file/pipe: read to the end
        if [ -z "${line//[[:space:]]/}" ]; then
            [ "$users_n" -gt 0 ] || [ "$prev_blank" = 1 ] && break
            prev_blank=1; continue
        fi
        prev_blank=0; low="${line,,}"
        if [[ "$low" =~ ^[[:space:]-]*(authori[sz]ed[[:space:]]+)?((standard|normal|regular|other)[[:space:]]+)?users?([[:space:]]*\([^\)]*\))?[[:space:]]*(:|$) ]]; then
            users_head=1; users_n=0
        elif [[ "$low" =~ admin ]]; then users_head=0
        elif [ "$users_head" = 1 ] && [[ "$low" != *password* ]]; then users_n=$((users_n + 1)); fi
    done
    if [ -t 0 ]; then while IFS= read -r -t 0.5 line; do PASTE+="${line%$'\r'}"$'\n'; done; fi
}

# Paste (or file) -> ADMINS USERS ME WEAK, with a typed fallback.
rd_intake_text() {
    local live
    rd_parse_text "$PASTE"
    ADMINS="$P_ADMINS"; USERS="$P_USERS"; WEAK="$P_WEAK"
    if [ -z "$ADMINS" ]; then
        cp_warn "No 'Authorized Administrators' list found - type the names instead."
        ADMINS="$(rd_names "$(cp_read "Authorized administrators (space-separated, yours too)" "")")"
        [ -n "$USERS" ] || USERS="$(rd_names "$(cp_read "Authorized users (space-separated, Enter = none)" "")")"
    fi
    live="$(rd_me_live)"
    ME="${live:-${CP_ME:-$P_YOU}}"
}

rd_fix_me() {   # your account is always an authorized admin
    [ -n "$ME" ] || return 0
    if [[ " $ADMINS " != *" $ME "* ]] && [[ " $USERS " != *" $ME "* ]]; then
        cp_warn "Your account '$ME' is not in the README lists - added to the admins (it is never removed or locked)"
        ADMINS="$ME${ADMINS:+ $ADMINS}"
    elif [[ " $USERS " == *" $ME "* ]]; then
        cp_warn "Your account '$ME' is listed as a standard user - scripts still never remove, lock or demote it"
    fi
}

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

# rd_intake [FILE] -> sets ADMINS USERS ME WEAK (README facts) after a paste (or FILE) and the confirm loop.
# Test harness: CP_ADMINS / CP_USERS [/ CP_ME] skip the paste. Returns 1 when nothing was given.
rd_intake() {
    local f="${1:-}" ans u
    P_YOU=""; P_DUPS=""; WEAK=""
    if [ -n "${CP_ADMINS:-}" ]; then
        ADMINS="$(rd_names "$CP_ADMINS")"; USERS="$(rd_names "${CP_USERS:-}")"
        ME="$(rd_me_live)"; ME="${ME:-${CP_ME:-}}"
        rd_fix_me
        for u in $USERS; do [[ " $ADMINS " == *" $u "* ]] && USERS="$(echo " $USERS " | sed "s/ $u / /; s/^ //; s/ $//")"; done
        cp_info "README users from the environment (test harness): admins: $ADMINS | users: ${USERS:--} | you: ${ME:-?}"
        return 0
    fi
    if [ -n "$f" ]; then
        [ -r "$f" ] || { cp_err "Cannot read $f"; return 1; }
        if grep -qi '<html\|<pre\|<br' "$f"; then PASTE="$(rd_html2text "$f")"; else PASTE="$(cat "$f")"; fi
    else
        rd_read_paste
        [ -n "${PASTE//[[:space:]]/}" ] || [ -t 0 ] || { cp_err "No README text on stdin"; return 1; }
    fi
    rd_intake_text
    rd_fix_me
    while :; do
        rd_summary
        ans="$(cp_read "Correct? Enter = yes | a = admins  u = users  m = you  p = paste again" y)"
        case "${ans,,}" in
            y|yes) break ;;
            a) ADMINS="$(rd_names "$(cp_read "Authorized administrators (space-separated)" "$ADMINS")")"; rd_fix_me ;;
            u) ans="$(cp_read "Authorized users (space-separated, - = none)" "$USERS")"
               [ "$ans" = - ] && USERS="" || USERS="$(rd_names "$ans")" ;;
            m) ME="$(rd_names "$(cp_read "Your account" "$ME")")"; rd_fix_me ;;
            p) rd_read_paste; rd_intake_text; rd_fix_me ;;
            *) cp_warn "Type y (or Enter), a, u, m or p" ;;
        esac
        for u in $USERS; do [[ " $ADMINS " == *" $u "* ]] && USERS="$(echo " $USERS " | sed "s/ $u / /; s/^ //; s/ $//")"; done
    done
    unset PASTE
    [ -n "$ADMINS" ]
}

# ----------------------------------------------------------------- main --
# Sourced (usersandsudo.sh): only the functions above are defined.
[[ "${BASH_SOURCE[0]}" != "$0" ]] && return 0

MODE=preview FILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --parse) MODE=parse; [ -n "${2:-}" ] && [ "${2#-}" = "$2" ] && { FILE="$2"; shift; } ;;
        --file) FILE="${2:-}"; shift ;;
        *) [ -f "$1" ] && FILE="$1" || { echo "Unknown option: $1 (see -h)"; exit 2; } ;;
    esac
    shift
done

if [ "$MODE" = parse ]; then   # no root, no state: print what the parser finds
    if [ -n "$FILE" ]; then
        if grep -qi '<html\|<pre\|<br' "$FILE"; then PASTE="$(rd_html2text "$FILE")"; else PASTE="$(cat "$FILE")"; fi
    else PASTE="$(cat)"; fi
    rd_parse_text "$PASTE"
    printf 'ADMINS=%s\nUSERS=%s\nYOU=%s\nWEAKPW=%s\nDUPS=%s\n' "$P_ADMINS" "$P_USERS" "$P_YOU" "$P_WEAK" "$P_DUPS"
    exit 0
fi

rd_intake "$FILE" || exit 1
cp_info "Preview only - nothing saved. usersandsudo.sh asks for the README users itself (same paste)."
exit 0
