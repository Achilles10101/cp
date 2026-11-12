#!/bin/bash
# readme.sh - README intake. Asked ONCE, saved for every other script (cp_cfg_*, /root/cp-state/readme.conf).
#
#   sudo bash readme.sh               click in the README page, Ctrl-A, Ctrl-C (the WHOLE page: the critical
#                                     services come before the user lists), paste into the terminal, confirm -> saved
#   sudo bash readme.sh --show        print the saved answers
#   sudo bash readme.sh --reset       forget the saved README answers and ask again
#   sudo bash readme.sh --if-missing  do nothing when the answers are already saved (for start.sh / other scripts)
#   sudo bash readme.sh --file F      read the README from a saved file (.txt or .html) instead of pasting
#   bash readme.sh --parse [F]        parse only (stdin or F) and print what was found; changes nothing (tests)
#   Non-interactive (test harness):   CP_ADMINS="a b" CP_USERS="c d" [CP_SERVICES="ssh"] [CP_ME=a] bash readme.sh
#                                     (with sudo: sudo CP_ADMINS=... bash readme.sh). CP_SERVICES unset = not saved.
# SERVICES is saved only from the README's critical-services text or a typed answer, confirmed at a terminal
# (or from CP_SERVICES) - never from a default and never without a TTY. A paste without a critical-services
# section gets a services question with NO default; "none" while service packages are installed needs a [y/N].
#
# Keys written (values are space-separated words):
#   ADMINS    authorized administrators (always includes your own account)
#   USERS     authorized standard users
#   ME        your account: SUDO_USER, else the login-UID owner, else the README's "(you)" account
#   SERVICES  critical services as services/*.sh names, or "none"
#   WEAKPW    accounts whose README password looks weak, as user:reason[,reason] (blank, common,
#             has-username, short (< 12 chars, the policy systemconfig.sh sets), letters-only, word+digits,
#             reused; no-symbol/no-digit/no-upper/no-lower for an otherwise strong-looking one). README passwords are only held in memory
#             during the intake to compute this - no password is ever written to disk.
# shellcheck disable=SC2034  # used by cp-common.sh (cp_todo tag)
CP_SCRIPT_NAME=readme.sh
# shellcheck source=cp-common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/cp-common.sh"

RD_SVCS="ssh vsftpd apache2 nginx php mysql postgresql samba bind9 mail wordpress openvpn squid"
RD_KEYS="ADMINS USERS ME SERVICES WEAKPW"

# ------------------------------------------------------------------ parser --
# stdin = README text (any part of it). Prints records, one per line:
#   A name | U name | DUP name (listed as admin AND user) | YOU name | S svc | SRC crit|none|text | W name reasons
# Rules: "Authorized Administrators:" / "Authorized Users:" headings (also "Administrators:", "Users:",
# "Standard users:"); one lowercase account name per line ("name (you)", "- name", "1. name", "a, b, c" all
# work); "password: X" (own line or after the name) belongs to the name before it; blank lines are ignored
# inside a list; any other line (a sentence, "Something:") ends the list. CRLF, tabs, NBSP, bracketed-paste
# escapes are cleaned. Critical services come from the "Critical services" part of the README when present,
# otherwise from product names anywhere outside the user lists. POSIX awk only (Mint ships mawk).
rd_parse() {
    awk '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function isname(s) { return s ~ /^[a-z_][a-z0-9_.-]*[$]?$/ && length(s) <= 32 }
    function nw(s,   a) { return split(s, a, / +/) }
    function norm(s) { s = " " tolower(s) " "; gsub(/[^a-z0-9]+/, " ", s); return s }
    function hit(k) { if (W == "c") CH[k] = 1; else FH[k] = 1 }
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
    function scan(s, weak) {
        if (s ~ / (openssh|ssh|sshd|openssh server) /) hit("ssh")
        if (s ~ / (vsftpd|vsftp|proftpd|pureftpd|pure ftpd) /) hit("vsftpd")
        if (s ~ / (apache|apache2|httpd) /) hit("apache2")
        if (s ~ / nginx /) hit("nginx")
        if (s ~ / php[0-9]* /) hit("php")
        if (s ~ / (mysql|mysqld|mariadb) /) hit("mysql")
        if (s ~ / (postgres|postgresql|psql|pgsql) /) hit("postgresql")
        if (s ~ / (samba|smbd) /) hit("samba")
        if (s ~ / bind9 /) hit("bind9")
        if (s ~ / (postfix|dovecot) /) hit("mail")
        if (s ~ / wordpress /) hit("wordpress")
        if (s ~ / openvpn /) hit("openvpn")
        if (s ~ / squid /) hit("squid")
        if (!weak) return
        if (s ~ / (ftp|ftps|ftpd) /) hit("vsftpd")
        if (s ~ / (smb|cifs) / || s ~ / file shar/) hit("samba")
        if (s ~ / (bind|dns|named) /) hit("bind9")
        if (s ~ / (mail|email|smtp|imap|imaps|pop3|pop3s) /) hit("mail")
        if (s ~ / vpn /) hit("openvpn")
        if (s ~ / proxy /) hit("squid")
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
            if (t == "") { blanks++; if (sec == "crit" && critn > 0 && blanks >= 2) sec = ""; continue }
            blanks = 0
            rest = ""; c = index(t, ":"); if (c) rest = trim(substr(t, c + 1))
            # ---- headings
            if (lb ~ /^(authori[sz]ed )?(administrators?|admins?) ?:/ || lb ~ /^(authori[sz]ed )?(administrators?|admins?)$/) {
                sec = "admins"; last = ""; if (rest != "") takenames(rest); continue
            }
            if (lb ~ /^(authori[sz]ed )?((standard|normal|regular|other) )?users? ?:/ || lb ~ /^(authori[sz]ed )?((standard|normal|regular|other) )?users?$/) {
                sec = "users"; last = ""; if (rest != "") takenames(rest); continue
            }
            if (l ~ /critical service/ || l ~ /services? (are|is) critical/ || l ~ /required service/) {
                sec = "crit"; critn = 0; W = "c"; CRITSEEN = 1
                if (c) { scan(norm(rest), 1); if (tolower(rest) ~ /^(none|n\/a|no critical services?)\.?$/) NONEH = 1 }
                else if (nw(t) > 3) scan(norm(t), 1)
                continue
            }
            # ---- inside a section
            if (sec == "crit") {
                if (t ~ /:$/ || nw(t) > 12) sec = ""
                else {
                    critn++; W = "c"; scan(norm(t), 1)
                    if (lb ~ /^(none|n\/a|no critical services?)\.?$/) NONEH = 1
                    continue
                }
            }
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
            W = "f"; scan(norm(t), 0)
        }
        for (i = 1; i <= NA; i++) print "A " AO[i]
        for (i = 1; i <= NU; i++) print ((UO[i] in A) ? "DUP " : "U ") UO[i]
        if (YOU != "") print "YOU " YOU
        n = split("ssh vsftpd apache2 nginx php mysql postgresql samba bind9 mail wordpress openvpn squid", S, " ")
        got = 0; for (i = 1; i <= n; i++) if (S[i] in CH) { print "S " S[i]; got++ }
        if (got) print "SRC crit"
        else if (NONEH) { print "S none"; print "SRC none" }
        else { for (i = 1; i <= n; i++) if (S[i] in FH) { print "S " S[i]; got++ }; if (got) print "SRC text" }
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

# Parse $1 (README text) into P_ADMINS P_USERS P_DUPS P_YOU P_SVCS P_SVCSRC P_WEAK.
# The text goes to awk through a pipe (no temp file: it holds the README passwords).
rd_parse_text() {
    local rec tag a b
    P_ADMINS=""; P_USERS=""; P_DUPS=""; P_YOU=""; P_SVCS=""; P_SVCSRC=""; P_WEAK=""
    rec="$(printf '%s\n' "$1" | rd_parse)"
    while read -r tag a b; do
        case "$tag" in
            A) P_ADMINS+=" $a" ;; U) P_USERS+=" $a" ;; DUP) P_DUPS+=" $a" ;; YOU) P_YOU="$a" ;;
            S) P_SVCS+=" $a" ;; SRC) P_SVCSRC="$a" ;; W) P_WEAK+=" $a:$b" ;;
        esac
    done < <(printf '%s\n' "$rec")
    P_ADMINS="${P_ADMINS# }"; P_USERS="${P_USERS# }"; P_DUPS="${P_DUPS# }"; P_SVCS="${P_SVCS# }"; P_WEAK="${P_WEAK# }"
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

# typed services (numbers 1-13, names, synonyms) -> services/*.sh names, or "none"
rd_svc_tokens() {
    local w s out="" all
    read -ra all <<< "$RD_SVCS"
    for w in $(echo "${*,,}" | tr ',;' '  '); do
        s=""
        case "$w" in
            none|0|-|no|n/a) echo none; return ;;
            [1-9]|1[0-3]) s="${all[$((w - 1))]}" ;;
            ssh|sshd|openssh|openssh-server) s=ssh ;;
            ftp|ftps|vsftpd|vsftp|proftpd|pure-ftpd|pureftpd) s=vsftpd ;;
            apache|apache2|httpd) s=apache2 ;;
            nginx) s=nginx ;;
            php|php-fpm) s=php ;;
            mysql|mariadb|mysqld) s=mysql ;;
            postgres|postgresql|psql|pgsql) s=postgresql ;;
            samba|smb|smbd|cifs) s=samba ;;
            bind|bind9|dns|named) s=bind9 ;;
            mail|email|postfix|dovecot|smtp|imap|pop3) s=mail ;;
            wordpress|wp) s=wordpress ;;
            openvpn|vpn) s=openvpn ;;
            squid|proxy) s=squid ;;
            *) cp_warn "Unknown service '$w' (ignored)" >&2 ;;
        esac
        [ -n "$s" ] && [[ " $out " != *" $s "* ]] && out+=" $s"
    done
    # canonical order
    local o=""; for s in $RD_SVCS; do [[ " $out " == *" $s "* ]] && o+=" $s"; done
    echo "${o# }"
}

rd_pick_services() {   # $1 = default ("" = none: Enter re-asks), $2 = hint -> echoes the choice ("" = no TTY)
    local def="${1:-}" hint="${2:-}" i=1 s line="" ans q
    for s in $RD_SVCS; do
        case "$s" in vsftpd) s="vsftpd(FTP)";; mysql) s="mysql(MariaDB)";; bind9) s="bind9(DNS)";; mail) s="mail(Postfix/Dovecot)";; esac
        line+=" $i=$s"; i=$((i + 1))
    done
    [ -t 0 ] || { echo ""; return; }       # never decided without a terminal
    echo "  Services:$line" >&2
    if [ -n "$def" ]; then q="Critical services in the README - numbers or names, Enter = $def"
    else q="Critical services in the README${hint:+ (the text mentions: $hint)} - type numbers or names, or none"; fi
    while :; do
        ans="$(cp_read "$q" "$def")"
        if [ -z "${ans//[[:space:]]/}" ]; then cp_warn "No default here - type e.g. 1 or ssh, several like 1 3, or none" >&2; continue; fi
        ans="$(rd_svc_tokens "$ans")"
        [ -n "$ans" ] && { echo "$ans"; return; }
        cp_warn "Nothing recognised - type e.g. 1 3, or ssh apache2, or none" >&2
    done
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

# installed-check for the services/*.sh names (one dpkg-query for all)
RD_PKGS=""
rd_installed() {
    [ -n "$RD_PKGS" ] || RD_PKGS=" $(dpkg-query -W -f='${Status} ${Package}\n' 2>/dev/null | awk '$3 == "installed" {printf "%s ", $4}')"
    local re
    case "$1" in
        ssh) re='openssh-server' ;; vsftpd) re='vsftpd' ;; apache2) re='apache2' ;; nginx) re='nginx(-core|-full|-light|-extras)?' ;;
        php) re='(php[0-9.]*(-fpm|-cli)?|libapache2-mod-php[0-9.]*)' ;; mysql) re='(mysql|mariadb)-server(-core)?(-[0-9.]+)?' ;;
        postgresql) re='postgresql-[0-9]+' ;; samba) re='samba' ;; bind9) re='bind9' ;; mail) re='(postfix|dovecot-core)' ;;
        openvpn) re='openvpn' ;; squid) re='squid[0-9]?' ;;
        wordpress)
            [[ "$RD_PKGS" == *" wordpress "* ]] && return 0
            compgen -G "/var/www/*/wp-config.php" >/dev/null || compgen -G "/var/www/*/*/wp-config.php" >/dev/null || compgen -G "/srv/www/*/wp-config.php" >/dev/null
            return ;;
        *) return 1 ;;
    esac
    [[ "$RD_PKGS" =~ \ $re\  ]]
}

rd_check_installed() {   # warn when README and the image disagree
    local s miss="" extra=""
    for s in $SERVICES; do [ "$s" = none ] && continue; rd_installed "$s" || miss+=" $s"; done
    for s in $RD_SVCS; do [[ " $SERVICES " == *" $s "* ]] && continue; rd_installed "$s" && extra+=" $s"; done
    for s in $miss; do
        if [ "$s" = vsftpd ] && [[ "$RD_PKGS" =~ \ (pure-ftpd[a-z-]*|proftpd[a-z-]*)\  ]]; then
            cp_todo "README FTP server is ${BASH_REMATCH[1]}, not vsftpd - services/vsftpd.sh does not cover it, harden it by hand"
        else
            cp_todo "README lists '$s' as critical but it is not installed - re-check the README (install it? other name?)"
        fi
    done
    [ -n "$extra" ] && cp_warn "Installed but NOT critical in the README:$extra (fileandpackage.sh offers removal - check the README first)"
}

# "none" while service packages are installed: everything would be offered for removal -> [y/N]
rd_confirm_none() {
    [ "$SERVICES" = none ] || return 0
    local s inst=""
    for s in ssh vsftpd apache2 nginx samba mysql postgresql bind9 mail squid openvpn; do
        rd_installed "$s" || continue
        case "$s" in ssh) inst+=" openssh-server" ;; mysql) inst+=" mysql/mariadb" ;; mail) inst+=" postfix/dovecot" ;; *) inst+=" $s" ;; esac
    done
    [ -z "$inst" ] && return 0
    cp_ask "README lists NO critical services, but these are installed and will be offered for removal:$inst - correct?" n
}

rd_show() {
    local k v
    if [ ! -f "$CP_CFG" ]; then echo "  (no README answers saved yet: sudo bash readme.sh)"; return 1; fi
    echo "  README answers ($CP_CFG):"
    for k in ADMINS USERS ME SERVICES WEAKPW GROUPS; do
        cp_cfg_has "$k" || continue; v="$(cp_cfg_get "$k")"; printf '    %-9s %s\n' "$k" "${v:--}"
    done
    grep -vE "^(ADMINS|USERS|ME|SERVICES|WEAKPW|GROUPS)=" "$CP_CFG" | awk -F= '{ k = $1; sub(/^[^=]*=/, ""); printf "    %-9s %s\n", k, $0 }'
    return 0
}

rd_summary() {
    local na nu
    na=$(wc -w <<< "$ADMINS"); nu=$(wc -w <<< "$USERS")
    cp_hdr "README summary"
    printf '  Admins (%s): %s\n' "$na" "${ADMINS:--}"
    printf '  Users  (%s): %s\n' "$nu" "${USERS:--}"
    printf '  You       : %s%s\n' "${ME:-?}" "$( [ -n "$P_YOU" ] && [ "$P_YOU" != "$ME" ] && echo "   (README marks $P_YOU as (you)!)")"
    printf '  Critical  : %s%s\n' "${SERVICES:-? (not saved - scripts that need it will ask)}" "$([ "${RD_SVC_UNKNOWN:-0}" = 1 ] || case "$P_SVCSRC" in crit) echo "   (from the README's critical services)";; text) echo "   (guessed from product names - check)";; none) echo "   (README says none)";; esac)"
    [ -n "$P_WEAK" ] && printf '  Weak README passwords: %s\n' "$P_WEAK"
    [ -n "$P_DUPS" ] && cp_warn "Listed as admin AND user (kept as admin): $P_DUPS"
    return 0
}

# Read the paste. Ends at an empty line after the users list, two empty lines in a row, or Ctrl-D.
# Whatever else was pasted (rest of a whole-page paste) is drained so it cannot answer later prompts.
rd_read_paste() {
    local line low n=0 users_head=0 users_n=0 prev_blank=0
    PASTE=""
    if [ -t 0 ]; then
        cp_hdr "README intake (asked once, used by every script)"
        echo "  1. Click anywhere in the README page, press Ctrl-A (select ALL - the critical services are above"
        echo "     the user lists), then Ctrl-C."
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

# Paste (or file) -> ADMINS USERS ME SERVICES WEAK, with manual fallbacks.
rd_intake_text() {
    local live
    rd_parse_text "$PASTE"
    ADMINS="$P_ADMINS"; USERS="$P_USERS"; SERVICES="$P_SVCS"; WEAK="$P_WEAK"
    if [ -z "$ADMINS" ]; then
        cp_warn "No 'Authorized Administrators' list found - type the names instead."
        ADMINS="$(rd_names "$(cp_read "Authorized administrators (space-separated, yours too)" "")")"
        [ -n "$USERS" ] || USERS="$(rd_names "$(cp_read "Authorized users (space-separated, Enter = none)" "")")"
    fi
    live="$(rd_me_live)"
    ME="${live:-${CP_ME:-$P_YOU}}"
    case "$P_SVCSRC" in
        crit|none) SERVICES="$P_SVCS" ;;
        *)  [ -t 0 ] && cp_warn "No 'Critical Services' section in the paste - type them from the README (no default)"
            SERVICES="$(rd_pick_services "" "$P_SVCS")" ;;
    esac
    # never saved without a terminal (only CP_SERVICES may do that)
    if [ -t 0 ] && [ -n "$SERVICES" ]; then RD_SVC_UNKNOWN=0; else RD_SVC_UNKNOWN=1; SERVICES=""; fi
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

rd_save() {
    cp_cfg_set ADMINS $ADMINS
    cp_cfg_set USERS $USERS
    cp_cfg_set ME $ME
    cp_cfg_set WEAKPW $WEAK
    if [ "${RD_SVC_UNKNOWN:-0}" = 1 ]; then
        cp_warn "SERVICES not saved (no terminal answer / CP_SERVICES not set) - scripts that need it will ask"
    else
        cp_cfg_set SERVICES "${SERVICES:-none}"
    fi
    cp_ok "Saved README answers -> $CP_CFG   (see: sudo bash readme.sh --show)"
    [ -z "$ME" ] && cp_warn "Could not tell which account is yours - set it: sudo bash readme.sh --reset"
    [ "${RD_SVC_UNKNOWN:-0}" = 1 ] || rd_check_installed
    return 0
}

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

# ----------------------------------------------------------------- main --
MODE=intake FILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --show) MODE=show ;;
        --reset) MODE=reset ;;
        --if-missing) MODE=ifmissing ;;
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
    printf 'ADMINS=%s\nUSERS=%s\nYOU=%s\nSERVICES=%s\nSRC=%s\nWEAKPW=%s\nDUPS=%s\n' \
        "$P_ADMINS" "$P_USERS" "$P_YOU" "$P_SVCS" "$P_SVCSRC" "$P_WEAK" "$P_DUPS"
    exit 0
fi

[ -n "$FILE" ] && [ ! -r "$FILE" ] && { cp_err "Cannot read $FILE - nothing changed"; exit 1; }
cp_require_root
case "$MODE" in
    show) rd_show; exit ;;
    ifmissing) if cp_cfg_has ADMINS && [ -n "$(cp_cfg_get ADMINS)" ]; then cp_ok "README answers already saved ($(cp_cfg_get ADMINS | wc -w) admins, $(cp_cfg_get USERS | wc -w) users)"; exit 0; fi ;;
    reset)
        if [ -f "$CP_CFG" ]; then
            cp_backup "$CP_CFG"
            sed -i -E "/^(${RD_KEYS// /|}|GROUPS)=/d" "$CP_CFG"
            cp_ok "Forgot the saved README answers"
        fi ;;
esac

# Non-interactive: CP_ADMINS / CP_USERS / CP_SERVICES
if [ -n "${CP_ADMINS:-}" ]; then
    P_YOU=""; P_SVCSRC=""; P_WEAK=""; P_DUPS=""; WEAK=""
    ADMINS="$(rd_names "$CP_ADMINS")"; USERS="$(rd_names "${CP_USERS:-}")"
    for u in $USERS; do [[ " $ADMINS " == *" $u "* ]] && USERS="$(echo " $USERS " | sed "s/ $u / /; s/^ //; s/ $//")"; done
    if [ -n "${CP_SERVICES+x}" ]; then SERVICES="$(rd_svc_tokens "${CP_SERVICES:-none}")"; RD_SVC_UNKNOWN=0
    else SERVICES=""; RD_SVC_UNKNOWN=1; fi
    ME="$(rd_me_live)"; ME="${ME:-${CP_ME:-}}"
    rd_fix_me
    cp_info "README from environment: admins: $ADMINS | users: ${USERS:--} | you: ${ME:-?} | critical: ${SERVICES:-not set}"
    rd_save
    exit 0
fi

# Interactive: answers already saved?
if [ "$MODE" = intake ] && cp_cfg_has ADMINS && [ -n "$(cp_cfg_get ADMINS)" ]; then
    rd_show
    cp_ask "Keep these README answers?" y && exit 0
fi

if [ -n "$FILE" ]; then
    [ -r "$FILE" ] || { cp_err "Cannot read $FILE"; exit 1; }
    if grep -qi '<html\|<pre\|<br' "$FILE"; then PASTE="$(rd_html2text "$FILE")"; else PASTE="$(cat "$FILE")"; fi
elif [ -t 0 ]; then
    rd_read_paste
else
    rd_read_paste                           # piped README text
    [ -n "${PASTE//[[:space:]]/}" ] || { cp_err "No README text on stdin and no CP_ADMINS - nothing saved"; exit 1; }
fi
rd_intake_text
rd_fix_me

while :; do
    rd_summary
    ans="$(cp_read "Correct? Enter = yes | a = admins  u = users  m = you  s = services  p = paste again" y)"
    case "${ans,,}" in
        y|yes)
            if [ "$RD_SVC_UNKNOWN" = 0 ] && ! rd_confirm_none; then
                SERVICES="$(rd_pick_services "")"; [ -n "$SERVICES" ] || RD_SVC_UNKNOWN=1; continue
            fi
            break ;;
        a) ADMINS="$(rd_names "$(cp_read "Authorized administrators (space-separated)" "$ADMINS")")"; rd_fix_me ;;
        u) ans="$(cp_read "Authorized users (space-separated, - = none)" "$USERS")"
           [ "$ans" = - ] && USERS="" || USERS="$(rd_names "$ans")" ;;
        m) ME="$(rd_names "$(cp_read "Your account" "$ME")")"; rd_fix_me ;;
        s) SERVICES="$(rd_pick_services "$SERVICES")"; [ -n "$SERVICES" ] && RD_SVC_UNKNOWN=0 ;;
        p) rd_read_paste; rd_intake_text; rd_fix_me ;;
        *) cp_warn "Type y (or Enter), a, u, m, s or p" ;;
    esac
    for u in $USERS; do [[ " $ADMINS " == *" $u "* ]] && USERS="$(echo " $USERS " | sed "s/ $u / /; s/^ //; s/ $//")"; done
done
unset PASTE
rd_save
exit 0
