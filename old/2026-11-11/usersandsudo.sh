#!/bin/bash
# usersandsudo.sh - accounts, admin rights, UID 0 accounts, passwords, README groups, sudoers.
#   sudo bash usersandsudo.sh      (from inside competition/)      -h = this help
# README facts (admins, users, your account) come from readme.sh - asked once, saved in /root/cp-state/readme.conf.
# If they are not saved yet, readme.sh runs first. Wrong? sudo bash readme.sh --reset, then run this again.
# Order: UID 0 accounts -> accounts not in the README (one list, one answer) -> missing README accounts ->
# admin groups (one list) -> one strong password for the README users -> empty passwords, aging, home folders
# (automatic with CP_AUTO=1) -> README groups -> sudoers NOPASSWD / sudo rights -> re-check.
# Never touched: root and your own account. Everything changed is backed up to /root/cp-backups/<timestamp>/.
# Anything left for a human is a TODO (red, and collected in /root/cp-state/TODO.txt).
# shellcheck disable=SC2034  # used by cp-common.sh (cp_todo tag)
CP_SCRIPT_NAME=usersandsudo.sh
# shellcheck source=cp-common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/cp-common.sh"

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }
case "${1:-}" in -h|--help) usage; exit 0 ;; "") ;; *) echo "Unknown option: $1 (see -h)"; exit 2 ;; esac

cp_require_root
cp_screenshot_prompt

# ------------------------------------------------------------- helpers --
inlist()  { local x="$1"; shift; [[ " $* " == *" $x "* ]]; }
is_auth()  { inlist "$1" "${ADMINS[@]}" "${USERS[@]}"; }
is_admin() { inlist "$1" "${ADMINS[@]}"; }
is_prot()  { inlist "$1" "${PROTECT[@]}"; }
exists()   { getent passwd "$1" >/dev/null; }
# exact group names: "admin" must not match "lpadmin" (Mint/Ubuntu desktop default group)
has_admin() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel'; }
backup_accounts() { cp_backup /etc/passwd /etc/shadow /etc/group /etc/gshadow; }
# yne "Question" [default] -> echoes y (all), n (none) or e (ask for each)
yne() {
    local a; a="$(cp_read "$1 y = all, n = none, e = ask each" "${2:-y}")"
    case "${a,,}" in e*) echo e ;; y*) echo y ;; *) echo n ;; esac
}
# rewrite FILE through an awk filter, keeping inode/owner/mode (passwd, shadow)
awk_inplace() {
    local f="$1" tmp; shift
    tmp="$(mktemp)" && awk "$@" "$f" > "$tmp" && [ -s "$tmp" ] && cat "$tmp" > "$f"
    rm -f "$tmp"
}
me_live() {   # SUDO_USER, else whoever logged in (logname / login UID)
    local u="${SUDO_USER:-}" luid
    [ -z "$u" ] || [ "$u" = root ] && u="$(logname 2>/dev/null)"
    if [ -z "$u" ] || [ "$u" = root ]; then
        luid="$(cat /proc/self/loginuid 2>/dev/null)"
        [ -n "$luid" ] && [ "$luid" != 4294967295 ] && u="$(getent passwd "$luid" | cut -d: -f1)"
    fi
    [ "$u" = root ] && u=""
    echo "$u"
}
strong_pw() {  # same policy systemconfig.sh sets: 12+ chars with upper, lower, digit and symbol
    [ ${#1} -ge 12 ] && [[ "$1" =~ [[:upper:]] ]] && [[ "$1" =~ [[:lower:]] ]] && [[ "$1" =~ [[:digit:]] ]] && [[ "$1" =~ [^[:alnum:]] ]]
}

# Human accounts that the README does not list (also "hidden" ones: system-range UID with a real home
# under /home, /tmp or /var/tmp). Sets UNAUTH (names) and UNAUTH_INFO (display lines).
find_unauth() {
    local u uid home shell kind ag
    UNAUTH=(); UNAUTH_INFO=()
    while IFS=: read -r u _ uid _ _ home shell; do
        [ "$uid" = 0 ] && continue                       # UID 0 duplicates: own step
        is_prot "$u" || is_auth "$u" && continue
        kind=""
        if [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ]; then :
        elif [ "$uid" -lt 1000 ] && [ "$u" != syslog ] && [[ "$home" =~ ^/(home|tmp|var/tmp)/. ]] && [ -d "$home" ]; then
            kind="hidden: system-range UID, home $home"
        elif [ "$uid" -ge 60000 ] && [ "$uid" -ne 65534 ] && [[ "$home" == /home/?* ]] && [[ ! "$shell" =~ (nologin|false)$ ]]; then
            kind="high UID with a login shell"
        else continue; fi
        ag="$(id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -xE 'sudo|admin|wheel|adm' | tr '\n' ' ')"
        UNAUTH+=("$u")
        UNAUTH_INFO+=("$(printf '%-12s UID %-6s %s%s' "$u" "$uid" "${ag:+[in ${ag% }] }" "$kind")")
    done < /etc/passwd
}

# Admin-group mismatches. Sets FIX_ADD (README admins without sudo/admin/wheel) and FIX_RM / FIX_RMG
# (non-admins in sudo/admin/wheel, or a human account in adm; syslog etc. in adm are stock). Root, your own
# account and primary-group membership are handled.
find_group_fixes() {
    local g u uid gs gid mm
    local -A seen=() gidname=()
    FIX_ADD=(); FIX_RM=(); FIX_RMG=()
    for u in "${ADMINS[@]}"; do exists "$u" && ! has_admin "$u" && FIX_ADD+=("$u"); done
    local cand=()
    for g in sudo admin wheel adm; do
        IFS=, read -ra mm <<< "$(getent group "$g" | cut -d: -f4)"; cand+=("${mm[@]}")
        gid="$(getent group "$g" | cut -d: -f3)"; [ -n "$gid" ] && gidname[$gid]="$g"
    done
    while IFS=: read -r u _ _ gid _; do [ -n "${gidname[$gid]:-}" ] && cand+=("$u"); done < /etc/passwd
    for u in "${cand[@]}"; do
        [ -n "${seen[$u]:-}" ] && continue; seen[$u]=1
        [ "$u" = root ] && continue
        exists "$u" || continue
        is_admin "$u" && continue
        uid="$(id -u "$u")"; gs=""
        for g in $(id -nG "$u"); do
            case "$g" in sudo|admin|wheel) gs+=" $g" ;; adm) [ "$uid" -ge 1000 ] && gs+=" adm" ;; esac
        done
        [ -n "$gs" ] || continue
        if is_prot "$u"; then cp_warn "$u (your account) is not a README admin but is in${gs} - left alone"; continue; fi
        FIX_RM+=("$u"); FIX_RMG+=("${gs# }")
    done
}

rm_from_groups() {  # user "g1 g2"
    local u="$1" g pg own
    pg="$(id -gn "$u")"
    for g in $2; do
        if [ "$g" = "$pg" ]; then   # primary group: gpasswd -d cannot remove it
            own="$(getent group "$u" >/dev/null && echo "$u" || echo users)"
            usermod -g "$own" "$u"
        else
            gpasswd -d "$u" "$g" >/dev/null 2>&1
        fi
    done
}

del_account() {
    local u="$1" home uid shared
    home="$(getent passwd "$u" | cut -d: -f6)"; uid="$(getent passwd "$u" | cut -d: -f3)"
    # another account with the same UID or home (planted duplicate)? then no pkill and no userdel -r
    shared="$(awk -F: -v u="$u" -v id="$uid" -v h="$home" '$1 != u && ($3 == id || $6 == h) {printf "%s ", $1}' /etc/passwd)"
    backup_accounts
    [ -n "$shared" ] && cp_warn "$u shares its UID or home with: $shared- deleting only the account entry"
    [ -z "$shared" ] && { pkill -KILL -u "$u" 2>/dev/null; sleep 0.2; }
    local note="home kept: $home"
    if [ -z "$shared" ] && [[ "$home" =~ ^/home/[^/]+$ ]] && [ -d "$home" ]; then
        mkdir -p "$CP_BACKUP_ROOT/$CP_TS/homes" && tar -czf "$CP_BACKUP_ROOT/$CP_TS/homes/$u.tgz" -C / "${home#/}" 2>/dev/null
        userdel -r "$u" >/dev/null 2>&1 || userdel -f -r "$u" >/dev/null 2>&1
        note="home backed up to $CP_BACKUP_ROOT/$CP_TS/homes/$u.tgz"
    else
        userdel "$u" >/dev/null 2>&1 || userdel -f "$u" >/dev/null 2>&1   # never -r on a shared/system home
    fi
    if exists "$u"; then cp_err "Could not delete $u"; cp_todo "Delete account $u by hand: sudo userdel -r $u"; return 1; fi
    cp_ok "Deleted $u ($note)"
}

# sudoers: NOPASSWD / !authenticate, and sudo rights for anyone who is not root, %sudo, %admin or a README
# admin. Prints "LINE<TAB>WHY<TAB>TEXT". Linux Mint's 3 stock /etc/sudoers.d/mintupdate lines are skipped.
MINT_STOCK='^[[:space:]]*ALL[[:space:]]+ALL[[:space:]]*=[[:space:]]*NOPASSWD:[[:space:]]*/usr/(bin/mint-refresh-cache|lib/linuxmint/mintUpdate/(synaptic-workaround\.py|dpkg_lock_check\.sh))[[:space:]]*$'
sudo_findings() {
    local f="$1" n why text
    awk -v allow=" root %sudo %admin ${ADMINS[*]} " '
        { t = $0; sub(/^[ \t]+/, "", t) }
        t == "" || t ~ /^#/ || t ~ /^@include/ { next }
        { why = "" }
        t ~ /NOPASSWD|!authenticate/ { why = "NOPASSWD/!authenticate" }
        t !~ /^Defaults/ && t !~ /^(User|Runas|Host|Cmnd)_Alias/ {
            split(t, a, /[ \t]+/); np = split(a[1], p, ",")
            for (i = 1; i <= np; i++) if (index(allow, " " p[i] " ") == 0) {
                why = why (why == "" ? "" : "; ") "sudo rights for " p[i] " (not a README admin)"; break }
        }
        why != "" { print FNR "\t" why "\t" $0 }' "$f" 2>/dev/null |
    while IFS=$'\t' read -r n why text; do
        [[ "$text" =~ $MINT_STOCK ]] && continue
        printf '%s\t%s\t%s\n' "$n" "$why" "$text"
    done
}
sudo_files() { local f; for f in /etc/sudoers /etc/sudoers.d/*; do [ -f "$f" ] && [ "$f" != /etc/sudoers.d/README ] && echo "$f"; done; }

# --------------------------------------------------------- README facts --
cp_hdr "Users and sudo"
if ! cp_cfg_has ADMINS || [ -z "$(cp_cfg_get ADMINS)" ]; then
    cp_info "README answers are not saved yet -> readme.sh"
    bash "$CP_ROOT/readme.sh" || { cp_err "readme.sh did not finish - nothing changed"; exit 1; }
fi
read -ra ADMINS <<< "$(cp_cfg_get ADMINS)"
read -ra USERS <<< "$(cp_cfg_get USERS)"
ME_CFG="$(cp_cfg_get ME)"
ME="$(me_live)"; ME="${ME:-$ME_CFG}"
PROTECT=(root); [ -n "$ME" ] && PROTECT+=("$ME"); [ -n "$ME_CFG" ] && PROTECT+=("$ME_CFG")
if [ ${#ADMINS[@]} -eq 0 ]; then cp_err "No authorized admins saved - refusing to change accounts. Run: sudo bash readme.sh --reset"; exit 1; fi
[ -n "$ME" ] || cp_warn "Could not tell which account is yours (no SUDO_USER / login UID / ME) - only root is protected"
[ -n "$ME_CFG" ] && [ "$ME" != "$ME_CFG" ] && cp_warn "You are '$ME' but readme.sh saved ME=$ME_CFG - both are protected"
cp_info "README: admins: ${ADMINS[*]} | users: ${USERS[*]:-none} | you: ${ME:-?}   (wrong? sudo bash readme.sh --reset)"

# ------------------------------------------------------- UID 0 accounts --
cp_hdr "UID 0 accounts"
UID0="$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)"
[ -z "$UID0" ] && cp_ok "Only root has UID 0"
for u in $UID0; do
    cp_warn "CRITICAL: $u has UID 0 (a second root account)"
    # usermod/userdel refuse here ("user is currently used by process 1"): UID 0 always has processes,
    # so the line is deleted / the UID edited directly (backup first) and the result verified.
    if is_prot "$u"; then cp_todo "$u (your account) has UID 0 - fix /etc/passwd by hand"; continue; fi
    if ! is_auth "$u" && cp_ask "Delete account $u (recommended unless the README names it)?" y; then
        backup_accounts
        awk_inplace /etc/passwd -F: -v u="$u" '$1 != u'
        awk_inplace /etc/shadow -F: -v u="$u" '$1 != u'
        if exists "$u"; then cp_todo "$u still exists - remove its line from /etc/passwd by hand"; else cp_ok "Deleted $u (backup: $CP_BACKUP_ROOT/$CP_TS)"; fi
    elif cp_ask "Give $u a normal UID instead?" y; then
        backup_accounts
        new_uid=1500; while getent passwd "$new_uid" >/dev/null; do new_uid=$((new_uid + 1)); done
        ugid="$(getent group users | cut -d: -f3)"
        awk_inplace /etc/passwd -F: -v OFS=: -v u="$u" -v n="$new_uid" -v g="${ugid:-100}" '$1 == u && $3 == 0 { $3 = n; if ($4 == 0) $4 = g } { print }'
        if [ "$(id -u "$u" 2>/dev/null)" = "$new_uid" ]; then cp_ok "$u now has UID $new_uid"; else cp_todo "Could not change the UID of $u - fix /etc/passwd by hand"; fi
    else
        cp_todo "$u has UID 0 - delete it or give it a normal UID (edit /etc/passwd)"
    fi
done

# ------------------------------------------- accounts not in the README --
cp_hdr "Accounts not in the README"
find_unauth
if [ ${#UNAUTH[@]} -eq 0 ]; then
    cp_ok "Every human account is in the README"
else
    cp_warn "Not in the README (${#UNAUTH[@]}):"
    printf '        %s\n' "${UNAUTH_INFO[@]}"
    def=y
    nh=$(awk -F: '$3 >= 1000 && $3 < 60000' /etc/passwd | wc -l)
    if [ ${#UNAUTH[@]} -gt 3 ] && [ $((${#UNAUTH[@]} * 2)) -gt "$nh" ]; then
        def=n; cp_warn "That is most of the accounts - check the README answers first (sudo bash readme.sh --show)"
    fi
    case "$(yne "Delete these ${#UNAUTH[@]} accounts (homes are backed up)?" "$def")" in
        y) for u in "${UNAUTH[@]}"; do del_account "$u"; done ;;
        e) for u in "${UNAUTH[@]}"; do cp_ask "Delete $u?" y && del_account "$u"; done ;;
        *) cp_info "Kept them" ;;
    esac
fi
SYS_SHELL="$(awk -F: '$3 > 0 && $3 < 1000 && $7 !~ /(nologin|false|sync)$/ {printf "%s ", $1}' /etc/passwd)"
[ -n "$SYS_SHELL" ] && cp_info "System accounts with a login shell: ${SYS_SHELL}(systemconfig.sh sets nologin; postgres is left alone)"

# ------------------------------------------------ missing README accounts --
MISSING=(); NEW=()
for u in "${ADMINS[@]}" "${USERS[@]}"; do exists "$u" || MISSING+=("$u"); done
if [ ${#MISSING[@]} -gt 0 ]; then
    cp_hdr "README accounts that do not exist"
    echo "        ${MISSING[*]}"
    if cp_ask "Create these ${#MISSING[@]} accounts (admins also get sudo)?" y; then
        backup_accounts
        for u in "${MISSING[@]}"; do
            if useradd -m -s /bin/bash "$u" 2>/dev/null; then
                is_admin "$u" && usermod -aG sudo "$u"
                NEW+=("$u"); cp_ok "Created $u$(is_admin "$u" && echo ' (sudo)')"
            else cp_err "useradd $u failed"; cp_todo "Create README account $u by hand"; fi
        done
    else
        cp_todo "README accounts missing: ${MISSING[*]} (sudo useradd -m -s /bin/bash NAME)"
    fi
fi

# ----------------------------------------------------------- admin groups --
cp_hdr "Admin rights (exact groups sudo/admin/wheel/adm - lpadmin is not one)"
find_group_fixes
if [ $((${#FIX_ADD[@]} + ${#FIX_RM[@]})) -eq 0 ]; then
    cp_ok "Admin groups match the README"
else
    for u in "${FIX_ADD[@]}"; do printf '        + %-12s add to sudo        (README admin; groups now: %s)\n' "$u" "$(id -nG "$u")"; done
    for i in "${!FIX_RM[@]}"; do
        u="${FIX_RM[$i]}"
        printf '        - %-12s remove from %-6s (%s)\n' "$u" "${FIX_RMG[$i]}" "$(is_auth "$u" && echo 'README standard user' || echo 'not in the README')"
    done
    n=$((${#FIX_ADD[@]} + ${#FIX_RM[@]}))
    ans="$(yne "Apply these $n admin-group fixes?" y)"
    [ "$ans" = n ] || backup_accounts
    for u in "${FIX_ADD[@]}"; do
        [ "$ans" = y ] || { [ "$ans" = e ] && cp_ask "Add $u to sudo group?" y; } || continue
        usermod -aG sudo "$u" && cp_ok "$u added to sudo"
    done
    for i in "${!FIX_RM[@]}"; do
        u="${FIX_RM[$i]}"
        [ "$ans" = y ] || { [ "$ans" = e ] && cp_ask "Remove $u from ${FIX_RMG[$i]}?" y; } || continue
        rm_from_groups "$u" "${FIX_RMG[$i]}" && cp_ok "$u removed from ${FIX_RMG[$i]}"
    done
fi

# -------------------------------------------------------------- passwords --
cp_hdr "Passwords"
declare -A WEAK=()
for e in $(cp_cfg_get WEAKPW); do WEAK[${e%%:*}]="${e#*:}"; done
# PWSET (state key in readme.conf): accounts this script already gave the new password - offered once only
read -ra PWDONE <<< "$(cp_cfg_get PWSET)"
OTHERS=()
for u in "${ADMINS[@]}" "${USERS[@]}"; do exists "$u" && ! is_prot "$u" && ! inlist "$u" "${PWDONE[@]}" && OTHERS+=("$u"); done
[ ${#PWDONE[@]} -gt 0 ] && cp_info "New password already set in an earlier run for: ${PWDONE[*]}"
wl=""; for u in "${!WEAK[@]}"; do exists "$u" && wl+=" $u(${WEAK[$u]})"; done
[ -n "$wl" ] && cp_warn "README passwords that look weak:$wl"
EMPTY="$(awk -F: '$2 == "" {printf "%s ", $1}' /etc/shadow)"
[ -n "$EMPTY" ] && cp_warn "EMPTY password (anyone can log in): ${EMPTY% }"
PW_SET=0
if [ ${#OTHERS[@]} -gt 0 ]; then
    cp_info "README passwords are often weak and 'insecure password' fixes are commonly scored."
    shown="${OTHERS[*]:0:6}"; [ ${#OTHERS[@]} -gt 6 ] && shown+=" +$(( ${#OTHERS[@]} - 6 )) more"
    if cp_ask "Set ONE new strong password for the ${#OTHERS[@]} README users except you ($shown)?" y; then
        if [ ! -t 0 ]; then
            cp_warn "Needs a terminal to type the password - skipped"
        else
            echo "  Type it twice (12+ characters with upper, lower, digit and symbol; Enter alone = cancel)."
            for _try in 1 2 3; do
                read -r -s -p "  ? New password: " P1; echo
                [ -z "$P1" ] && break
                read -r -s -p "  ? Retype new password: " P2; echo
                if [ "$P1" != "$P2" ]; then cp_warn "They differ - again"; P1=""; continue; fi
                if ! strong_pw "$P1"; then cp_warn "Too weak (12+ chars with upper, lower, digit and symbol) - again"; P1=""; continue; fi
                break
            done
            if [ -n "$P1" ]; then
                backup_accounts
                ok=(); bad=()
                for u in "${OTHERS[@]}"; do
                    if printf '%s:%s\n' "$u" "$P1" | chpasswd 2>/dev/null; then ok+=("$u"); else bad+=("$u"); fi
                done
                [ ${#ok[@]} -gt 0 ] && { PW_SET=1; cp_cfg_set PWSET "${PWDONE[@]}" "${ok[@]}"
                    cp_ok "New password set for: ${ok[*]}"; cp_todo "WRITE DOWN the new password you set for: ${ok[*]}"; }
                [ ${#bad[@]} -gt 0 ] && cp_todo "chpasswd failed for: ${bad[*]} - sudo passwd NAME"
            else
                cp_info "No password set"
            fi
            unset P1 P2
        fi
    fi
fi
for u in "${!WEAK[@]}"; do
    exists "$u" || continue
    if is_prot "$u"; then cp_warn "Your own README password looks weak (${WEAK[$u]}). READMEs say the auto-login account's password need NOT be changed (it can lock you out) - only change it if the README asks, and write it down"
    elif [ "$PW_SET" = 0 ] && ! inlist "$u" "${PWDONE[@]}"; then cp_todo "README password of $u is weak (${WEAK[$u]}) - change it: sudo passwd $u (write it down)"; fi
done
[ "$PW_SET" = 0 ] && [ ${#NEW[@]} -gt 0 ] && cp_todo "Set a password for the new account(s) ${NEW[*]}: sudo passwd NAME"
# empty passwords that are still there
LOCK=()
for u in $(awk -F: '$2 == "" {print $1}' /etc/shadow); do
    if is_prot "$u"; then cp_todo "Account $u (yours/root) has an EMPTY password - set one: sudo passwd $u (write it down)"
    else LOCK+=("$u"); fi
done
if [ ${#LOCK[@]} -gt 0 ]; then
    if cp_auto "Lock the ${#LOCK[@]} account(s) that still have an EMPTY password (${LOCK[*]})?" y; then
        backup_accounts
        for u in "${LOCK[@]}"; do passwd -l "$u" >/dev/null 2>&1; done
    fi
fi
left="$(awk -F: '$2 == "" {printf "%s ", $1}' /etc/shadow)"
if [ -n "$left" ]; then cp_todo "Empty password: ${left}- sudo passwd NAME (or passwd -l NAME)"
elif [ -n "$EMPTY" ]; then cp_ok "No empty passwords left"; fi

# ------------------------------------------- password aging, home folders --
cp_hdr "Password aging and home folders"
AGING=()
while IFS=: read -r u _ uid _ _ _ shell; do
    if [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ] && ! is_prot "$u" && [[ ! "$shell" =~ (nologin|false)$ ]]; then AGING+=("$u"); fi
done < /etc/passwd
# An EXPIRED password blocks PAM logins of non-interactive services (vsftpd refuses "expired password",
# Dovecot and Samba with "obey pam restrictions" too). When one of them is critical - or SERVICES is unknown
# and one is installed - no forced change (passwd -e), and no max-age that would expire a password right now.
PAMSVC=""
if cp_cfg_has SERVICES; then
    for s in vsftpd mail samba; do cp_critical "$s" && PAMSVC+=" $s"; done
else
    for s in vsftpd dovecot-core samba; do cp_pkg_installed "$s" && PAMSVC+=" ${s%-core}"; done
fi
PAMSVC="${PAMSVC# }"
if [ ${#AGING[@]} -eq 0 ]; then
    cp_info "No other login users for password aging"
elif [ -z "$PAMSVC" ]; then
    if cp_auto "Password aging 30/7/14 + forced password change at next login for ${#AGING[@]} users (not you)?" y; then
        backup_accounts
        fail=""
        for u in "${AGING[@]}"; do
            chage -M 30 -m 7 -W 14 "$u" >/dev/null 2>&1 || fail+=" $u"
            passwd -e "$u" >/dev/null 2>&1 || fail+=" $u"
        done
        [ -z "$fail" ] && cp_ok "Aging 30/7/14 and change-at-next-login set for: ${AGING[*]}" || cp_err "chage/passwd -e failed for:$fail"
    fi
elif cp_auto "Password aging 30/7/14 for ${#AGING[@]} users (not you; NO forced change at next login - $PAMSVC logins would fail)?" y; then
    backup_accounts
    fail=""; old=""; today=$(( $(date +%s) / 86400 ))
    for u in "${AGING[@]}"; do
        last="$(getent shadow "$u" | cut -d: -f3)"
        if [[ "$last" =~ ^[0-9]+$ ]] && [ $((last + 30)) -le "$today" ]; then
            chage -m 7 -W 14 "$u" >/dev/null 2>&1 || fail+=" $u"; old+=" $u"     # -M 30 would expire it now
        else
            chage -M 30 -m 7 -W 14 "$u" >/dev/null 2>&1 || fail+=" $u"
        fi
    done
    [ -z "$fail" ] && cp_ok "Aging set for: ${AGING[*]}${old:+ (max-age 30 skipped for$old: password older than 30 days)}" || cp_err "chage failed for:$fail"
    cp_todo "No forced password change at next login (critical: $PAMSVC - an expired password blocks those logins). Force it only for users who never log in there: sudo passwd -e NAME"
fi
HOMES=()
while IFS=: read -r u _ uid _ _ home _; do
    [ "$uid" -ge 1000 ] && [ "$uid" -ne 65534 ] && [[ "$home" =~ ^/home/[^/]+/?$ ]] && [ -d "$home" ] && HOMES+=("$u:$home")
done < /etc/passwd
if [ ${#HOMES[@]} -gt 0 ] && cp_auto "Home folders: mode 750, owned by their user (${#HOMES[@]} folders)?" y; then
    for e in "${HOMES[@]}"; do chmod 0750 "${e#*:}" && chown "${e%%:*}" "${e#*:}"; done
    cp_ok "750 + owner set on ${#HOMES[@]} home folders"
fi

# -------------------------------------------------- groups from the README --
cp_hdr "Groups the README asks for"
if cp_cfg_has GROUPS; then
    GSPEC="$(cp_cfg_get GROUPS)"
    [ -n "$GSPEC" ] && cp_info "Saved README groups: $GSPEC"
else
    gin="$(cp_read 'README groups, as "group: member member" ("; " between groups, Enter = none)' "")"
    GSPEC=""
    IFS=';' read -ra GPARTS <<< "$gin"
    for part in "${GPARTS[@]}"; do
        part="${part//,/ }"; part="${part/:/ }"
        read -ra W <<< "$part"
        [ ${#W[@]} -gt 0 ] || continue
        if [[ ! "${W[0]}" =~ ^[a-z_][a-z0-9_-]*$ ]]; then cp_warn "Bad group name '${W[0]}' - skipped"; continue; fi
        m="$(IFS=,; echo "${W[*]:1}")"
        GSPEC+=" ${W[0]}:$m"
    done
    GSPEC="${GSPEC# }"
    cp_cfg_set GROUPS $GSPEC
fi
for e in $GSPEC; do
    g="${e%%:*}"; m="${e#*:}"
    if ! getent group "$g" >/dev/null; then backup_accounts; groupadd "$g" && cp_ok "Created group $g"; fi
    for u in ${m//,/ }; do
        if ! exists "$u"; then cp_todo "README group $g: account $u does not exist"; continue; fi
        id -nG "$u" | tr ' ' '\n' | grep -qx "$g" || { backup_accounts; gpasswd -a "$u" "$g" >/dev/null && cp_ok "$u added to $g"; }
    done
    cp_info "Group $g: $(getent group "$g" | cut -d: -f4)"
done
[ -z "$GSPEC" ] && cp_info "None"

# ----------------------------------------------------------------- sudoers --
cp_hdr "sudoers: NOPASSWD / !authenticate, sudo rights for non-admins"
# Per file, because plain "visudo" only opens /etc/sudoers. Linux Mint ships /etc/sudoers.d/mintupdate with
# 3 NOPASSWD lines for its own update helpers - those are stock and left alone.
HIT_FILES=()
mapfile -t SFILES < <(sudo_files)
for f in "${SFILES[@]}"; do
    hits="$(sudo_findings "$f")"
    if [ -z "$hits" ]; then
        grep -qE '^[^#]*NOPASSWD' "$f" 2>/dev/null && cp_info "Stock Linux Mint NOPASSWD lines in $f - leave them"
        continue
    fi
    HIT_FILES+=("$f")
    cp_warn "$f:"
    while IFS=$'\t' read -r n why text; do printf '        line %-3s %-40s <- %s\n' "$n" "$text" "$why"; done <<< "$hits"
done
if [ ${#HIT_FILES[@]} -eq 0 ]; then
    cp_ok "No NOPASSWD / !authenticate (other than Mint stock) and only admins have sudo rights"
else
    for f in "${HIT_FILES[@]}"; do
        lines="$(sudo_findings "$f" | cut -f1 | paste -sd, -)"
        if cp_ask "Open $f in visudo to fix line $lines?" y; then
            if [ -t 0 ]; then
                cp_backup "$f"
                if [ "$f" = /etc/sudoers ]; then visudo; else visudo -f "$f"; fi
            else
                cp_warn "visudo needs a terminal - skipped"
            fi
        fi
    done
    for f in "${HIT_FILES[@]}"; do
        left="$(sudo_findings "$f")"
        if [ -z "$left" ]; then cp_ok "$f fixed"; continue; fi
        while IFS=$'\t' read -r n why text; do
            if [[ "$why" == NOPASSWD* ]]; then cp_todo "remove NOPASSWD in $f line $n ($text): sudo visudo -f $f"
            else cp_todo "check sudo rights in $f line $n ($text) - $why: sudo visudo -f $f"; fi
        done <<< "$left"
    done
fi
visudo -c -q >/dev/null 2>&1 || { cp_err "sudoers has a syntax error"; cp_todo "sudoers syntax error - run: sudo visudo -c"; }

# ---------------------------------------------------------------- re-check --
cp_hdr "Re-check"
problems=0
find_unauth
[ ${#UNAUTH[@]} -gt 0 ] && { problems=1; cp_todo "Accounts not in the README still exist: ${UNAUTH[*]} (if unauthorized: sudo userdel -r NAME)"; }
find_group_fixes >/dev/null
for u in "${FIX_ADD[@]}"; do problems=1; cp_todo "README admin $u has no sudo: sudo usermod -aG sudo $u"; done
for i in "${!FIX_RM[@]}"; do
    problems=1; u="${FIX_RM[$i]}"; cmds=""
    for g in ${FIX_RMG[$i]}; do
        if [ "$g" = "$(id -gn "$u")" ]; then cmds+="; sudo usermod -g $(getent group "$u" >/dev/null && echo "$u" || echo users) $u"
        else cmds+="; sudo gpasswd -d $u $g"; fi
    done
    cp_todo "$u is not a README admin but is in ${FIX_RMG[$i]}: ${cmds#; }"
done
u0="$(awk -F: '$3 == 0 && $1 != "root" {printf "%s ", $1}' /etc/passwd)"
[ -n "$u0" ] && { problems=1; cp_todo "Still UID 0 besides root: $u0"; }
dupuid="$(awk -F: '$3 != 0 { n[$3] = n[$3] " " $1; c[$3]++ } END { for (k in c) if (c[k] > 1) printf "UID %s:%s; ", k, n[k] }' /etc/passwd)"
[ -n "$dupuid" ] && { problems=1; cp_todo "Accounts sharing a UID: ${dupuid}give the unauthorized one its own UID or delete it"; }
[ -n "$(awk -F: '$2 == ""' /etc/shadow)" ] && problems=1
[ "$problems" = 0 ] && cp_ok "Accounts, admin groups and UID 0 match the README"
echo
echo "=== usersandsudo.sh done ==="
