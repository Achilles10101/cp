#!/bin/bash
# Mail (Postfix + Dovecot) Security Hardening Script
# Research-doc items: MAIL1-MAIL4, G1-G3 (baseline first: section B)
#
# Usage: sudo bash services/mail.sh [--reask]
# README answers are asked once and kept in /root/cp-state/readme.conf:
#   MAIL_SMTP_ENCRYPT (yes|no)  MAIL_POP3 (yes|no: README requires POP3; no = dovecot-pop3d purged, pop3 off,
#   UFW 110/995 closed); "mail is critical" comes from SERVICES (readme.sh), else MAIL_CRITICAL (yes|no)
#   --reask   forget those answers and ask again

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# ---- local helpers (same block in every services/*.sh; cp-common.sh is shared/owned elsewhere) ----
SVC=mail; SVC_T0=$SECONDS
svc_result() { mkdir -p "$CP_STATE_DIR/svc" 2>/dev/null && echo "$*" > "$CP_STATE_DIR/svc/$SVC.result"; }
svc_snap()   { find "$@" -xdev -type f -print0 2>/dev/null | LC_ALL=C sort -z | xargs -0 -r md5sum 2>/dev/null | md5sum | cut -c1-32; }
svc_forget() { [ -f "$CP_CFG" ] && sed -i -E "/^($(echo "$*" | tr ' ' '|'))=/d" "$CP_CFG"; }
svc_keys()   { awk '{ sub(/^[ \t]+/, ""); if ($0 == "" || $0 ~ /^[#;]/) next; p = index($0, "=");
                      if (p) { k = substr($0, 1, p - 1); sub(/[ \t]+$/, "", k) } else k = $1
                      if (!s[k]++) { n++; if (n <= 12) printf "%s ", k } } END { if (n > 12) printf "(+%d more)", n - 12 }'; }
svc_changes() {  # svc_changes PATH... -> one line per config file this run changed (vs. its cp_backup copy)
    local p rp b line bf lf k any=0
    for p in "$@"; do
        rp="$(readlink -f "$p" 2>/dev/null)"; b="$CP_BACKUP_ROOT/$CP_TS$rp"
        [ -n "$rp" ] && [ -e "$b" ] || continue
        while IFS= read -r line; do
            any=1
            case "$line" in
                "Files "*) bf="${line#Files }"; bf="${bf%% and *}"; lf="${line#* and }"; lf="${lf% differ}"
                           k="$(diff "$bf" "$lf" 2>/dev/null | sed -n 's/^> //p' | svc_keys)"; echo "      ~ $lf: ${k:-(lines removed)}" ;;
                "Only in $rp"*) echo "      + new file: $(echo "${line#Only in }" | sed 's#: #/#')" ;;
                "Only in $b"*)  echo "      - removed: $(echo "${line#Only in "$CP_BACKUP_ROOT/$CP_TS"}" | sed 's#: #/#')" ;;
            esac
        done < <(if [ -d "$rp" ]; then diff -rq "$b" "$rp" 2>/dev/null; else cmp -s "$b" "$rp" || echo "Files $b and $rp differ"; fi)
    done
    [ $any = 1 ] || echo "      (no config file changed - already hardened)"
}
# ------------------------------------------------------------------------------------------------

cp_require_root
[ "${1:-}" = "--reask" ] && svc_forget MAIL_CRITICAL MAIL_SMTP_ENCRYPT MAIL_POP3
cp_hdr "Mail hardening (Postfix / Dovecot)"
cp_screenshot_prompt

HAVE_POSTFIX=0; HAVE_DOVECOT=0
command -v postconf >/dev/null 2>&1 && HAVE_POSTFIX=1
command -v doveconf >/dev/null 2>&1 && HAVE_DOVECOT=1
[ $HAVE_POSTFIX = 1 ] || [ $HAVE_DOVECOT = 1 ] || { echo "ERROR: neither postfix nor dovecot is installed"; svc_result FAIL "not installed"; exit 1; }
[ $HAVE_POSTFIX = 1 ] && cp_baseline_gate postfix
[ $HAVE_DOVECOT = 1 ] && cp_baseline_gate dovecot

# README answers, asked once. "critical" comes from the README's SERVICES list when it is known.
if cp_cfg_has SERVICES; then
    CRITICAL=0; cp_critical mail && CRITICAL=1
    cp_info "README critical services: $(cp_cfg_get SERVICES) -> mail is $([ $CRITICAL = 1 ] && echo '' || echo 'NOT ')critical"
elif cp_cfg_has MAIL_CRITICAL; then
    CRITICAL=0; [ "$(cp_cfg_get MAIL_CRITICAL)" = yes ] && CRITICAL=1
else
    CRITICAL=0
    cp_ask "Is MAIL a critical service in the README (other machines send/receive mail through this one)?" y && CRITICAL=1
    cp_cfg_set MAIL_CRITICAL "$([ $CRITICAL = 1 ] && echo yes || echo no)"
fi

# README-dependent settings: one line with the defaults, one question (asked once, then stored)
POP3_NOW=""; [ $HAVE_DOVECOT = 1 ] && doveconf -h protocols 2>/dev/null | grep -qwE 'pop3s?' && POP3_NOW=" - POP3 is ON now"
if { [ $HAVE_POSTFIX = 0 ] || cp_cfg_has MAIL_SMTP_ENCRYPT; } && { [ $HAVE_DOVECOT = 0 ] || cp_cfg_has MAIL_POP3; }; then
    ENCRYPT="$(cp_cfg_get MAIL_SMTP_ENCRYPT)"; POP3="$(cp_cfg_get MAIL_POP3)"
    cp_info "README answers (stored; --reask to change):$([ $HAVE_POSTFIX = 1 ] && echo " encrypted-only SMTP $ENCRYPT")$([ $HAVE_DOVECOT = 1 ] && echo " | POP3 required $POP3")"
else
    ENCRYPT=no; POP3=no
    echo "  README-dependent mail settings - Enter keeps all of them:"
    echo "      $([ $HAVE_POSTFIX = 1 ] && echo 'SMTP TLS offered, not forced (smtpd_tls_security_level = may)')$([ $HAVE_POSTFIX = 1 ] && [ $HAVE_DOVECOT = 1 ] && echo ' | ')$([ $HAVE_DOVECOT = 1 ] && echo "POP3 not needed: removed (dovecot-pop3d purged, pop3 dropped from protocols, UFW 110/995 closed)$POP3_NOW")"
    if cp_ask "Does the README change any of these (encrypted-only SMTP, POP3 access)?" n; then
        [ $HAVE_POSTFIX = 1 ] && cp_ask "Does the README require ENCRYPTED SMTP only (smtpd_tls_security_level = encrypt)?" n && ENCRYPT=yes
        [ $HAVE_DOVECOT = 1 ] && cp_ask "Does the README REQUIRE POP3 (users fetch mail over POP3 / port 110 or 995)?" n && POP3=yes
    fi
    [ $HAVE_POSTFIX = 1 ] && cp_cfg_set MAIL_SMTP_ENCRYPT "$ENCRYPT"
    [ $HAVE_DOVECOT = 1 ] && cp_cfg_set MAIL_POP3 "$POP3"
fi
RESULT=OK

# ================================================================== Postfix ==
if [ $HAVE_POSTFIX = 1 ]; then
    cp_backup /etc/postfix
    P0="$(svc_snap /etc/postfix)"
    # postconf -e edits main.cf IN PLACE (G1) - one call for everything; values are read back from main.cf
    PC=(
        'smtpd_banner = $myhostname ESMTP'                                       # MAIL1: no mail_name/version
        'disable_vrfy_command = yes'
        'smtpd_helo_required = yes'
        'mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128'
        'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
        'biff = no'
        "smtpd_tls_security_level = $([ "$ENCRYPT" = yes ] && echo encrypt || echo may)"   # MAIL2: TLS
        'smtpd_tls_auth_only = yes'
        'smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
        'smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
    )
    CERT="$(cp_get /etc/postfix/main.cf smtpd_tls_cert_file)"
    if [ -z "$CERT" ] || [ ! -f "$CERT" ]; then
        [ -f /etc/ssl/certs/ssl-cert-snakeoil.pem ] || make-ssl-cert generate-default-snakeoil --force-overwrite 2>/dev/null
        PC+=('smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem' 'smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key')
    fi
    # MAIL3: local-only when mail is not a critical service
    [ "$CRITICAL" = 0 ] && PC+=('inet_interfaces = loopback-only')
    postconf -e "${PC[@]}"
    if [ "$CRITICAL" = 0 ]; then
        cp_ok "inet_interfaces = loopback-only (mail not critical)"
    else
        cp_info "Mail is critical - leaving inet_interfaces = $(cp_get /etc/postfix/main.cf inet_interfaces)"
    fi
    MYN="$(cp_get /etc/postfix/main.cf mynetworks)"
    echo "$MYN" | grep -qE '0\.0\.0\.0/0|::/0' && cp_todo "postfix mynetworks still contains a world range: $MYN"
    chown -R root:root /etc/postfix; chmod 755 /etc/postfix; chmod 644 /etc/postfix/*.cf
    cp_ok "Postfix: banner hides version, VRFY off, HELO required, no open relay, TLS 1.2+ (encrypt-only: $ENCRYPT)"
    if postfix check 2>/tmp/postfix-check.txt; then
        cp_ok "postfix check passed"
    else
        cat /tmp/postfix-check.txt; cp_err "postfix check failed - restoring"; cp_restore /etc/postfix
        cp_todo "mail.sh: postfix check failed after hardening - /etc/postfix rolled back"; RESULT="ROLLBACK postfix check failed"
    fi
    if [ "$(svc_snap /etc/postfix)" = "$P0" ] && postfix status >/dev/null 2>&1; then
        cp_ok "Postfix config unchanged - no restart needed"
    elif ! cp_restart postfix || ! postfix status >/dev/null 2>&1; then
        cp_restore /etc/postfix; cp_restart postfix
        cp_todo "mail.sh: postfix did not start with the hardened config - rolled back"; RESULT="ROLLBACK postfix did not start"
    fi
    if [ "$CRITICAL" = 1 ]; then cp_ufw_allow "Postfix" 25/tcp; cp_ufw_allow "Postfix Submission" 587/tcp; fi
    # G2: banner + VRFY test
    if exec 3<>/dev/tcp/127.0.0.1/25 2>/dev/null; then
        read -r -t 5 BANNER <&3; printf 'EHLO test\r\nVRFY root\r\nQUIT\r\n' >&3
        RESP="$(timeout 5 cat <&3)"; exec 3>&-
        cp_info "SMTP banner: ${BANNER%$'\r'}"
        if echo "$RESP" | grep -q '^252\|^250 .*root'; then cp_warn "VRFY still answers"; else cp_ok "VRFY disabled"; fi
    else
        [ "$CRITICAL" = 1 ] && { cp_warn "Port 25 is not answering - mail is a critical service!"; RESULT="FAIL port 25 not answering"; }
    fi
fi

# ================================================================== Dovecot ==
if [ $HAVE_DOVECOT = 1 ]; then
    # imap_up -> 0 when dovecot is active and (if IMAP is one of its protocols) IMAP greets on 127.0.0.1
    # (143, or 993 when only imaps listens); sets IMAP_BANNER
    imap_up() {
        systemctl is-active --quiet dovecot || return 1
        doveconf -h protocols 2>/dev/null | grep -qwE 'imaps?' || { IMAP_BANNER="(dovecot active; IMAP not enabled)"; return 0; }
        IMAP_PORT=143; ss -Htln 2>/dev/null | grep -qE '[:.]143 ' || { ss -Htln 2>/dev/null | grep -qE '[:.]993 ' && IMAP_PORT=993; }
        for _ in 1 2 3 4 5 6; do
            if [ "$IMAP_PORT" = 993 ]; then
                IMAP_BANNER="$(timeout 4 openssl s_client -quiet -connect 127.0.0.1:993 </dev/null 2>/dev/null | head -1 | tr -d '\r')"
            else
                IMAP_BANNER="$(timeout 4 bash -c 'exec 3<>/dev/tcp/127.0.0.1/143; IFS= read -r -t 3 l <&3; echo "$l"' 2>/dev/null | tr -d '\r')"
            fi
            [[ "$IMAP_BANNER" == "* OK"* ]] && { IMAP_BANNER="${IMAP_BANNER:0:60}"; return 0; }
            sleep 0.5
        done
        return 1
    }
    D=/etc/dovecot
    cp_backup "$D"
    D0="$(svc_snap "$D")"
    DVER="$(dovecot --version 2>/dev/null | cut -d. -f1,2)"
    # canonical file for each setting; the same key is removed from every other file (G1)
    declare -A DSET=( [ssl]="required" [auth_debug_passwords]="no" )
    declare -A DFILE=( [ssl]="$D/conf.d/10-ssl.conf" [auth_debug_passwords]="$D/conf.d/10-logging.conf" )
    if awk -v v="$DVER" 'BEGIN{split(v,a,"."); exit !(a[1] > 2 || (a[1] == 2 && a[2] >= 4))}'; then
        DSET[auth_allow_cleartext]="no"; DFILE[auth_allow_cleartext]="$D/conf.d/10-auth.conf"
        DSET[ssl_min_protocol]="TLSv1.2"; DFILE[ssl_min_protocol]="$D/conf.d/10-ssl.conf"
    else
        DSET[disable_plaintext_auth]="yes"; DFILE[disable_plaintext_auth]="$D/conf.d/10-auth.conf"
        DSET[ssl_min_protocol]="TLSv1.2"; DFILE[ssl_min_protocol]="$D/conf.d/10-ssl.conf"
    fi
    for k in "${!DSET[@]}"; do
        for f in "$D"/dovecot.conf "$D"/conf.d/*.conf "$D"/conf.d/*.ext "$D"/local.conf; do
            [ -f "$f" ] || continue
            [ "$f" = "${DFILE[$k]}" ] && continue
            [ -n "$(cp_get "$f" "$k")" ] && { cp_warn "$f also set $k - removed there"; cp_unset "$f" "$k" >/dev/null; }
        done
        cp_set "${DFILE[$k]}" "$k" "${DSET[$k]}"
    done
    grep -q 'ssl_cert' "$D/conf.d/10-ssl.conf" || cp_todo "Dovecot: no ssl_cert in 10-ssl.conf - 'ssl = required' needs a certificate"
    # POP3 not required (README): drop pop3/pop3s from every "protocols =" line; a line left with nothing
    # (or only "$protocols") is deleted instead of leaving an empty one - the packages' protocols.d decide then
    if [ "$POP3" != yes ]; then
        for f in "$D"/dovecot.conf "$D"/conf.d/*.conf "$D"/local.conf; do
            [ -f "$f" ] && grep -qE '^[[:space:]]*protocols[[:space:]]*=.*pop3' "$f" || continue
            T="$(mktemp)"
            awk '/^[ \t]*protocols[ \t]*=/ {
                    l = $0; sub(/^[ \t]*protocols[ \t]*=[ \t]*/, "", l); n = split(l, a, /[ \t]+/); out = ""
                    for (i = 1; i <= n; i++) if (a[i] != "" && a[i] != "pop3" && a[i] != "pop3s") out = out (out == "" ? "" : " ") a[i]
                    if (out == "" || out == "$protocols") next
                    match($0, /^[ \t]*/); print substr($0, 1, RLENGTH) "protocols = " out; next }
                 { print }' "$f" > "$T" && cat "$T" > "$f"; rm -f "$T"
            cp_ok "pop3 removed from 'protocols' in $f"
        done
    fi
    if doveconf -n >/dev/null 2>/tmp/doveconf.err; then
        cp_ok "Dovecot $(dovecot --version 2>/dev/null | cut -d' ' -f1): $(doveconf -n 2>/dev/null | grep -E '^(ssl|ssl_min_protocol|disable_plaintext_auth|auth_allow_cleartext|auth_debug_passwords) ' | tr '\n' ';')"
    else
        cat /tmp/doveconf.err; cp_err "Dovecot config invalid - restoring"; cp_restore "$D"
        cp_todo "mail.sh: dovecot config invalid after hardening - rolled back"; RESULT="ROLLBACK doveconf failed"
    fi
    if [ "$(svc_snap "$D")" = "$D0" ] && systemctl is-active --quiet dovecot; then
        cp_ok "Dovecot config unchanged - no restart needed"
    elif ! cp_restart dovecot || ! imap_up; then
        cp_restore "$D"; cp_restart dovecot
        cp_todo "mail.sh: dovecot did not start/answer with the hardened config - rolled back"; RESULT="ROLLBACK dovecot did not start"
    fi
    DOVE_UP=0
    if imap_up; then DOVE_UP=1; cp_ok "IMAP answers: $IMAP_BANNER"
    else
        cp_warn "Dovecot/IMAP does not answer on 127.0.0.1:${IMAP_PORT:-143} (critical service?)"
        [ "$CRITICAL" = 1 ] && [ "$RESULT" = OK ] && RESULT="FAIL IMAP not answering"
    fi
    # POP3 not required: UFW rules first (dovecot-pop3d ships the 'Dovecot POP3' profiles - after the purge
    # ufw can no longer match them), then the package - only once dovecot is known to run without pop3
    if [ "$POP3" != yes ] && [ "$DOVE_UP" = 0 ]; then
        cp_todo "mail.sh: POP3 was NOT removed because dovecot is not running/answering - fix dovecot first (journalctl -u dovecot), then re-run"
    elif [ "$POP3" != yes ]; then
        if command -v ufw >/dev/null 2>&1; then
            for r in "Dovecot POP3" "Dovecot Secure POP3" 110/tcp 110 995/tcp 995; do
                ufw delete allow "$r" >/dev/null 2>&1 && cp_ok "UFW: removed 'allow $r'"
            done
            LEFT="$(ufw show added 2>/dev/null | grep -iE "pop3|[^0-9](110|995)([^0-9]|$)" | xargs)"
            [ -n "$LEFT" ] && cp_todo "mail.sh: UFW still allows POP3 ($LEFT) - delete it: ufw status numbered, then ufw delete N"
        fi
        if cp_pkg_installed dovecot-pop3d; then
            if DEBIAN_FRONTEND=noninteractive cp_apt purge -y dovecot-pop3d >/dev/null 2>&1; then
                cp_ok "dovecot-pop3d purged (README does not require POP3)"
                systemctl is-active --quiet dovecot && imap_up || cp_restart dovecot >/dev/null
                if imap_up; then cp_ok "Dovecot still answers after the purge: $IMAP_BANNER"
                else cp_todo "mail.sh: dovecot/IMAP is down after purging dovecot-pop3d - check journalctl -u dovecot"; RESULT="FAIL IMAP down after pop3d purge"; fi
            else
                cp_warn "Could not purge dovecot-pop3d"; cp_todo "mail.sh: purge dovecot-pop3d by hand (sudo apt-get purge dovecot-pop3d) - README does not require POP3"
            fi
        fi
    elif [ "$POP3" = yes ] && [ "$CRITICAL" = 1 ]; then
        cp_ufw_allow "Dovecot Secure POP3" 995/tcp
    fi
    [ "$CRITICAL" = 1 ] && cp_ufw_allow "Dovecot Secure IMAP" 993/tcp
fi
echo "  Changed:"
svc_changes /etc/postfix /etc/dovecot
svc_result $RESULT
cp_ok "Mail hardening complete ($((SECONDS - SVC_T0))s)"
