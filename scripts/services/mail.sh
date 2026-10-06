#!/bin/bash
# Mail (Postfix + Dovecot) Security Hardening Script (new)
# Research-doc items: MAIL1-MAIL4, G1-G3 (baseline first: section B)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

cp_require_root
cp_screenshot_prompt

HAVE_POSTFIX=0; HAVE_DOVECOT=0
command -v postconf >/dev/null 2>&1 && HAVE_POSTFIX=1
command -v doveconf >/dev/null 2>&1 && HAVE_DOVECOT=1
[ $HAVE_POSTFIX = 1 ] || [ $HAVE_DOVECOT = 1 ] || { echo "ERROR: neither postfix nor dovecot is installed"; exit 1; }
[ $HAVE_POSTFIX = 1 ] && cp_baseline_gate postfix
[ $HAVE_DOVECOT = 1 ] && cp_baseline_gate dovecot

echo "========================================="
echo "Mail Security Hardening"
echo "========================================="
CRITICAL=0
cp_ask "Is MAIL a critical service in the README (other machines send/receive mail through this one)?" y && CRITICAL=1

# ================================================================== Postfix ==
if [ $HAVE_POSTFIX = 1 ]; then
    echo ""
    echo "--- Postfix"
    cp_backup /etc/postfix
    # postconf -e edits main.cf IN PLACE (G1)
    postconf -e 'smtpd_banner = $myhostname ESMTP'                              # MAIL1: no mail_name/version
    postconf -e 'disable_vrfy_command = yes'
    postconf -e 'smtpd_helo_required = yes'
    postconf -e 'mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128'
    postconf -e 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
    postconf -e 'biff = no'
    # MAIL2: TLS
    CERT="$(postconf -h smtpd_tls_cert_file)"; KEY="$(postconf -h smtpd_tls_key_file)"
    if [ -z "$CERT" ] || [ ! -f "$CERT" ]; then
        [ -f /etc/ssl/certs/ssl-cert-snakeoil.pem ] || make-ssl-cert generate-default-snakeoil --force-overwrite 2>/dev/null
        postconf -e 'smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem' 'smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key'
    fi
    : "$KEY"
    if cp_ask "Does the README require ENCRYPTED SMTP only (smtpd_tls_security_level = encrypt)?" n; then
        postconf -e 'smtpd_tls_security_level = encrypt'
    else
        postconf -e 'smtpd_tls_security_level = may'
    fi
    postconf -e 'smtpd_tls_auth_only = yes'
    postconf -e 'smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
    postconf -e 'smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
    # MAIL3: local-only when mail is not a critical service
    if [ "$CRITICAL" = 0 ]; then
        postconf -e 'inet_interfaces = loopback-only'
        cp_ok "inet_interfaces = loopback-only (mail not critical)"
    else
        cp_info "Mail is critical - leaving inet_interfaces = $(postconf -h inet_interfaces)"
    fi
    # open relay check
    MYN="$(postconf -h mynetworks)"
    echo "$MYN" | grep -qE '0\.0\.0\.0/0|::/0' && cp_warn "mynetworks still contains a world range: $MYN"
    chown -R root:root /etc/postfix; chmod 755 /etc/postfix; chmod 644 /etc/postfix/*.cf
    if postfix check 2>/tmp/postfix-check.txt; then
        cp_ok "postfix check passed"
    else
        cat /tmp/postfix-check.txt; cp_err "postfix check failed - restoring"; cp_restore /etc/postfix
    fi
    cp_restart postfix || { cp_restore /etc/postfix; cp_restart postfix; }
    if [ "$CRITICAL" = 1 ]; then cp_ufw_allow "Postfix" 25/tcp; cp_ufw_allow "Postfix Submission" 587/tcp; fi
    # G2: banner + VRFY test
    if exec 3<>/dev/tcp/127.0.0.1/25 2>/dev/null; then
        read -r -t 5 BANNER <&3; printf 'EHLO test\r\nVRFY root\r\nQUIT\r\n' >&3
        RESP="$(timeout 5 cat <&3)"; exec 3>&-
        cp_info "SMTP banner: ${BANNER%$'\r'}"
        echo "$RESP" | grep -q '^252\|^250 .*root' && cp_warn "VRFY still answers" || cp_ok "VRFY disabled"
    else
        [ "$CRITICAL" = 1 ] && cp_warn "Port 25 is not answering - mail is a critical service!"
    fi
fi

# ================================================================== Dovecot ==
if [ $HAVE_DOVECOT = 1 ]; then
    echo ""
    echo "--- Dovecot ($(dovecot --version 2>/dev/null))"
    D=/etc/dovecot
    cp_backup "$D"
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
            [ -n "$(cp_get "$f" "$k")" ] && { cp_warn "$f also sets $k - removing"; cp_unset "$f" "$k"; }
        done
        cp_set "${DFILE[$k]}" "$k" "${DSET[$k]}"
    done
    grep -q 'ssl_cert' "$D/conf.d/10-ssl.conf" || cp_warn "No ssl_cert configured in 10-ssl.conf - 'ssl = required' needs a certificate"
    if doveconf -n >/dev/null 2>/tmp/doveconf.err; then
        cp_ok "doveconf -n: config valid"
        doveconf -n 2>/dev/null | grep -E '^(ssl|ssl_min_protocol|disable_plaintext_auth|auth_allow_cleartext|auth_debug_passwords) ' | sed 's/^/      /'
    else
        cat /tmp/doveconf.err; cp_err "Dovecot config invalid - restoring"; cp_restore "$D"
    fi
    cp_restart dovecot || { cp_restore "$D"; cp_restart dovecot; }
    [ "$CRITICAL" = 1 ] && cp_ufw_allow "Dovecot Secure IMAP" 993/tcp
fi
echo ""
echo "Mail hardening complete."
