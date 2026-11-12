#!/bin/bash
# PostgreSQL Security Hardening Script
# Research-doc items: PG1-PG5, G1, G2, G5 (baseline first: section B)
#
# Usage: sudo bash services/postgresql.sh [--reask]
# The README answer is asked once and kept in /root/cp-state/readme.conf: PG_REMOTE (yes|no);
# PG_ROLES_OK = non-default roles you already reviewed and kept (only new ones are asked about)
#   --reask   forget it and ask again

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# ---- local helpers (same block in every services/*.sh; cp-common.sh is shared/owned elsewhere) ----
SVC=postgresql; SVC_T0=$SECONDS
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
[ "${1:-}" = "--reask" ] && svc_forget PG_REMOTE PG_ROLES_OK
cp_hdr "PostgreSQL hardening"
cp_screenshot_prompt
ls -d /etc/postgresql/*/main >/dev/null 2>&1 || { echo "ERROR: no /etc/postgresql/<ver>/main cluster found"; svc_result FAIL "not installed"; exit 1; }
cp_baseline_gate postgresql

psql_q() { sudo -u postgres psql -P pager=off -AtXq -c "$1" 2>/dev/null; }

# README answer (PG3), asked once
if cp_cfg_has PG_REMOTE; then
    REMOTE=0; [ "$(cp_cfg_get PG_REMOTE)" = yes ] && REMOTE=1
    cp_info "Answer (stored; --reask to change): remote connections $(cp_cfg_get PG_REMOTE)"
else
    REMOTE=0
    cp_ask "Does the README require REMOTE connections to PostgreSQL?" n && REMOTE=1
    cp_cfg_set PG_REMOTE "$([ $REMOTE = 1 ] && echo yes || echo no)"
fi

CDIRS=(/etc/postgresql/*/main)
cp_backup "${CDIRS[@]}"
SNAP0="$(svc_snap "${CDIRS[@]}")"
RESET_AUTO=0
for CDIR in "${CDIRS[@]}"; do
    VER="$(basename "$(dirname "$CDIR")")"
    HBA="$CDIR/pg_hba.conf"; IDENT="$CDIR/pg_ident.conf"; PGCONF="$CDIR/postgresql.conf"
    cp_info "Cluster $VER/main ($CDIR)"

    # ------------------------------------------------------------------ PG1 pg_hba.conf --
    if grep -qE '^[[:space:]]*[^#].*[[:space:]](trust|password)([[:space:]]|$)' "$HBA"; then
        cp_warn "pg_hba.conf: 'trust' (no password) or 'password' (cleartext) authentication:"
        grep -nE '^[[:space:]]*[^#].*[[:space:]](trust|password)([[:space:]]|$)' "$HBA" | sed 's/^/      /'
        if cp_auto "Replace: local trust -> peer, host trust/password -> scram-sha-256?" y; then
            sed -i -E '/^[[:space:]]*local[[:space:]]/ s/[[:space:]]trust([[:space:]]|$)/ peer\1/' "$HBA"
            sed -i -E '/^[[:space:]]*(host|hostssl|hostnossl)[[:space:]]/ s/[[:space:]](trust|password)([[:space:]]|$)/ scram-sha-256\2/' "$HBA"
            cp_ok "pg_hba.conf: authentication required for every connection"
        fi
    fi
    # address column ($4 on host lines) open to everyone
    OPEN_LINES="$(awk '$1 ~ /^host/ && ($4 == "all" || $4 == "0.0.0.0/0" || $4 == "::/0" || ($4 == "0.0.0.0" && $5 == "0.0.0.0")) {print NR}' "$HBA")"
    if [ -n "$OPEN_LINES" ]; then
        if [ "$REMOTE" = 0 ]; then
            for n in $OPEN_LINES; do cp_info "world-open: $(sed -n "${n}p" "$HBA")"; done
            if cp_auto "Comment out the entries open to ANY address (README does not need remote access)?" y; then
                for n in $OPEN_LINES; do sed -i "${n}s/^/# disabled by postgresql.sh: /" "$HBA"; done
                cp_ok "World-open pg_hba entries disabled"
            fi
        else
            for n in $OPEN_LINES; do cp_todo "pg_hba.conf allows ANY address (remote access is on): $(sed -n "${n}p" "$HBA" | xargs) - narrow it to the README's network if it names one"; done
        fi
    fi
    grep -qE '^[[:space:]]*host[a-z]*[[:space:]].*[[:space:]]md5([[:space:]]|$)' "$HBA" && \
        cp_info "md5 entries kept (they also accept scram passwords; switching them to scram-sha-256 breaks users with old md5 hashes)"

    # ------------------------------------------------------------------ PG2 pg_ident.conf --
    if grep -qE '^[[:space:]]*[^#[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+postgres[[:space:]]*$' "$IDENT" 2>/dev/null; then
        cp_warn "pg_ident.conf maps OS users onto the postgres superuser: $(grep -E '^[[:space:]]*[^#[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+postgres[[:space:]]*$' "$IDENT" | xargs)"
        if cp_auto "Remove these mappings?" y; then
            sed -i -E '/^[[:space:]]*[^#[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+postgres[[:space:]]*$/ s/^/# disabled by postgresql.sh: /' "$IDENT"
            cp_ok "Mappings to postgres removed"
        fi
    fi

    # ------------------------------------------------------------------ PG3 postgresql.conf --
    LISTEN="'localhost'"; [ "$REMOTE" = 1 ] && LISTEN="'*'"
    declare -A PGSET=(
        [ssl]=on
        [listen_addresses]="$LISTEN"
        [password_encryption]="'scram-sha-256'"
        [log_connections]=on
        [log_disconnections]=on
    )
    for k in "${!PGSET[@]}"; do
        cp_set "$PGCONF" "$k" "${PGSET[$k]}" eqs 0 0
        for f in "$CDIR"/conf.d/*.conf; do
            [ -f "$f" ] && [ -n "$(cp_get "$f" "$k")" ] && { cp_warn "$f overrode $k - removed there"; cp_unset "$f" "$k" >/dev/null; }
        done
    done
    unset PGSET
    grep -qE "^[[:space:]]*ssl_cert_file" "$PGCONF" || cp_set "$PGCONF" ssl_cert_file "'/etc/ssl/certs/ssl-cert-snakeoil.pem'"
    grep -qE "^[[:space:]]*ssl_key_file" "$PGCONF" || cp_set "$PGCONF" ssl_key_file "'/etc/ssl/private/ssl-cert-snakeoil.key'"
    [ -f /etc/ssl/private/ssl-cert-snakeoil.key ] || make-ssl-cert generate-default-snakeoil --force-overwrite 2>/dev/null
    id postgres 2>/dev/null | grep -q ssl-cert || usermod -aG ssl-cert postgres 2>/dev/null

    # ALTER SYSTEM settings live in postgresql.auto.conf in the data dir and override postgresql.conf
    DATA="$(sed -n -E "s/^[[:space:]]*data_directory[[:space:]]*=[[:space:]]*'([^']+)'.*/\1/p" "$PGCONF")"
    DATA="${DATA:-/var/lib/postgresql/$VER/main}"
    if [ -f "$DATA/postgresql.auto.conf" ] && grep -vqE '^[[:space:]]*(#|$)' "$DATA/postgresql.auto.conf"; then
        cp_warn "ALTER SYSTEM overrides in $DATA/postgresql.auto.conf: $(grep -vE '^[[:space:]]*(#|$)' "$DATA/postgresql.auto.conf" | tr '\n' ';')"
        cp_auto "Reset them all (ALTER SYSTEM RESET ALL) after restart?" y && RESET_AUTO=1
    fi

    # ------------------------------------------------------------------ PG4 permissions --
    chown postgres:postgres "$CDIR"/*.conf
    chmod 640 "$HBA" "$IDENT"
    chmod 644 "$PGCONF" "$CDIR"/environment "$CDIR"/start.conf "$CDIR"/pg_ctl.conf 2>/dev/null
    [ -d "$DATA" ] && { chown postgres:postgres "$DATA"; chmod 700 "$DATA"; }
    cp_ok "Perms: config files postgres:postgres (pg_hba/pg_ident 640), data dir 700"
done

# ------------------------------------------------------------------ restart once + verify (G2) --
UNIT="$(cp_first_unit postgresql)"; UNIT="${UNIT:-postgresql}"
pg_up() { local _i; for _i in $(seq 1 30); do [ -n "$(psql_q 'SELECT 1')" ] && return 0; sleep 0.3; done; return 1; }
if [ "$(svc_snap "${CDIRS[@]}")" = "$SNAP0" ] && [ -n "$(psql_q 'SELECT 1')" ]; then
    cp_ok "PostgreSQL config unchanged - no restart needed"
elif ! cp_restart "$UNIT" || ! pg_up; then
    cp_err "PostgreSQL failed to start - restoring configs"
    cp_restore "${CDIRS[@]}"
    cp_restart "$UNIT"
    cp_todo "postgresql.sh: PostgreSQL did not come back with the hardened config - rolled back; check journalctl -u 'postgresql*'"
    svc_result ROLLBACK "postgresql did not start"; exit 1
fi
[ "$RESET_AUTO" = 1 ] && psql_q "ALTER SYSTEM RESET ALL;" && psql_q "SELECT pg_reload_conf();" >/dev/null && cp_ok "ALTER SYSTEM overrides reset"

RESULT=OK
if [ -n "$(psql_q 'SELECT 1')" ]; then
    cp_ok "PostgreSQL answers queries: ssl=$(psql_q 'SHOW ssl') password_encryption=$(psql_q 'SHOW password_encryption') listen_addresses=$(psql_q 'SHOW listen_addresses') log_connections=$(psql_q 'SHOW log_connections')"

    # ------------------------------------------------------------------ PG5 roles --
    # a default install has only 'postgres' (+ built-in pg_* roles): show and ask only about the others
    EXTRA="$(psql_q "SELECT rolname FROM pg_authid WHERE rolname !~ '^pg_' AND rolname <> 'postgres' ORDER BY 1")"
    NEWR=""; for r in $EXTRA; do [[ " $(cp_cfg_get PG_ROLES_OK) " == *" $r "* ]] || NEWR="$NEWR $r"; done
    if [ -z "$EXTRA" ]; then
        cp_ok "Only the default 'postgres' role exists"
    elif [ -z "$NEWR" ]; then
        cp_info "Non-default roles already reviewed and kept (--reask to review again): $(echo $EXTRA)"
    else
        echo "  Roles a default install does NOT have (compare with the README):"
        sudo -u postgres psql -P pager=off -X -c "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin,
            CASE WHEN rolpassword IS NULL THEN 'none' WHEN rolpassword LIKE 'SCRAM%' THEN 'scram' ELSE 'md5/old' END AS pw
            FROM pg_authid WHERE rolname !~ '^pg_' AND rolname <> 'postgres' ORDER BY 1;" 2>/dev/null | sed 's/^/      /'
        PRIV="$(psql_q "SELECT string_agg(rolname, ',') FROM pg_authid WHERE rolname !~ '^pg_' AND rolname <> 'postgres' AND (rolsuper OR rolcreaterole OR rolcreatedb)")"
        if [ -n "$PRIV" ]; then
            STRIP="$(cp_read "Roles to strip SUPERUSER/CREATEROLE/CREATEDB from (comma separated, Enter = none; have them: $PRIV)" "")"
            IFS=',' read -ra R <<< "$STRIP"
            for r in "${R[@]}"; do r="$(echo "$r" | xargs)"; [ -n "$r" ] && [ "$r" != postgres ] && psql_q "ALTER ROLE \"$r\" NOSUPERUSER NOCREATEROLE NOCREATEDB;" && cp_ok "Stripped privileges from $r"; done
        fi
        DROP="$(cp_read "Roles to DROP (comma separated, Enter = none)" "")"
        IFS=',' read -ra R <<< "$DROP"
        for r in "${R[@]}"; do
            r="$(echo "$r" | xargs)"; [ -n "$r" ] && [ "$r" != postgres ] || continue
            psql_q "REASSIGN OWNED BY \"$r\" TO postgres; DROP OWNED BY \"$r\";" 2>/dev/null
            if psql_q "DROP ROLE \"$r\";"; then cp_ok "Dropped role $r"; else cp_warn "Could not drop $r (owns objects in another database?)"; fi
        done
        cp_cfg_set PG_ROLES_OK "$(psql_q "SELECT rolname FROM pg_authid WHERE rolname !~ '^pg_' AND rolname <> 'postgres' ORDER BY 1" | xargs)"
    fi
    for r in $(psql_q "SELECT rolname FROM pg_authid WHERE rolname !~ '^pg_' AND rolname <> 'postgres' AND rolsuper"); do
        cp_todo "PostgreSQL role $r is still SUPERUSER - strip it unless the README needs it"
    done
    # After switching to scram, roles with md5 hashes must get a new password
    for r in $(psql_q "SELECT rolname FROM pg_authid WHERE rolpassword LIKE 'md5%'"); do
        NP=""
        [ -t 0 ] && { read -r -s -p "  Role $r still has an md5 password hash. New password (Enter to skip): " NP; echo; }
        if [ -n "$NP" ]; then
            echo "ALTER ROLE \"$r\" PASSWORD :'pw';" | sudo -u postgres psql -P pager=off -AtXq -v pw="$NP" && cp_ok "Password for $r re-hashed with scram-sha-256"
        else
            cp_todo "PostgreSQL role $r has an md5 password hash - set a new password (ALTER ROLE \"$r\" PASSWORD '...') so it is stored as scram"
        fi
    done
else
    cp_warn "Cannot query PostgreSQL as postgres - check the service (critical!)"
    RESULT="FAIL no answer to SELECT 1"
fi

[ "$REMOTE" = 1 ] && cp_ufw_allow "PostgreSQL" 5432/tcp
echo "  Changed:"
svc_changes "${CDIRS[@]}"
svc_result $RESULT
cp_ok "PostgreSQL hardening complete ($((SECONDS - SVC_T0))s)"
