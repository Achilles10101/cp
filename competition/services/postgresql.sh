#!/bin/bash
# PostgreSQL Security Hardening Script (new)
# Research-doc items: PG1-PG5, G1, G2, G5 (baseline first: section B)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

cp_require_root
cp_screenshot_prompt
ls -d /etc/postgresql/*/main >/dev/null 2>&1 || { echo "ERROR: no /etc/postgresql/<ver>/main cluster found"; exit 1; }
cp_baseline_gate postgresql

psql_q() { sudo -u postgres psql -P pager=off -AtXq -c "$1" 2>/dev/null; }

echo "========================================="
echo "PostgreSQL Security Hardening"
echo "========================================="

REMOTE=0
cp_ask "Does the README require REMOTE connections to PostgreSQL?" n && REMOTE=1

for CDIR in /etc/postgresql/*/main; do
    VER="$(basename "$(dirname "$CDIR")")"
    HBA="$CDIR/pg_hba.conf"; IDENT="$CDIR/pg_ident.conf"; PGCONF="$CDIR/postgresql.conf"
    echo ""
    echo "--- Cluster $VER/main ($CDIR)"
    cp_backup "$CDIR"

    # ------------------------------------------------------------------ PG1 pg_hba.conf --
    echo "pg_hba.conf entries:"
    grep -nvE '^[[:space:]]*(#|$)' "$HBA" | sed 's/^/      /'
    if grep -qE '^[[:space:]]*[^#].*[[:space:]](trust|password)([[:space:]]|$)' "$HBA"; then
        cp_warn "'trust' (no password) or 'password' (cleartext) authentication found"
        if cp_ask "Replace: local trust -> peer, host trust/password -> scram-sha-256?" y; then
            sed -i -E '/^[[:space:]]*local[[:space:]]/ s/[[:space:]]trust([[:space:]]|$)/ peer\1/' "$HBA"
            sed -i -E '/^[[:space:]]*(host|hostssl|hostnossl)[[:space:]]/ s/[[:space:]](trust|password)([[:space:]]|$)/ scram-sha-256\2/' "$HBA"
            cp_ok "pg_hba.conf: authentication required for every connection"
        fi
    fi
    # address column ($4 on host lines) open to everyone
    OPEN_LINES="$(awk '$1 ~ /^host/ && ($4 == "all" || $4 == "0.0.0.0/0" || $4 == "::/0" || ($4 == "0.0.0.0" && $5 == "0.0.0.0")) {print NR}' "$HBA")"
    if [ -n "$OPEN_LINES" ]; then
        cp_warn "Entries allow connections from ANY address:"
        for n in $OPEN_LINES; do echo "      $n: $(sed -n "${n}p" "$HBA")"; done
        if [ "$REMOTE" = 0 ] && cp_ask "Comment them out (README does not need remote access)?" y; then
            for n in $OPEN_LINES; do sed -i "${n}s/^/# disabled by postgresql.sh: /" "$HBA"; done
            cp_ok "World-open entries disabled"
        fi
    fi
    grep -qE '^[[:space:]]*host[a-z]*[[:space:]].*[[:space:]]md5([[:space:]]|$)' "$HBA" && \
        cp_info "md5 entries kept (they also accept scram passwords; switching them to scram-sha-256 breaks users with old md5 hashes)"

    # ------------------------------------------------------------------ PG2 pg_ident.conf --
    if grep -qE '^[[:space:]]*[^#[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+postgres[[:space:]]*$' "$IDENT" 2>/dev/null; then
        cp_warn "pg_ident.conf maps OS users onto the postgres superuser:"
        grep -nE '^[[:space:]]*[^#[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+postgres[[:space:]]*$' "$IDENT" | sed 's/^/      /'
        if cp_ask "Remove these mappings?" y; then
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
            [ -f "$f" ] && [ -n "$(cp_get "$f" "$k")" ] && { cp_warn "$f overrides $k - removing"; cp_unset "$f" "$k"; }
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
        cp_warn "ALTER SYSTEM overrides in $DATA/postgresql.auto.conf:"
        grep -vE '^[[:space:]]*(#|$)' "$DATA/postgresql.auto.conf" | sed 's/^/      /'
        cp_ask "Reset them all (ALTER SYSTEM RESET ALL) after restart?" y && RESET_AUTO=1
    fi

    # ------------------------------------------------------------------ PG4 permissions --
    chown postgres:postgres "$CDIR"/*.conf
    chmod 640 "$HBA" "$IDENT"
    chmod 644 "$PGCONF" "$CDIR"/environment "$CDIR"/start.conf "$CDIR"/pg_ctl.conf 2>/dev/null
    [ -d "$DATA" ] && { chown postgres:postgres "$DATA"; chmod 700 "$DATA"; }
    cp_ok "Config files postgres:postgres (pg_hba/pg_ident 640), data dir 700"
done

# Restart and verify (G2)
echo ""
UNIT="$(cp_first_unit postgresql)"
if ! cp_restart "${UNIT:-postgresql}"; then
    cp_err "PostgreSQL failed to start - restoring configs"
    for CDIR in /etc/postgresql/*/main; do cp_restore "$CDIR"; done
    cp_restart "${UNIT:-postgresql}"; exit 1
fi
sleep 2
[ "${RESET_AUTO:-0}" = 1 ] && psql_q "ALTER SYSTEM RESET ALL;" && psql_q "SELECT pg_reload_conf();" >/dev/null && cp_ok "ALTER SYSTEM overrides reset"

if [ -n "$(psql_q 'SELECT 1')" ]; then
    cp_ok "PostgreSQL answers queries"
    echo "  ssl=$(psql_q 'SHOW ssl') password_encryption=$(psql_q 'SHOW password_encryption') listen_addresses=$(psql_q 'SHOW listen_addresses') log_connections=$(psql_q 'SHOW log_connections')"

    # ------------------------------------------------------------------ PG5 roles --
    echo ""
    echo "Roles (compare with the README):"
    sudo -u postgres psql -P pager=off -X -c "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin,
        CASE WHEN rolpassword IS NULL THEN 'none' WHEN rolpassword LIKE 'SCRAM%' THEN 'scram' ELSE 'md5/old' END AS pw
        FROM pg_authid WHERE rolname !~ '^pg_' ORDER BY 1;" 2>/dev/null
    STRIP="$(cp_read "Roles to strip SUPERUSER/CREATEROLE/CREATEDB from (comma separated, Enter = none)" "")"
    IFS=',' read -ra R <<< "$STRIP"
    for r in "${R[@]}"; do r="$(echo "$r" | xargs)"; [ -n "$r" ] && [ "$r" != postgres ] && psql_q "ALTER ROLE \"$r\" NOSUPERUSER NOCREATEROLE NOCREATEDB;" && cp_ok "Stripped privileges from $r"; done
    DROP="$(cp_read "Roles to DROP (comma separated, Enter = none)" "")"
    IFS=',' read -ra R <<< "$DROP"
    for r in "${R[@]}"; do
        r="$(echo "$r" | xargs)"; [ -n "$r" ] && [ "$r" != postgres ] || continue
        psql_q "REASSIGN OWNED BY \"$r\" TO postgres; DROP OWNED BY \"$r\";" 2>/dev/null
        psql_q "DROP ROLE \"$r\";" && cp_ok "Dropped role $r" || cp_warn "Could not drop $r (owns objects in another database?)"
    done
    # After switching to scram, roles with md5 hashes must get a new password
    for r in $(psql_q "SELECT rolname FROM pg_authid WHERE rolpassword LIKE 'md5%'"); do
        cp_warn "Role $r still has an md5 password hash"
        if [ -t 0 ]; then
            read -r -s -p "  New password for $r (Enter to skip): " NP; echo
            [ -n "$NP" ] && echo "ALTER ROLE \"$r\" PASSWORD :'pw';" | sudo -u postgres psql -P pager=off -AtXq -v pw="$NP" && cp_ok "Password for $r re-hashed with scram-sha-256"
        fi
    done
else
    cp_warn "Cannot query PostgreSQL as postgres - check the service (critical!)"
fi

[ "$REMOTE" = 1 ] && cp_ufw_allow "PostgreSQL" 5432/tcp
echo "PostgreSQL hardening complete."
