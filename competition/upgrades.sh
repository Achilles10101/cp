#!/bin/bash
# upgrades.sh - install package upgrades (checklist: "Install updates for bash, kernel, LibreOffice ...").
#   sudo bash upgrades.sh        (from inside competition/; speedrun.sh runs it as its last script)
#
#   1. Lists the repositories apt uses - anything that is not an official Ubuntu/Mint/Debian host gets a warning
#      and a TODO (an unknown repository can install anything).
#   2. Simulates the full-upgrade and shows the count, notable packages (bash, kernel, firefox, libreoffice,
#      service packages) and anything it would REMOVE (then the default becomes n).
#   3. One question, then installs. Every config file the scripts hardened is kept: dpkg conffiles
#      (--force-confdef --force-confold) and ucf-managed files such as sshd_config (UCF_FORCE_CONFFOLD=1).
#   Uses the upgrades speedrun.sh downloaded in the background (/var/cache/apt/cp-upgrades/) when they are
#   there, otherwise plain apt. Linux Mint's Update Manager automation is set by systemconfig.sh.
CP_SCRIPT_NAME=upgrades.sh
# shellcheck source=cp-common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found next to upgrades.sh"; exit 1; }
case "${1:-}" in -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;; "") ;; *) echo "Unknown option $1 (see -h)"; exit 2 ;; esac
cp_require_root
cp_screenshot_prompt

UPG_DIR=/var/cache/apt/cp-upgrades
APTO=()
if ls "$UPG_DIR"/*.deb >/dev/null 2>&1; then
    APTO=(-o Dir::Cache::archives="$UPG_DIR/")
    cp_info "Using the $(ls "$UPG_DIR"/*.deb | wc -l) package files downloaded in the background ($UPG_DIR)"
fi

cp_hdr "Package lists"
upd="$(cat "$CP_STATE_DIR/apt-updated" 2>/dev/null)"
if [ -n "$upd" ] && [ $(( $(date +%s) - upd )) -lt 3600 ]; then
    cp_ok "apt-get update ran $(( ($(date +%s) - upd) / 60 )) min ago - not repeated"
else
    if LC_ALL=C cp_apt -q update > "$CP_STATE_DIR/upgrades-update.log" 2>&1; then
        date +%s > "$CP_STATE_DIR/apt-updated"; cp_ok "apt-get update done"
    else
        cp_warn "apt-get update reported errors (log: $CP_STATE_DIR/upgrades-update.log):"
        grep -E '^(E|W):' "$CP_STATE_DIR/upgrades-update.log" | head -5 | sed 's/^/      /'
        cp_info "Linux Mint: Update Manager -> Edit -> Software Sources -> restore the default settings, then refresh."
    fi
fi

cp_hdr "Repositories"
# Official hosts only (a substring match would accept http://evil-ubuntu.example): Ubuntu/Debian/Mint
# archives, country mirrors <cc>.archive.ubuntu.com, plus the mirror list Linux Mint ships (mint-mirrors).
OFFICIAL_RE='^(archive|security|ports)\.ubuntu\.com$|^[a-z]{2}\.archive\.ubuntu\.com$|^(packages|security)\.linuxmint\.com$|^(deb|security|ftp)\.debian\.org$|^ftp\.[a-z]{2}\.debian\.org$'
MINT_MIRRORS="$(cat /usr/share/mint-mirrors/* 2>/dev/null | grep -oE '^[a-z]+://[^/[:space:]]+' | sed -E 's#^[a-z]+://##' | sort -u)"
official() {
    local h="${1#*://}"; h="${h%%/*}"; h="${h%%:*}"
    [[ "$h" =~ $OFFICIAL_RE ]] && return 0
    [ -n "$MINT_MIRRORS" ] && grep -qxF -- "$h" <<<"$MINT_MIRRORS"
}
bad=0
# from apt-cache policy AND the source files (a repository whose update failed is missing from the policy)
for r in $( { LC_ALL=C /usr/bin/apt-cache policy 2>/dev/null
              grep -hsE '^[[:space:]]*(deb|deb-src|URIs:)[[:space:]]' /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources
            } | grep -oE '(https?|ftp)://[^ ]+' | sed 's#/*$##' | sort -u); do
    if official "$r"; then echo "      $r"
    else
        echo "      ${CP_C_YEL}$r${CP_C_OFF}  <- check"; bad=1
        cp_todo "APT repository that is not an official Ubuntu/Mint/Debian host: $r - check /etc/apt/sources.list(.d) (keep it only if the README needs it)"
    fi
done
[ "$bad" = 1 ] && cp_warn "Upgrades from an unknown repository can install anything - check it before saying yes."

cp_hdr "Upgrades"
sim="$(LC_ALL=C /usr/bin/apt-get -s "${APTO[@]}" full-upgrade 2>&1)"; src=$?
if [ "$src" -ne 0 ] || grep -q '^E:' <<<"$sim"; then   # no plan = no "Inst" lines: never report that as "nothing to upgrade"
    cp_err "apt-get could not plan the upgrade (exit $src):"; grep -E '^(E|W):' <<<"$sim" | head -5 | sed 's/^/      /'
    cp_todo "Upgrades NOT installed: apt-get -s full-upgrade failed - fix apt (sudo dpkg --configure -a; sudo apt-get -f install), then run upgrades.sh again"
    exit 1
fi
held="$(/usr/bin/apt-mark showhold 2>/dev/null | xargs)"
[ -n "$held" ] && { cp_warn "On hold, NOT upgraded: $held"; cp_todo "Held packages are not upgraded: $held - sudo apt-mark unhold <pkg> unless the README needs it pinned, then run upgrades.sh again"; }
n_inst="$(grep -c '^Inst ' <<<"$sim")"; n_rem="$(grep -c '^Remv ' <<<"$sim")"
if [ "$n_inst" -eq 0 ] && [ "$n_rem" -eq 0 ]; then cp_ok "Nothing to upgrade."; exit 0; fi
notable="$(grep '^Inst ' <<<"$sim" | awk '{print $2}' | grep -E '^(bash|sudo|linux-image|linux-generic|firefox|libreoffice-core|thunderbird|openssh-server|openssl|apache2|nginx|vsftpd|mysql-server|mariadb-server|postgresql|samba|bind9|postfix|dovecot-core|php[0-9.]*|openvpn|squid|cinnamon|policykit-1|pkexec)' | head -12 | tr '\n' ' ')"
cp_info "$n_inst package(s) to upgrade/install${notable:+ - includes: $notable}"
def=y
if [ "$n_rem" -gt 0 ]; then cp_warn "It would also REMOVE: $(grep '^Remv ' <<<"$sim" | awk '{print $2}' | tr '\n' ' ')"; def=n; fi
cp_ask "Install them now (your hardened config files are kept)?" "$def" || { cp_info "Not installed."; exit 0; }

DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l UCF_FORCE_CONFFOLD=1 \
LC_ALL=C cp_apt -q -y "${APTO[@]}" -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade
rc=$?
if [ "$rc" -eq 0 ]; then
    cp_ok "Upgrades installed."
    [ ${#APTO[@]} -gt 0 ] && /usr/bin/apt-get -q "${APTO[@]}" clean
else
    cp_err "apt-get full-upgrade failed (exit $rc) - see the output above"
    cp_todo "Upgrades failed (exit $rc) - run: sudo apt-get update && sudo apt-get full-upgrade"
fi
exit "$rc"
