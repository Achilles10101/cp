#!/bin/bash
# runstep.sh CONTAINER NAME RULES_JSON CMD...   (runs CMD inside the container's competition dir via drive2.py)
C="$1"; N="$2"; RULES="$3"; shift 3
docker exec -e RULES="$RULES" -e SUDO_USER=${SUDO_AS:-cpuser} -e CP_ADMINS="${CP_ADMINS:-}" -e CP_USERS="${CP_USERS:-}" -e TERM=xterm -e DEBIAN_FRONTEND=${DEBIAN_FRONTEND:-readline} -e PAGER=cat -e SYSTEMD_PAGER= -e IDLE="${IDLE:-2.5}" -e HARD="${HARD:-1500}" \
  -e PATH="/root/harness/fakebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" -w /root/competition "$C" \
  python3 /root/harness/drive2.py "/root/logs/$N.log" -- "$@"
mkdir -p /home/claude/logs/$C; docker cp -q "$C:/root/logs/$N.log" /home/claude/logs/$C/ ; docker cp -q "$C:/root/logs/$N.log.answers" /home/claude/logs/$C/
tail -1 /home/claude/logs/$C/$N.log.answers
