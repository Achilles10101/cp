#!/bin/bash
# pipeline.sh CONTAINER SRC_COMPETITION_DIR  - competition order, answering like a competitor who read the README
C="$1"; SRC="$2"; H=/home/claude/harness
docker exec $C bash -c 'rm -rf /root/competition /root/harness; mkdir -p /root/logs'; docker cp "$SRC" $C:/root/competition; docker cp $H $C:/root/harness
docker cp /home/claude/pack/linuxmint-21.3 $C:/root/competition/baseline/ 2>/dev/null
export HARD=1500
$H/runstep.sh $C p1-baseline '[]' bash services/baseline.sh
CP_ADMINS="${PIPE_ADMINS:-cpuser alice}" CP_USERS="${PIPE_USERS-bob carol dave frank}" $H/runstep.sh $C p2-users '[
 ["Remove these users\\?","y"], ["adm: syslog.*Remove\\?","n"], ["unauthorized\\).*Remove\\?","y"],
 ["Add .* to sudo group","y"], ["Remove from admin groups","y"], ["Change UID","y"], ["Review with visudo","y"],
 ["Delete account toor","y"], ["Open /etc/sudoers.* in visudo","y"], ["Set a password for carol","y"],
 ["New password:","Car0l-Str0ng!pw"], ["Retype new password:","Car0l-Str0ng!pw"]]' bash usersandsudo.sh
$H/runstep.sh $C p3-sysconfig '[["Proceed with operation","y"],["Open or Close a port","n"],["Enable IPv6","n"],["install stable updates","yes"],["Do you want to continue","y"],["Remove ALL superuser","n"],["Lock the root account","y"],["Linux Mint: turn on Update Manager","y"]]' bash systemconfig.sh
$H/runstep.sh $C p4-filepkg '[
 ["\\[SERVICE\\] (apache2|FTP servers|PHP):.*Remove\\?","y"], ["\\[SERVICE\\].*Remove\\?","n"], ["\\[REVIEW\\].*Remove\\?","n"],
 ["Remove\\? \\[","y"], ["Purge these","y"], ["Run autoremove","y"], ["Purge their config","y"], ["dpkg --purge","y"]]' bash fileandpackage.sh
$H/runstep.sh $C p5-portmisc '[["Select option","SEQ:2,3,4"],["Install it now","y"],["Remove nmap again","y"],["Do you want to continue","y"]]' bash portandmisc.sh
$H/runstep.sh $C p6-ssh '[["Remove /root/.ssh","y"]]' bash services/ssh.sh
