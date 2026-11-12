#!/bin/bash
# svcpipe.sh CONTAINER SRC  - baseline, systemconfig, then every service script (defaults + README answers used by the Aperture/1984 checks)
C="$1"; SRC="$2"; H=/home/claude/harness
docker exec $C bash -c 'rm -rf /root/competition /root/harness; mkdir -p /root/logs'; docker cp "$SRC" $C:/root/competition; docker cp $H $C:/root/harness
docker exec $C bash -c '[ -d /root/competition/baseline/linuxmint-21.3 ] || true'
export HARD=900
$H/runstep.sh $C s1-baseline '[]' bash services/baseline.sh
$H/runstep.sh $C s3-sysconfig '[["Proceed with operation","y"],["Open or Close a port","n"],["Enable IPv6","n"],["install stable updates","yes"],["Do you want to continue","y"],["Remove ALL superuser","n"],["Lock the root account","y"],["Linux Mint: turn on Update Manager","y"]]' bash systemconfig.sh
for s in ssh vsftpd apache2 php mysql postgresql samba bind9 mail squid; do
  $H/runstep.sh $C s-$s '[["Test login - FTP username","ftpuser"],["Password for ftpuser","Ftp-Us3r!pass"],["\\(END\\)","q"],["Do you want to continue","y"]]' bash services/$s.sh
done
