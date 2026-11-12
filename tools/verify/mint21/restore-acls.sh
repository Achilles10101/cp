#!/bin/bash
# restore-acls.sh CONTAINER [IMAGE]  - TEST HARNESS. `docker commit` on this host drops POSIX ACLs (security.*
# xattrs such as file capabilities survive). build-images.sh therefore saves every extended ACL of the build
# container in the image label cptest.acls (getfacl dump, gzip+base64) and resets the group mode bits to the
# group:: entry; this puts the ACLs back into a running container (run-pipeline.sh does it right after boot).
# Example: cp-mint-planted's planted "setfacl -m u:bob:rwx /usr/bin/sudo" (plant-mint.sh).
C="${1:?container}"; IMAGE="${2:-$(docker inspect -f '{{.Config.Image}}' "$C")}"
acl="$(docker image inspect -f '{{index .Config.Labels "cptest.acls"}}' "$IMAGE" 2>/dev/null)"
[ -n "$acl" ] && [ "$acl" != "<no value>" ] || exit 0
echo "$acl" | base64 -d | gunzip | docker exec -i "$C" setfacl --restore=- \
    && echo "restored POSIX ACLs from $IMAGE: $(echo "$acl" | base64 -d | gunzip | grep -c '^# file:') file(s)"
