# TEST ONLY: Debian 12 GNOME-ish CP image stand-in (systemd, gdm3, classic sources.list, admin cpuser)
FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN rm -f /etc/apt/sources.list.d/debian.sources && printf 'deb http://deb.debian.org/debian bookworm main non-free-firmware\ndeb http://deb.debian.org/debian bookworm-updates main non-free-firmware\ndeb http://security.debian.org/debian-security bookworm-security main non-free-firmware\n' > /etc/apt/sources.list \
 && apt-get update -qq && apt-get install -y -qq systemd systemd-sysv dbus ca-certificates locales python3 sudo procps iproute2 rsyslog cron \
    passwd login acl curl less nano psmisc net-tools anacron gdm3 gnome-session-bin xserver-xorg-core >/dev/null \
 && sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && locale-gen >/dev/null && update-locale LANG=en_US.UTF-8 \
 && useradd -m -u 1000 -s /bin/bash -c "CP User" -G sudo,adm cpuser && echo 'cpuser:Cpus3r-Passw0rd!' | chpasswd \
 && systemctl set-default graphical.target && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && find /etc/systemd/system /lib/systemd/system -path '*.wants/*' \( -name '*getty*' -o -name 'systemd-remount-fs*' \) -delete; truncate -s0 /etc/machine-id
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
