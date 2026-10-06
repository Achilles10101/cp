# Baseline pack (research doc B10 / B11)

This folder holds known-good ("pristine") copies of each critical service's configuration and state, captured from CLEAN virtual machines. `scripts/services/baseline.sh` uses it automatically when a folder matching the image's OS exists. Otherwise it falls back to pristine copies on the image, then to `apt-get download`.

## Building it (before the season)

1. Make a clean VM for each likely CP19 OS: Ubuntu 22.04 and 24.04, Linux Mint 21.x and 22.x, and Debian 12.
2. Install every critical service with default settings and don't configure anything: `openssh-server vsftpd apache2 nginx php libapache2-mod-php php-fpm mariadb-server (or mysql-server) postgresql samba bind9 postfix dovecot-imapd openvpn squid`.
3. Copy the repo onto the VM and run `sudo bash scripts/services/baseline.sh --capture /tmp/pack`.
4. Copy `/tmp/pack/<os-id>/` into this folder, e.g. `baseline/ubuntu-22.04/`.

## Layout

```
baseline/<os-id>/                 os-id = ID-VERSION_ID from /etc/os-release (ubuntu-22.04, linuxmint-21.3 ...)
  dpkg-l.txt, unit-files.txt, listening-all.txt, world-writable.txt, suid-sgid.txt   (whole system)
  <svc>/pristine/<full path>      default config files (e.g. ssh/pristine/etc/ssh/sshd_config)
  <svc>/stat.txt                  "mode user:group path" of config/content/data dirs
  <svc>/accounts.txt              default DB / Samba accounts
  <svc>/listen.txt                default listening sockets
  <svc>/packages.txt              package versions
  <svc>/hardened/<full path>      B11: YOUR hardened version of the same files (fill these in by hand)
```

## Using it in competition (B11)

`baseline.sh` writes each changed file pair to `/root/baseline/<svc>/pairs.txt`. Use `--meld` to open each diff. For the 3-way merge the blog describes:

```
meld baseline/<os-id>/<svc>/pristine/etc/ssh/sshd_config /etc/ssh/sshd_config baseline/<os-id>/<svc>/hardened/etc/ssh/sshd_config
```

The left pane is default, the middle is the live image and the right is your target. Anything in the middle that differs from the left is a potential planted vuln; merge from the right to harden.
