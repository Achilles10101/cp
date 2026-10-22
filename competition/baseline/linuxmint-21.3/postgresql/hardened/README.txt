B11: put YOUR hardened versions of the files from ../pristine/ here, same paths
(e.g. hardened/etc/ssh/sshd_config). At competition time open a 3-way Meld:
  meld <pack>/postgresql/pristine/<file> /<file> <pack>/postgresql/hardened/<file>
