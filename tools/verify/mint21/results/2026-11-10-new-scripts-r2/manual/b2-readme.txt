### typed none
[    2.5s] '? Paste the README now:' -> 'Authorized Administrators:\ncpuser (you)\n\tpassword: Cyb3rP@triot!\nalice\n\tpassword: Alic3-Adm1n!\n\nAuthorized Users:\nbob\ncarol\ndave\nfrank\n' (rule)
[    5.5s] '? Critical services in the README - type numbers or names, or none:' -> 'none' (rule)
[    8.0s] '? Correct? Enter = yes | a = admins  u = users  m = you  s = services  p = paste again [y]:' -> '' (rule)
[   10.6s] '? README lists NO critical services, but these are installed and will be offered for removal: openssh-server vsftpd apache2 - correct? [y/N]:' -> '' (rule)
[   13.1s] '? Critical services in the README - type numbers or names, or none:' -> '1' (rule)
[   15.6s] '? Correct? Enter = yes | a = admins  u = users  m = you  s = services  p = paste again [y]:' -> '' (rule)
STATS prompts=6 rule=6 default=0 stall=0 wait=15.0s elapsed=15.6s
EXIT 0
  README answers (/root/cp-state/readme.conf):
    ADMINS    cpuser alice
    USERS     bob carol dave frank
    ME        cpuser
    SERVICES  ssh
    WEAKPW    -
### whole page
[    2.5s] '? Paste the README now:' -> 'CyberPatriot README\n\nCompetition Scenario\nThis company\'s security policies require that all user accounts be password protected. Employees are required to choose secure passwords, however this policy may not be currently enforced on this computer. The presence of any non-work related media files and "hacking tools" on any computers is strictly prohibited. Do not install an FTP server or a web server.\n\nLinux Mint 21\n\nIt is company policy to use only Linux Mint 21 on this computer.\n\nCritical Services:\nOpenSSH Server (sshd)\n\nAuthorized Administrators and Users\n\nAuthorized Administrators:\ncpuser (you)\n\tpassword: Cyb3rP@triot!\nalice\n\tpassword: Alic3-Adm1n!\n\nAuthorized Users:\nbob\ncarol\ndave\nfrank\n\nCompetition Guidelines\nIn order to complete this exercise, you must log into the computer, and you must verify the scoring report. Do not stop or remove critical services listed in this README or you may lose points.\nAnswering Forensics Questions\ny' (rule)
[    5.6s] '? Correct? Enter = yes | a = admins  u = users  m = you  s = services  p = paste again [y]:' -> '' (rule)
STATS prompts=2 rule=2 default=0 stall=0 wait=5.0s elapsed=5.6s
EXIT 0
  README answers (/root/cp-state/readme.conf):
    ADMINS    cpuser alice
    USERS     bob carol dave frank
    ME        cpuser
    SERVICES  ssh
    WEAKPW    -
