#!/usr/bin/env python3
"""V: start speedrun.sh in a pty, stop at the forensics prompt, wait, report what changed, then Ctrl-C."""
import os, pty, select, subprocess, sys, time, signal
subprocess.run("touch -d '-1 sec' /tmp/V-marker", shell=True)
pid, fd = pty.fork()
if pid == 0:
    os.chdir("/root/competition"); os.environ["SUDO_USER"] = "cpuser"; os.environ["TERM"] = "xterm"
    os.execvp("bash", ["bash", "speedrun.sh"])
buf = ""; t0 = time.time()
while time.time() - t0 < 120:
    r, _, _ = select.select([fd], [], [], 0.5)
    if r:
        try: buf += os.read(fd, 65536).decode(errors="replace")
        except OSError: break
    if "Forensics Questions" in buf: break
seen = time.time() - t0
print(f"forensics prompt after {seen:.1f}s; output before it:\n{buf}\n---- waiting 30 s at the prompt")
time.sleep(30)
chk = r"""echo "apt processes: $(pgrep -af 'apt-get|apt.systemd|unattended' | grep -v pgrep || echo none)"
echo "cp-upgrades dir: $(ls /var/cache/apt/cp-upgrades 2>&1 | head -3 | tr '\n' ' ')"
echo "apt lists newer than start: $(find /var/lib/apt/lists -maxdepth 1 -type f -newer /tmp/V-marker | wc -l)"
echo "speedrun jobs: $(ls /root/cp-state/speedrun/jobs 2>/dev/null | tr '\n' ' ')"
echo "files under /etc changed since start:"; find /etc -newer /tmp/V-marker \( -type f -o -type l \) 2>/dev/null | sed 's/^/   /'
echo "other changed (excluding /root/baseline /root/cp-state /proc /sys /run /tmp /var/log):"
find / -xdev -newer /tmp/V-marker \( -type f -o -type l \) 2>/dev/null | grep -vE '^/(root/baseline|root/cp-state|proc|sys|run|tmp|var/log|var/lib/systemd|var/cache/man|root/logs)/' | head -20 | sed 's/^/   /'
echo "baseline job: $(cat /root/cp-state/speedrun/jobs/baseline.rc 2>/dev/null || echo running)"
"""
print(subprocess.run(chk, shell=True, capture_output=True, text=True).stdout)
os.write(fd, b"\x03"); time.sleep(2)
try: os.kill(pid, signal.SIGKILL)
except Exception: pass
