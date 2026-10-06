#!/usr/bin/env python3
"""Run a script in a pseudo-terminal and answer prompts by regex (simulates a human reading the README)."""
import os, pty, re, sys, select, time
script = sys.argv[1]
answers = [(re.compile(a, re.I), b) for a, b in zip(sys.argv[2::2], sys.argv[3::2])]
default = "\n"
pid, fd = pty.fork()
if pid == 0:
    os.environ["PATH"] = "/tmp/fakebin:" + os.environ["PATH"]
    os.execvp("bash", ["bash", script])
buf = ""
log = open("drive.log", "a")
while True:
    r, _, _ = select.select([fd], [], [], 120)
    if not r: break
    try: data = os.read(fd, 4096).decode(errors="replace")
    except OSError: break
    if not data: break
    buf += data; log.write(data); log.flush()
    tail = buf[-400:]
    # a prompt is waiting when output ends with ": " or "] " or "? "
    if re.search(r"(\?|:|\]|\.\.\.)\s*$", tail.split("\n")[-1]):
        line = tail.split("\n")[-1]
        ans = None
        for rx, a in answers:
            if rx.search(line): ans = a; break
        if ans is None:
            ans = "y" if "screenshot" in line else ""
        os.write(fd, (ans + "\n").encode()); buf = ""
os.waitpid(pid, 0)
