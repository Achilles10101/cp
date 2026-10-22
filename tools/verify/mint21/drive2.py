#!/usr/bin/env python3
"""Drive an interactive script through a pseudo-terminal, like a person at the keyboard.

usage: drive2.py LOG -- CMD... ; rules come from the env var RULES (JSON list of [regex, answer]).
A prompt is "whatever the last output line is once output has been quiet for IDLE seconds".
Each prompt is matched against the rules in order (first match wins); no match -> Enter (default answer).
Every prompt/answer pair is logged to LOG.answers so the run can be audited afterwards.
"""
import json, os, pty, re, select, sys, time, signal

log_path = sys.argv[1]
cmd = sys.argv[sys.argv.index("--") + 1:]
rules = [(re.compile(a, re.I), b) for a, b in json.loads(os.environ.get("RULES", "[]"))]
rules.append((re.compile(r"taken a screenshot", re.I), "y"))
seen = {}
queues = {}
IDLE = float(os.environ.get("IDLE", "2.5"))
HARD = float(os.environ.get("HARD", "1500"))
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\r")

pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)

log = open(log_path, "w")
ans_log = open(log_path + ".answers", "w")
buf = ""
last = time.time()
start = time.time()
pending = False
while True:
    if time.time() - start > HARD:
        ans_log.write("!! HARD TIMEOUT - killed\n"); os.kill(pid, signal.SIGKILL); break
    r, _, _ = select.select([fd], [], [], 0.5)
    if r:
        try:
            data = os.read(fd, 65536).decode(errors="replace")
        except OSError:
            break
        if not data:
            break
        log.write(data); log.flush()
        buf = (buf + data)[-4000:]
        last = time.time(); pending = True
        continue
    if pending and time.time() - last > IDLE:
        lines = [l.strip() for l in ANSI.sub("", buf).split("\n")]
        line = lines[-1]
        ctx = " | ".join(l for l in lines[-4:] if l)
        if not line:
            pending = False
            continue
        ans = None
        for rx, a in rules:
            if rx.search(ctx):
                ans = a; break
        looks_like_prompt = re.search(r"([?:\]\)>+]|\.\.\.)\s*$", line) is not None
        if ans is None and not looks_like_prompt and time.time() - last < 40:
            continue   # probably still working (apt, find ...) - don't type into it yet
        tag = "rule" if ans is not None else ("DEFAULT(Enter)" if looks_like_prompt else "STALL->Enter")
        if ans is None:
            ans = ""
        if ans.startswith("SEQ:"):
            q = queues.setdefault(id(rx), ans[4:].split(","))
            ans = q.pop(0) if q else ""
        seen[line] = seen.get(line, 0) + 1
        if seen[line] > 30:
            ans_log.write(f"!! LOOP on prompt {line!r} - killed\n"); os.kill(pid, signal.SIGKILL); break
        ans_log.write(f"[{time.time()-start:7.1f}s] {line[-160:]!r} -> {ans!r} ({tag})\n"); ans_log.flush()
        os.write(fd, (ans + "\n").encode())
        buf = ""; pending = False
_, status = os.waitpid(pid, 0)
code = os.waitstatus_to_exitcode(status)
ans_log.write(f"EXIT {code}\n")
log.write(f"\n[drive2] EXIT {code}\n")
sys.exit(0)
