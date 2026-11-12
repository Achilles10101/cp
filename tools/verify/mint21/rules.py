#!/usr/bin/env python3
"""rules.py RULES_FILE  ->  prints the run plan as JSON (used by run-pipeline.sh).

Rules file format (one directive per line, '#' starts a comment line, blank lines ignored):

  set KEY=VALUE          harness setting. Before the first 'step' = default for every step; inside a step = that step only.
                         IDLE (s of quiet output = "a prompt is waiting", default 2.5)   HARD (s, kill the step, default 1500)
                         UMASK (e.g. 0022; default: docker exec's own umask, 0000 here, as on 2026-10-21)
                         SUDO_USER (default cpuser)   DEBIAN_FRONTEND (default readline)   SSH_PORT (for svccheck, default 22)
                         FINDINGS=1 (count baseline '!!' findings after this step; automatic for steps running baseline.sh)
  env NAME=VALUE         environment variable for the command (global before the first step, else per step)
  step NAME CMD...       a new step: CMD runs inside /root/competition through drive2.py (a pseudo-terminal)
  rule REGEX => ANSWER   answer prompts matching REGEX (Python regex, case-insensitive, searched in the last 4 non-empty
                         output lines once output is quiet). First match wins: the step's rules, then the global rules
                         (those before the first step), then the built-in "taken a screenshot" => y.
                         ANSWER is typed followed by Enter; empty ANSWER = just Enter; "SEQ:a,b,c" = a, then b, then c
                         on successive matches (then Enter). Prompts that match nothing get Enter (the script's default).
"""
import json, re, shlex, sys

def die(n, msg):
    sys.exit(f"{sys.argv[1]}:{n}: {msg}")

def main():
    glob = {"set": {}, "env": {}, "rules": []}
    steps = []
    cur = glob
    for n, raw in enumerate(open(sys.argv[1], encoding="utf-8"), 1):
        line = raw.rstrip("\n")
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        kw, _, rest = s.partition(" ")
        rest = rest.strip()
        if kw == "step":
            name, _, cmd = rest.partition(" ")
            if not name or not cmd.strip():
                die(n, "step needs NAME and CMD")
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                die(n, f"step name {name!r}: use letters, digits, . _ -")
            cur = {"name": name, "cmd": shlex.split(cmd), "set": {}, "env": {}, "rules": []}
            steps.append(cur)
        elif kw in ("set", "env"):
            k, eq, v = rest.partition("=")
            if not eq or not k.strip():
                die(n, f"{kw} needs NAME=VALUE")
            cur[kw][k.strip()] = v.strip()
        elif kw == "rule":
            if " => " in rest:
                rx, ans = rest.split(" => ", 1)
            elif rest.endswith(" =>"):
                rx, ans = rest[:-3], ""
            else:
                die(n, "rule needs 'REGEX => ANSWER'")
            rx, ans = rx.strip(), ans.strip()
            try:
                re.compile(rx, re.I)
            except re.error as e:
                die(n, f"bad regex {rx!r}: {e}")
            cur["rules"].append([rx, ans])
        else:
            die(n, f"unknown directive {kw!r} (set/env/step/rule)")
    if not steps:
        sys.exit(f"{sys.argv[1]}: no steps")
    defaults = {"IDLE": "2.5", "HARD": "1500", "UMASK": "", "SUDO_USER": "cpuser",
                "DEBIAN_FRONTEND": "readline", "SSH_PORT": "22", "FINDINGS": ""}
    out = []
    for st in steps:
        sett = dict(defaults); sett.update(glob["set"]); sett.update(st["set"])
        env = dict(glob["env"]); env.update(st["env"])
        if not sett["FINDINGS"]:
            sett["FINDINGS"] = "1" if any("baseline.sh" in c for c in st["cmd"]) else "0"
        out.append({"name": st["name"], "cmd": st["cmd"], "set": sett, "env": env,
                    "rules": st["rules"] + glob["rules"]})
    json.dump({"steps": out, "global": glob["set"]}, sys.stdout, indent=1)

if __name__ == "__main__":
    main()
