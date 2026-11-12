# tools/verify/mint21 - Linux Mint 21.3 container test harness (TEST ONLY)

Runs the `competition/` scripts inside throwaway systemd containers that look like a Linux Mint 21.3 Cinnamon
image, answers their prompts from a rules file the way a competitor who read the README would, times every step,
and scores the result. **Never run anything from here on a real image** (`plant*.sh` plant vulnerabilities).

## Images (build: `build/build-images.sh [clean|services|planted|svcplanted|all]`)

| image | what |
|---|---|
| `cp-mint-clean` | Ubuntu jammy with the exact package set of the 2026-10-21 Mint image (`build/jammy-packages.txt`), Mint's own packages built from github.com/linuxmint at their 21.3 versions + stubs (`build/build-mint-debs.sh`), Mint identity, user `cpuser` (sudo) |
| `cp-mint-services` | clean + every critical service at defaults (+ test-only no-IPv6 overrides for vsftpd/dovecot, nginx installed but disabled, account `ftpuser`) |
| `cp-mint-planted` | clean + OpenSSH, vsftpd, apache2, hacking tools + `plant-mint.sh` (README: admins `cpuser alice`, users `bob carol dave frank`, critical service OpenSSH) |
| `cp-mint-svcplanted` | services + `../plant.sh` |

## Run a pipeline

```
./run-pipeline.sh IMAGE COMPETITION_DIR RULES_FILE OUTDIR
# old scripts, as on 2026-10-21:
./run-pipeline.sh cp-mint-planted    /home/claude/orig/competition rules-2026-10-21.txt     /tmp/out-planted
./run-pipeline.sh cp-mint-svcplanted /home/claude/orig/competition rules-2026-10-21-svc.txt /tmp/out-svc
# baseline scan alone (time + findings), no scoring:
NOSCORE=1 ./run-pipeline.sh cp-mint-clean /home/claude/work/competition rules-baseline-only.txt /tmp/out-bl
```

It starts a fresh container, copies COMPETITION_DIR to `/root/competition`, runs each step through `drive2.py`
(pseudo-terminal) from inside that folder as root with `SUDO_USER=cpuser`, then runs `mintchecks.py` (100 checks
from `checks_cp.py` + 44 planted-image checks) and `svccheck.sh` (is every installed service up and answering), and
removes the container. Env: `NAME=` container name, `KEEP=1` keep it, `NOSCORE=1`, `RESYSCTL=0` (see below).

OUTDIR gets `summary.txt` / `summary.json` (per-step wall-clock, prompts answered, harness wait, findings; totals;
checks; services), `timings.tsv`, `score.txt` + `score.json` (every check), `svccheck.txt`, `todo.txt`
(`/root/cp-state/TODO.txt` if the scripts wrote one), `findings-<step>.txt`, `logs/<step>.log` (full terminal
output) and `logs/<step>.log.answers` (every prompt, the answer typed, and which rule matched).

Timing columns: `wall` = host wall-clock of the step, `wait` = time the harness sat waiting for quiet output before
answering (IDLE = 2.5 s per prompt; a STALL = 40 s of silence without a prompt-looking line, then Enter), `net` =
`wall - wait` = time the scripts themselves ran. The machine is shared (2 CPUs), so `load` is recorded per step.

## Rules file format (`rules.py` parses it; `python3 rules.py FILE` prints the plan / errors)

```
# comment
set HARD=1500                       # before the first step = default for all steps
env CP_ADMINS=cpuser alice          # before the first step = passed to every step
rule taken a screenshot => y        # before the first step = global rule (checked after the step's own rules)

step p2-users bash usersandsudo.sh  # NAME then the command, run inside /root/competition
env CP_USERS=bob carol dave frank   # only for this step
set IDLE=3                          # only for this step
rule Remove these users\?   => y    # REGEX => ANSWER
rule New password:          => Car0l-Str0ng!pw
rule Select option          => SEQ:2,3,4   # successive answers on successive matches
rule Press Enter            =>             # empty answer = just Enter
```

- REGEX: Python, case-insensitive, searched in the last 4 non-empty output lines once output has been quiet for
  IDLE seconds. First match wins (step rules, then global rules, then the built-in `taken a screenshot => y`).
  No match + the line looks like a prompt (ends in `? : ] ) > +` or `...`) -> Enter = the script's default.
- `set` keys: `IDLE` (2.5), `HARD` (1500 s, then the step is killed), `UMASK` (default: docker exec's own, which is
  `0000` on this host - the 2026-10-21 runs had the same; use `set UMASK=0022` for a sudo-like umask), `SUDO_USER`
  (cpuser), `DEBIAN_FRONTEND` (readline), `SSH_PORT` (22; port given to svccheck.sh if the rules move SSH),
  `FINDINGS=1` (count baseline findings after this step; automatic when the command runs `baseline.sh`). New
  baseline.sh: FIX NOW + REVIEW from the `/root/baseline/FINDINGS.txt` header (copied to `FINDINGS-<step>.txt`);
  old baseline.sh: `!!` lines in `/root/baseline/*/report.txt` (always recorded too, as `bang=`).
- `fakebin/` is first on PATH: `nano` types `$CP_ADMINS`/`$CP_USERS` into the old usersandsudo.sh user list,
  `visudo` deletes the NOPASSWD lines a person would delete. The new scripts read README facts from
  `readme.sh` / env `CP_ADMINS CP_USERS CP_SERVICES`, so for them put those three `env` lines before the first step.
- Check every `*.log.answers` after a run: a `DEFAULT(Enter)` on a question you meant to answer means the regex
  did not match; `STALL->Enter` means a step was silent for 40 s (that Enter may land in the next prompt).

## Known limits of the containers
No IPv6 in the kernel (test-only listen overrides for vsftpd/dovecot; nginx not running next to apache2), no X
session (LightDM configured, not running), auditd cannot start, no /boot/grub. `kernel.*` sysctls are global to the
host: every privileged container that boots applies its own sysctl.d (e.g. `cp-mint-planted` sets
`randomize_va_space=0`), so `run-pipeline.sh` re-applies the container's own sysctl config right before scoring
(`RESYSCTL=0` turns that off); otherwise the two 1984 live-`/proc` checks flip at random.

`results/2026-11-10-old-scripts/` = the "before" runs of the OLD scripts (timings, scores, every prompt/answer).
Edit `run-pipeline.sh` by writing a new file and `mv`-ing it over: bash reads a running script lazily, so editing it
in place breaks runs that are in progress.

`docker commit` on this host drops POSIX ACLs (file capabilities survive). `build-images.sh` saves them in the image
label `cptest.acls` (cp-mint-planted: the planted `u:bob:rwx` ACL on /usr/bin/sudo) and `run-pipeline.sh` restores
them after boot; if you start an image yourself, run `./restore-acls.sh CONTAINER` (without it, sudo is a plain 4755).

Legacy 2026-10-21 drivers (`pipeline.sh`, `svcpipe.sh`, `runstep.sh`) still work against a running container.
