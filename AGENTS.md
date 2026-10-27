# AGENTS.md

Two executable bash scripts; no build, CI, lint config or test framework.
`README.md` is the user-facing reference (mounts, environment variables).
`DESIGN.md` is the long-form reference: threat model, protected/not-protected
tables, what each selftest section asserts, SSH forwarding, state layout. This
file is what you need before changing either script.

- `bubblewrap_opencode` — the wrapper: resolve opencode → `--help`
  short-circuit → state-dir selection → shared config/state seeding → per-repo
  cache seeding → credential masks → `bwrap_args` → `--standalone` juggling →
  `exec bwrap … -- opencode …`.
- `sandbox-selftest` — runs *inside* the sandbox the wrapper just built, and is
  the authority for every security claim.
- `.v/` — a stray local Python venv with its own `.gitignore`; nothing here uses
  it.

## Verify changes

- **Check whether you are already inside the sandbox before running anything.**
  `hostname` is `opencode-sandbox`, and `~/.local/share/opencode-sbx` is a tmpfs
  when the default state root is in use. Nested `bwrap` is denied by design, so
  a wrapper invocation there fails with `bwrap: Creating new namespace failed:
  … (ENOSPC)`. Run the wrapper from an ordinary host login.
- The one verification command:

  ```sh
  OPENCODE_SANDBOX_EXEC=1 ./bubblewrap_opencode ./sandbox-selftest [security|functional|toolchains|all]
  ```

  `OPENCODE_SANDBOX_EXEC` is a switch: any non-empty value makes the wrapper run
  its own argv inside the sandbox instead of opencode, and the value is never
  interpreted as a command.
- `security` + `functional` are the quick pair; `all` adds `toolchains`, which
  downloads npm/bun/uv/pip packages and is slow. Network probes accept any HTTP
  status; `SBX_EGRESS_URL` / `SBX_DNS_HOST` pin the targets.
- Run `./sandbox-selftest` only through the wrapper. Directly on a host it prints
  a `NOT INSIDE A SANDBOX` block and is a baseline, not a verdict: `FUNCTIONALITY`
  passing there means "baseline only", and `HOST IPC`, `ESCAPE MECHANISMS` and
  `CROSS-REPO ISOLATION` are expected to report `[ OPEN ]` there.
- The selftest is not read-only: it writes `./.selftest-probe`, installs packages
  under `/tmp`, and temporarily replaces the shared `model.json` (restored by an
  `EXIT`/`INT`/`TERM`/`HUP` trap; a SIGKILL can leave `.selftest-backup.*`
  behind).
- Absent subjects make vacuous rows. `denied` treats any non-zero exit, including
  command-not-found, as denied; `sock` reports a non-existent socket as
  `[CLOSED]`. On a minimal host do not cite those rows as proof the mechanism
  was exercised.
- `bash -n bubblewrap_opencode` and `bash -n sandbox-selftest` are the only static
  checks; there is no shellcheck on this host.
- `./bubblewrap_opencode --help` is the only wrapper path that works inside a
  sandbox: it needs no bwrap and creates no state.
- After changing preferences or shared state, run twice: plain, then
  `OPENCODE_SANDBOX_SYNC_PREFS=1 …`. The second pass must print the host pull and
  leave the shared `model.json` matching the host's.
- The script exits non-zero if any check failed. On a host the escape checks
  really do succeed, so a full run there exits non-zero by design.

## Editing rules

- A new `OPENCODE_SANDBOX_*` variable needs three edits: the wrapper's `--help`
  heredoc, the README "Environment variables" table, and the selftest if it
  changes a verdict. A protection change also touches `DESIGN.md`.
- A new hardening claim needs a selftest check. Re-run the affected section at
  the commit that adds the claim; `DESIGN.md` asserts its tables were re-run.
- "What is NOT protected" is load-bearing and must not go stale. The "Deliberate;
  do not 'fix'" list in `DESIGN.md` is not a bug queue: `--share-net`, shared
  config/state, readable host config, the plaintext per-repo credential copy and
  the documented lock race are all chosen.
- Removing a variable keeps a warning for one release: `OPENCODE_SANDBOX_HOST_PREFS`
  is the precedent (wrapper warns, README marks it removed).

## bwrap mount invariants (only when touching the mount list)

- Mounts apply in order and **a later mount hides an earlier one beneath it**.
  Current order in `bwrap_args`: `--ro-bind / /` → `--tmpfs /tmp` → `cwd_args` →
  `hide_dirs` tmpfs masks → 0-byte `mask_args` → per-repo binds → shared
  state/config binds → `/dev`/`/proc` → SSH socket → read-only toolchains.
  Never move the cwd bind after a mask or after `/tmp`: a cwd of `$HOME`/`/home`
  would hide every mask under it, and a cwd under `/tmp` would be hidden by the
  `/tmp` tmpfs.
- Bind sources are resolved in the host namespace, so the per-repo and shared
  binds still work after `${SBX_PARENT}` is masked; the destinations are
  recreated inside the tmpfs. Every tmpfs target must already exist on the host —
  bwrap cannot create one under `--ro-bind / /` — hence the `mkdir -p` in the
  `hide_dirs` loop and before the shared state/config binds.
- Each 0-byte mask needs its own fd (`exec {fd}</dev/null`); bwrap consumes them.
- `hide_dirs` dedupes `XDG_RUNTIME_DIR` against `/run/user/<uid>` and, when a
  target is absent and uncreatable, reports it and leaves it visible read-only
  rather than aborting.
- `OPENCODE_SANDBOX_HOME` must be writable and not under `/tmp`. The probe is
  `( : > file )`, never `mkdir -p` (which succeeds on a read-only filesystem when
  the directory already exists). There is no `/tmp` fallback; the fallback is
  `${XDG_CACHE_HOME}/opencode-sbx`. A nested run's probe is fooled by the masked
  tmpfs, so never diagnose state placement — or the no-fallback path — from a
  nested run.
- The cwd bind is writable at its exact path even when that path is host state:
  running from `~/.cache/opencode` makes it writable (verified). The `~/.cache`
  and `~/.config/opencode` read-only re-binds exist only in the
  `OPENCODE_SANDBOX_HOME_RW=1` branch. Do not run the wrapper from either path.
- v2 credential seeding needs `sqlite3` on the host; without it the per-repo DB
  is left without provider rows (wrapper warns, selftest reports `n/a`). On the
  first seed the wrapper bootstraps the schema by running
  `opencode session list --standalone` against a blank config (60 s timeout),
  then ATTACHes the host DB `mode=ro` and copies only the `credential` rows.

## Bash traps

- The wrapper runs under `set -eo pipefail`; the selftest under `set -uo pipefail`
  with **no `-e`**, because most of its checks expect commands to fail.
- Keep the empty-array splice shape `${arr[@]+"${arr[@]}"}"` when adding optional
  bind groups.
- `${@:N}` is 1-based, and a nested `${#path[@]}` inside it is mis-parsed into a
  silently wrong slice — compute the offset in a variable first.
- In the selftest, expand every wrapper-exported variable with a default, so a
  wrapper regression that stops exporting one shows up as a verdict rather than
  an aborted run. `IN_SANDBOX` is detected via `UV_TOOL_BIN_DIR` under
  `$SBX_ROOT`, not `XDG_DATA_HOME` (a desktop session sets that too).
- Writable paths are classified from `/proc/self/mountinfo` (`bind_root`),
  matching the repo *key* or a path *suffix* — never a full prefix, because
  mount roots are filesystem-relative (`/@home/lukas/…` on this btrfs
  subvolume). New report rows must follow that convention.
- `--standalone` is gated on `*v[2-9].*` and belongs *after* the subcommand path.
  The deny list is hard-coded from the v2.1.2 help output (the version installed
  here), so an unknown command gets the flag; re-check it when opencode is
  upgraded. `auth` and `session` are the only commands whose second word is part
  of the path.

## Gotchas

- **Check which copy you are running.** An older `bubblewrap_opencode` installed
  on `PATH` (typically `~/.local/bin`) takes precedence over this directory and
  quietly ignores every variable documented here. Use `./bubblewrap_opencode`.
- The state root is masked inside the sandbox; a tool that walks it (e.g. to size
  the other repos) sees only this repo and concludes it is alone. Intended.
- opencode's config and state are shared by every repo; a repo's `data/`, `cache/`
  and `tools/` are not. Reset the shared copy with `rm -rf <root>/shared`; reset
  one repo with `OPENCODE_SANDBOX_RESET=1` from that repo (deletes its `data/`,
  `cache/`, `tools/` and the shared config, keeps the shared state). The first
  run anywhere seeds the shared config; each repo's first run seeds its cache
  (reflink where supported, otherwise a real copy — ~57 MB of plugin
  `node_modules` on this host).
- Old per-repo `state/opencode/` and `config/opencode/` are hidden by the shared
  binds; `prefs/model.json` is read only as a seed fallback.
- `OPENCODE_SANDBOX_SSH=1` with gpg-agent's socket re-opens the gpg-agent row the
  selftest expects `[CLOSED]`. That is the opt-in, not a regression. A bind-mounted
  socket is also reported by `find -type s` as a regular file, so a clean
  `HOST IPC SOCKETS` sweep is not proof forwarding is off. Check with:
  `OPENCODE_SANDBOX_SSH=1 OPENCODE_SANDBOX_EXEC=1 ./bubblewrap_opencode ssh-add -l`.
- `GH_TOKEN` in the environment crosses into the sandbox whether or not
  `OPENCODE_SANDBOX_GH_TOKEN=1` is set; the flag only resolves the keyring-stored
  token on the host. The selftest skips its GitHub row when `GH_TOKEN` is unset
  and asserts it only when set, so `[skip]` is not a failure.
- Do not run two sandboxes with terminal sessions at once: opencode's shared
  state has a documented lock race and one PTY registry.
