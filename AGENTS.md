# AGENTS.md

Two executable bash scripts, no build, no CI, no lint config, no test framework.
`README.md` (500+ lines) is the design document and part of the deliverable, not
just documentation — read it before changing behaviour.

- `bubblewrap_opencode` — the wrapper. Resolves opencode → `--help` short-circuit
  → state-dir selection → cache/config seeding → credential masks → prefs →
  `bwrap_args` → `--standalone` argument juggling → `exec bwrap … -- opencode …`.
- `sandbox-selftest` — the measuring instrument. It runs *inside* the sandbox the
  wrapper just built, and is the stated authority for every security claim in the
  README.

## Verify changes

- **You are probably already inside the sandbox** (`hostname` = `opencode-sandbox`,
  `stat -f -c %T ~/.local/share/opencode-sbx` = `tmpfs`). Nested `bwrap` is denied
  by design, so any wrapper invocation from here fails with
  `bwrap: Creating new namespace failed: … (ENOSPC)`. Run the wrapper from an
  ordinary host login; that is also exactly what the README's "Not tested here"
  section is still waiting for.
- The one verification command:
  `OPENCODE_SANDBOX_EXEC=1 ./bubblewrap_opencode ./sandbox-selftest [security|functional|toolchains|all]`
  `OPENCODE_SANDBOX_EXEC` is a switch — the value is never the command.
- When the change touches preferences, run it twice: plain, then
  `OPENCODE_SANDBOX_HOST_PREFS=1 …` (that pass must report the flip).
- `./sandbox-selftest` on a host prints a `NOT INSIDE A SANDBOX` block and then
  expects CROSS-REPO ISOLATION and HOST IPC to report `[ OPEN ]`. On the host,
  functionality passing means "baseline only".
- `toolchains` downloads packages; it is slow. Network probes accept any HTTP
  status, and `SBX_EGRESS_URL` / `SBX_DNS_HOST` pin the targets.
- No shellcheck on this host — `bash -n bubblewrap_opencode` is the only static
  check available.
- `./bubblewrap_opencode --help` is the only wrapper path that works inside a
  sandbox: it needs no bwrap and creates no state. History is 24 commits straight
  to `main`.

## Editing discipline

- A new `OPENCODE_SANDBOX_*` variable needs three edits: the wrapper's `--help`
  heredoc, the README "Environment variables" table, and the selftest if it
  changes a verdict.
- A new hardening claim needs a selftest check. The README tables assert each row
  was re-run at the commit that added it — re-run before claiming it.
- "What is NOT protected" is load-bearing, and the "Not tested here" list is live
  open work. Do not let them go stale.

## Deliberate; do not "fix"

- `--share-net`. Egress filtering belongs in front of the wrapper, not in it.
- `prefs/model.json` shared across every repo, as one bound *file* with its
  directory masked. Per-repo favourites were the bug this fixed.
- The host's `~/.config/opencode` readable (only not writable), so a dotfiles
  symlink keeps resolving.
- The per-repo `data/opencode/auth.json` is a real, readable, mode-600 credential
  copy on the host disk. `OPENCODE_SANDBOX_RESET=1` is how you revoke it.
- The two-repos-writing-`model.json` lock race is documented, not fixed.
- The state root is a masked tmpfs, so sibling repos are invisible from inside —
  a tool that walks it will under-report. That is the intended answer.

## bwrap invariants (only when touching the mount list)

- Order matters: every `--tmpfs` mask and every `--ro-bind-data` mask comes
  **before** the per-repo `--bind`s. bwrap resolves a bind's *source* in the host
  namespace, so this works; the destinations are recreated inside the tmpfs.
- A mount point must exist on the host before bwrap starts — bwrap cannot create
  one underneath `--ro-bind / /`. That is why the `hide_dirs` loop does
  `mkdir -p` and why `mkdir -p "${SBX}/state/opencode"` precedes the `model.json`
  bind. Every new tmpfs target needs the same.
- Each 0-byte mask needs its own fd (`exec {fd}</dev/null` per call); bwrap
  consumes them.
- `OPENCODE_SANDBOX_HOME` must be writable and **not under `/tmp`**. The
  writability probe is `( : > file )`, never `mkdir -p` — that succeeds on a
  read-only filesystem when the directory already exists. Note the probe *is*
  fooled by the masked tmpfs when the wrapper runs inside a sandbox, so a nested
  run reports no fallback and its state is RAM-only. Never diagnose state
  placement from a nested run.

## Bash traps

- Wrapper runs under `set -eo pipefail`; the selftest under `set -uo pipefail`
  with **no `-e`**, because most checks expect commands to fail.
- Keep the empty-array splice shape `${arr[@]+"${arr[@]}"}"` when adding optional
  bind groups.
- `${@:N}` is 1-based, and a nested `${#path[@]}` inside it is mis-parsed into a
  silently wrong slice — compute the offset in a variable first.
- In the selftest, expand every wrapper-exported variable with a default. A
  wrapper regression that stops exporting one then shows up as an aborted run
  rather than a verdict. `IN_SANDBOX` is detected via `UV_TOOL_BIN_DIR` under
  `$SBX_ROOT`, not `XDG_DATA_HOME` (a desktop session sets that too).
- The selftest classifies writable paths from `/proc/self/mountinfo`
  (`bind_root`) and matches on the repo *key* or a path *suffix* — never a full
  prefix, because the mount root is filesystem-relative (`/@home/lukas/…` on
  this btrfs subvolume). New report rows must follow that convention.
- `--standalone` (opencode v2.0.11 here, gated on `*v[2-9].*`): belongs *after*
  the subcommand path, acceptance is per **leaf** command, the verdict is cached
  in `<state root>/.standalone-flags`, and the subcommand path is the leading run
  of non-flag args capped at 3 words so `run "long message"` is not split.
- Checks whose subject is absent must report `[ n/a ]` or a skip, never `FAIL`,
  so a minimal host still passes.

## State

Outside the repository on purpose (`git clean -fdx` would destroy session
history), keyed on the git toplevel: `<root>/<repo>-<sha256[:12]>/{data,state,cache,tools,config}`
plus `<root>/prefs/model.json` shared by every repo.

- `config/` and `cache/home` are seeded once from the host, copied to a temp name,
  moved into place, marker `.opencode-seeded` written last, and a failed seed
  warns rather than aborting. Plain files in the config copy are snapshots from
  seed time — only `OPENCODE_SANDBOX_RESET=1` re-seeds them. Symlinks stay live
  (`cp -a`), which is why this host's `~/.config/opencode/opencode.json` symlink
  into `~/profile/playbooks/opencode.json` keeps resolving.
- Relocate opencode's config with `OPENCODE_CONFIG_DIR`, never `XDG_CONFIG_HOME`:
  moving the latter relocates `git` and `gh` configuration too. `XDG_CACHE_HOME`
  is safe to move wholesale precisely because opencode resolves its cache as
  `$XDG_CACHE_HOME/opencode` with no variable of its own.
- The package-manager exports (`BUN_INSTALL_CACHE_DIR`, `npm_config_cache`,
  `UV_CACHE_DIR`, `UV_TOOL_DIR`, `UV_TOOL_BIN_DIR`, `PIP_CACHE_DIR`) must stay
  pointed at the per-repo copies while `~/.bun` and `~/.local/share/uv/tools` are
  ro-bound.
