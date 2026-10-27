# AGENTS.md

Two executable bash scripts, no build, no CI, no lint config, no test framework.
`README.md` is the quick reference (what is bound where, environment variables);
this file is the design document. Read it before changing behaviour.

- `bubblewrap_opencode` — the wrapper. Resolves opencode → `--help` short-circuit
  → state-dir selection → shared config/state seeding → per-repo cache seeding →
  credential masks → `bwrap_args` → `--standalone` argument juggling →
  `exec bwrap … -- opencode …`.
- `sandbox-selftest` — the measuring instrument. It runs *inside* the sandbox the
  wrapper just built, and is the stated authority for every security claim in
  this file.

## Verify changes

- **You are probably already inside the sandbox** (`hostname` = `opencode-sandbox`,
  `stat -f -c %T ~/.local/share/opencode-sbx` = `tmpfs`). Nested `bwrap` is denied
  by design, so any wrapper invocation from here fails with
  `bwrap: Creating new namespace failed: … (ENOSPC)`. Run the wrapper from an
  ordinary host login.
- The one verification command:
  `OPENCODE_SANDBOX_EXEC=1 ./bubblewrap_opencode ./sandbox-selftest [security|functional|toolchains|all]`
  `OPENCODE_SANDBOX_EXEC` is a switch — the value is never the command.
- When the change touches preferences or the shared state, run it twice: plain,
  then `OPENCODE_SANDBOX_SYNC_PREFS=1 …` (that pass must report the host pull and
  the shared `model.json` must match the host's afterwards).
- `./sandbox-selftest` on a host prints a `NOT INSIDE A SANDBOX` block and then
  expects CROSS-REPO ISOLATION and HOST IPC to report `[ OPEN ]`. On the host,
  functionality passing means "baseline only".
- `toolchains` downloads packages; it is slow. Network probes accept any HTTP
  status, and `SBX_EGRESS_URL` / `SBX_DNS_HOST` pin the targets.
- No shellcheck on this host — `bash -n bubblewrap_opencode` is the only static
  check available.
- `./bubblewrap_opencode --help` is the only wrapper path that works inside a
  sandbox: it needs no bwrap and creates no state.

## Editing discipline

- A new `OPENCODE_SANDBOX_*` variable needs three edits: the wrapper's `--help`
  heredoc, the README "Environment variables" table, and the selftest if it
  changes a verdict.
- A new hardening claim needs a selftest check. The tables below assert each row
  was re-run at the commit that added it — re-run before claiming it.
- "What is NOT protected" is load-bearing; do not let it go stale.

## Threat model

Defended against: **opencode, or a tool it runs, being prompt-injected into doing
something you did not ask for** — writing a payload into a directory that later
shells execute, reading your SSH key, or talking to a service that acts with your
full privileges.

Not defended against: a determined human with your account. This is mitigation,
not a boundary in the seccomp/capabilities sense. Everything below is scoped to
what bubblewrap can enforce on an unprivileged Linux host, and `--share-net` is
deliberate.

Assumes a Linux host with unprivileged user namespaces and `bubblewrap` on
`PATH`. Where a check depends on a daemon that may be absent (systemd, D-Bus, a
desktop session) the selftest reports the socket as absent rather than failing,
so a minimal host is fine.

## What is protected

| Area | How |
| --- | --- |
| **Host control plane** | `$XDG_RUNTIME_DIR`, `/run/user/$(id -u)`, `/run/dbus` and `/run/systemd` are replaced with empty tmpfs mounts. This is what closed the `systemd-run --user` escape: with no bus, the sandbox cannot make the *host* act on its behalf. |
| **Host credentials and history** | `~/.local/share/opencode` and `~/.local/state/opencode` are tmpfs-masked wholesale, and `auth.json`, `mcp-auth.json`, `account.json` and `service.json` additionally get 0-byte read-only binds. The host's `~/.config/opencode/service.json` — the same host-wide server password, in a stale location — is masked the same way and stripped from the seeded config copy. The three auth files are copied once into this repo's own `data/opencode/` at mode `600`, and the v2 provider credential *rows* are copied out of the host's `opencode.db` into this repo's own database — only those rows; the host database itself, with all its session history, stays masked. The sandbox reads those copies. |
| **Key material** | `~/.ssh` is a tmpfs — no private key, `config` or `known_hosts` from the host is ever visible. Agent forwarding is opt-in and forwards the socket only. |
| **Other repos' data** | The state root is a tmpfs with only this repo's `data/`, `cache/`, `tools/` and the shared opencode `config/` and `state/` bound back in, so no sibling repo's directory — and therefore no sibling repo's credential copy or session database — is visible. opencode's config and state *are* shared by every sandbox, by design; see below. |
| **Kernel and namespaces** | `--unshare-all --share-net`, `--unshare-user --disable-userns`, `--cap-drop ALL`, `NoNewPrivs`, `--new-session`. Nested user namespaces fail with `ENOSPC`, so a compromised process cannot build a second sandbox. |
| **Code execution via PATH** | `~/.bun` and `~/.local/share/uv/tools` are read-only, so a downloaded script cannot be edited into a host-side code-execution path. The package managers are redirected at per-repo caches so installing still works. |
| **opencode's cache and config** | The host's `~/.cache/opencode` is read-only — opencode downloads and executes provider packages there — and so is `~/.config/opencode`, whose `cli.json` the TUI writes and into which plugins install. The cache is a per-repo seeded copy via `XDG_CACHE_HOME`; the config is one sandbox-wide seeded copy via `OPENCODE_CONFIG_DIR`, shared by every repo. |
| **The rest of the filesystem** | `--ro-bind / /`. The writable host paths are the working directory, this repo's `data/`, `cache/` and `tools/`, and the shared opencode `config/` and `state/`; the state root holding the shared copies is itself masked and they are bound at the sandbox's own state/config paths. A working directory that is `$HOME` or a parent of it (such as `/home`) is read-only unless `OPENCODE_SANDBOX_HOME_RW=1`. Subdirectories of home are writable as usual, and `/` is refused outright. `/tmp` is a fresh tmpfs. |
| **Host desktop surface** | `DISPLAY`, `WAYLAND_DISPLAY`, `DBUS_SESSION_BUS_ADDRESS`, `XAUTHORITY` and the `XDG_SESSION_*`/`XDG_SEAT*` pointers are unset, so nothing blocks for seconds on a socket that no longer exists. |

Hostname inside is `opencode-sandbox`, so a sandboxed process is obvious in
`ps`, `top` and screenshots.

## What is NOT protected

Read this section before trusting the thing.

- **The network is shared, not isolated.** `--share-net` gives the sandbox the
  host's interfaces, so it reaches `127.0.0.1` and the LAN. It can port-scan
  localhost, talk to other machines, and hit services that trust the source
  address. Deliberate: the agent needs to reach model APIs. Egress filtering
  belongs in front of the wrapper, not in it.
- **Everything else under `/` is readable.** `--ro-bind / /` hides nothing. Other
  secrets in `$HOME` — `~/.gnupg`, browser profiles, other `~/.local/share/*`
  apps, `~/.config/*/credentials` — are readable and can be exfiltrated over that
  network. Only the opencode and ssh paths were handled.
- **This repo's `auth.json` copy is readable and usable.** That is the point: the
  sandbox needs credentials. It is a real, mode-600, plaintext file on the host
  disk at `~/.local/share/opencode-sbx/<repo>-<hash>/data/opencode/auth.json`,
  one set per repo, so revoking means deleting the state directory. The v2
  provider credential rows sit in this repo's own `opencode.db` — the same keys,
  readable by the same process — so nothing is exposed that the file did not
  already expose. A compromised process can both use it and read it out. Other
  repos' copies are *not* readable, so a sandbox cannot lift one repo's account
  into another; but this is the host's plaintext account either way, and anything
  that can already read the network can ask the provider directly.
- **The host's `~/.config/opencode` is readable, just not writable — except
  `service.json`.** The directory is deliberately not masked: a dotfiles symlink
  in it (e.g. `opencode.json` pointing into a config repo) has to keep resolving
  for the seeded copy to be useful. A sandboxed agent can read it and the
  playbook it points at. The one exception is `service.json`, which can carry the
  host-wide server password; that file is a 0-byte mask, and the copy is stripped
  as well.
- **opencode's config and runtime state are shared across every repo, by one
  writable directory.** `~/.local/share/opencode-sbx/shared/state/opencode`
  (favourites, recents, prompt history, kv, pinned sessions, locks, PTY
  registry) and `shared/config/opencode` (providers, MCP servers, plugins,
  keybinds, theme) are bound read-write at the sandbox's
  `$XDG_STATE_HOME/opencode` and `$OPENCODE_CONFIG_DIR`. A sandboxed agent can
  read and change any of that for *all* repos: see prompts typed in another
  repo, delete favourites, edit the config, clear prompt history, pin or unpin
  sessions, or plant a plugin for the next sandbox. Deliberate: these describe
  the person and the tool, not the repository, and per-repo copies were the
  complexity that made favourites unmaintainable. It cannot use this to reach
  the host's copies or another repo's `data/`, `cache/` or `tools/`; source code
  outside the working directory is still read-only.
- **`OPENCODE_SANDBOX_HOME_RW=1` makes your home directory writable.** Off by
  default. The working directory is then all of `$HOME`, so the sandbox can write
  the files the host runs or reads later: `~/.bashrc` and `~/.zshrc`, which later
  shells source; the dotfiles that are symlinks into `~/profile`; the playbook
  behind `~/.config/opencode/opencode.json`, which the unsandboxed opencode reads,
  so an added MCP server or plugin would run on the host; this wrapper; every
  repo's `.git/hooks`. Files under home can also be overwritten or deleted,
  including `Documents`, `Downloads` and the `Nextcloud` folder, where deletions
  sync. `~/.cache` and `~/.config/opencode` are re-bound read-only, and the masks
  and the other repos stay hidden as before. Use it when you want to edit files in
  home; otherwise run from a subdirectory such as `~/scratch`.
- **`OPENCODE_SANDBOX_SSH=1` hands the sandbox a signing oracle.** Not a key —
  the crypto stays in the agent on the host — but anything inside can ask that
  agent to authenticate to any host you can reach, repeatedly, and a plain
  `ssh-agent` will not ask you first. A keyring agent that prompts per use is
  what keeps this small. See [SSH agent forwarding](#ssh-agent-forwarding).
- **`OPENCODE_SANDBOX_GH_TOKEN=1` hands the sandbox the gh CLI's token, whole.**
  Unlike the SSH case there is no agent left on the host — GitHub has no
  per-use prompt and the token carries every scope the login got (`repo`,
  `workflow`, `read:org`, `gist` on a default login). Anything inside can use
  it at will until the token is revoked, from the host, with
  `gh auth logout -h github.com -u <user>` (or `gh auth refresh`, which rotates
  the keyring entry). To scope what the sandbox gets, write a dedicated
  fine-grained PAT and run `GH_TOKEN=... ./bubblewrap_opencode ...`
  without the flag — an exported `GH_TOKEN` crosses into the sandbox whether
  the flag is set or not; the flag's only job is resolving the keyring-stored
  one, which nothing inside can reach. This is why the keyring cut exists and
  why the route through it is opt-in.
- **`/tmp` is RAM-backed and per-invocation.** Writable, but thrown away when the
  sandbox exits. Do not use it to carry state between runs.
- **The state directory is on the host disk.** Per-repo `data/`, `cache/` and
  `tools/` are keyed on the git toplevel, so every subdirectory of a repo shares
  one history; the shared opencode `config/` and `state/` are one copy for all
  repos. Two repos' data is isolated by a mount rather than by a convention, and
  that separation was measured failing — a sandbox in one repo read another
  repo's `auth.json` — before the state root was masked. The shared opencode
  state is not isolated; see the bullet above.
- **Concurrent sandboxes share opencode's state.** Two sandboxes running at the
  same time write the same `model.json`, `kv.json`, `locks/` and `pty/`. The
  model store's locks are keyed on the full path, which still differs per
  sandbox, so a concurrent toggle can be lost; and opencode's PTY service may
  refuse a second registration. If that bites, do not run two sandboxes with
  terminal sessions at the same time.

## Verification

`sandbox-selftest` runs *inside* the sandbox the wrapper just built. It is the
authority for every claim in the two tables above.

```sh
OPENCODE_SANDBOX_EXEC=1 ./bubblewrap_opencode ./sandbox-selftest [section]
```

`OPENCODE_SANDBOX_EXEC` is a switch, never a command: it makes the wrapper run
its own argument list in the sandbox instead of opencode. Sections, or `all`
(the default):

| Section | Asserts |
| --- | --- |
| `HOST IPC SOCKETS` | The systemd user manager, the system bus (and so polkit, flatpak, NetworkManager), KDE Wallet, Wayland, PulseAudio, PipeWire, the a11y bus, PKCS#11, gpg-agent, the journal and the xdg portal are all unconnectable — each tested with a bare `connect(2)`, because a bus daemon answers with cheerful errors that look like failures but mean the opposite. A final sweep fails the run on any socket nobody listed. |
| `ESCAPE MECHANISMS` | `systemd-run --user`, `nsenter -t 1`, `machinectl`, nested user namespaces, nested bubblewrap, `dmesg`, writing `/proc/sys`, `modprobe`, `mount`, `ptrace` and `process_vm_readv` are all denied. |
| `HOST FILES` | The host `auth.json`, `mcp-auth.json`, `account.json` and both `service.json` locations read back empty; the host `opencode.db` and the host's `~/.ssh` contents are absent; this repo's credential copy is present and non-empty, and this repo's own `opencode.db` holds at least one provider credential row. A 0-byte mask is openable but empty, so the test is "can I read bytes", not "does `open()` succeed". |
| `CROSS-REPO ISOLATION` | This repo's `data/` and the shared opencode state are writable — asserted first, so a sandbox that masked too much cannot pass by showing nothing — no sibling repo's directory is visible, and the shared state root is masked at its own path. |
| `WORKING DIRECTORY AND HOME` | When the working directory is `$HOME` or a parent of it, it is read-only, or writable only under `OPENCODE_SANDBOX_HOME_RW=1`. A subdirectory of home is writable as usual. `~/.cache` and `~/.config/opencode` are read-only in every mode. |
| `FUNCTIONALITY`, `OPENCODE CONFIG`, `PREFERENCES` | The toolchain runs, the working directory is writable (or read-only by design when it is `$HOME` or a parent of it), git history and DNS and egress work, `/tmp` is writable; the config dir is the shared sandbox copy, writable, not the host's inode, with no dangling symlinks and no `service.json`; the state dir is a bind of the shared state, `model.json` parses, and an actual `write(tmp)+rename()` succeeds. The GitHub row makes a real authenticated `gh api user` call — it skips on plain runs and asserts only under `OPENCODE_SANDBOX_GH_TOKEN=1`, never classifying the off state as a failure. |
| `TOOLCHAIN WRITES` | `npm`, `bun`, `uv` and `pip` installs land in per-repo caches, and the read-only toolchain dirs stay read-only. Slow — it downloads packages. |

`FUNCTIONALITY` also prints every writable path in the sandbox, classified as
`repo-local`, `shared`, `tmpfs` or `ro`. The classification comes from the
kernel's own `/proc/self/mountinfo`, not from comparing path prefixes, because
the state directory is *opened* inside this repo's state directory while really
being a bind of a directory every repo shares. A `WRITABLE` line naming a path
outside the per-repo state directory is expected for the shared state and
config; anything else is the finding to read, not a cosmetic note.

The selftest adapts to the host: paths come from `$HOME`, the read-only
toolchain check enumerates whatever is installed rather than naming a tool, and
checks whose subject is absent report absent or skipped. `SBX_EGRESS_URL` and
`SBX_DNS_HOST` pin the network probes. Egress has no hard-coded target — the
IANA example domains are unreachable on some networks — so a short candidate
list is tried and whichever answers is named; any HTTP status counts, including
401, because the assertion is that the connection was made.

## SSH agent forwarding

`OPENCODE_SANDBOX_SSH=1` forwards your **SSH agent socket** into the sandbox so
git-over-SSH authenticates. It is off by default, and off means absent: with the
variable unset, `SSH_AUTH_SOCK` still reaches the sandbox but points at nothing
inside, and `ssh-add -l` answers `Error connecting to agent`.

```sh
OPENCODE_SANDBOX_SSH=1 ./bubblewrap_opencode              # TUI, agent forwarded
OPENCODE_SANDBOX_SSH=1 ./bubblewrap_opencode run "push it"
```

### The agent has to already exist

The wrapper requires `$SSH_AUTH_SOCK` to be a live socket and never starts one.
Running an agent inside would mean putting a private key inside, which is the
one thing the `~/.ssh` tmpfs exists to prevent, and an agent started by the
sandbox would die with it. If the variable is unset, or names a path that is not
a socket, the wrapper says so and starts the sandbox anyway, without SSH:

```
bubblewrap_opencode: OPENCODE_SANDBOX_SSH=1 but SSH_AUTH_SOCK is not a live socket; continuing without SSH
```

Nothing then fails loudly. `git clone git@…` simply fails to authenticate, so if
a session mysteriously cannot reach a remote, check that line first.

### What you get, and what you do not

| | Inside the sandbox |
| --- | --- |
| **Agent socket** | Bound at the **same path** the host uses, so `SSH_AUTH_SOCK` needs no rewriting and `git`, `ssh` and `gh` work unchanged. Verified: `ssh-add -l` from inside lists the agent's keys. |
| **`known_hosts`** | A per-repo copy at `<state root>/<repo>-<hash>/ssh/known_hosts`, seeded from the host's `~/.ssh/known_hosts` on first use and kept on the host disk from then on, so hosts stay remembered across runs. Handed to git through `GIT_SSH_COMMAND="-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=…"`, which also means a host seen for the first time is accepted rather than prompting. |
| **Private keys** | Never. `~/.ssh` is a tmpfs and is empty inside; the signing happens in the agent, on the host. |
| **`~/.ssh/config`** | Never either — it is in the same tmpfs. That has two consequences below. |

Everything above was measured on a host by running the wrapper. A real
authenticated *push* against a private remote was not exercised, since that
needs a repository you control.

- **`git` gets the `known_hosts` options, a bare `ssh` does not.** They travel in
  `GIT_SSH_COMMAND`, which only git reads. Measured inside the sandbox:
  `git ls-remote git@github.com:…` reports `Host 'github.com' is known and matches
  the ED25519 host key`, while `ssh -T git@github.com` dies with `Host key
  verification failed` — the host's `known_hosts` is masked and, without the
  `-o` options, there is nothing left to check against. Pass them yourself when
  you need a plain `ssh`: `ssh -o UserKnownHostsFile="$SSH_KNOWN_HOSTS" …`.
- **Host aliases, `IdentityFile`, `ProxyJump` and non-default ports are gone**,
  because they are defined in the `config` file that is not there. A remote like
  `git@work-github:me/repo.git` is taken as the literal hostname `work-github`
  and fails to resolve. Use the real hostname, or put the setting on the command
  line.

The switch is all or nothing. There is no per-repo or per-command form of it
other than not setting the variable for that run.

### What the agent still gives away

The sandbox never sees a key, but a forwarded socket is a **signing oracle**: any
process inside can ask the agent to authenticate, to any host you can reach, as
often as it likes. What stands between that and a silent impersonation is the
agent's own policy, not this wrapper:

- A desktop keyring agent (KWallet, GNOME Keyring) prompts per use, so you see
  each signature and can refuse it. That prompt is the control that remains, and
  it is the reason to prefer such an agent here.
- A plain `ssh-agent` holding added keys signs without asking. The only remaining
  limits are the key's own constraints — `command=`, `from=`, `restrict` in the
  *server's* `authorized_keys` — and `--share-net` means the sandbox can also
  reach whatever trusts your address on the LAN.
- Revocation is a host-side act: unload the key from the agent, or drop it from
  `authorized_keys`. The `ssh/` directory holds only public host keys, which is
  why `OPENCODE_SANDBOX_RESET=1` does not touch it.

### Checking it, and what the selftest will report

Use the wrapper's exec hook to ask the agent itself:

```sh
OPENCODE_SANDBOX_SSH=1 OPENCODE_SANDBOX_EXEC=1 ./bubblewrap_opencode ssh-add -l
```

`FUNCTIONALITY` also runs `ssh -V` and prints `SSH_AUTH_SOCK=…` — but that line
reflects the *variable*, which is inherited either way, so it is not evidence
that anything was forwarded. `ssh-add -l` is the check.

Then expect `security` to stay green **unless your agent is gpg-agent's**. With
`SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/gnupg/S.gpg-agent.ssh`, the flag re-opens the
very socket the selftest asserts is closed:

```
[ OPEN]  gpg-agent (SSH keys)  →  /run/user/1000/gnupg/S.gpg-agent.ssh
```

That is the opt-in working as designed, not a regression — but an agent shared
with gpg-agent cannot also keep that row `[CLOSED]`.

For every other agent location the row stays `[CLOSED]`, and the closing sweep
("no unlisted socket is connectable") does not count the forwarded socket
either. That is a property of the sweep, not evidence that nothing was
forwarded: it enumerates with `find -type s`, and a bind-mounted socket is
reported by `find` as a **regular file**. Measured inside the sandbox on a
forwarded agent socket: `find -type s` returns nothing, `find -type f` returns
it, and `stat` and `connect(2)` both say socket. So a clean `HOST IPC SOCKETS`
section is not proof that SSH forwarding is off.

## Gotchas

- **Check which copy you are running.** An older `bubblewrap_opencode` installed
  on `PATH` (typically `~/.local/bin`) takes precedence over this directory and
  will quietly ignore every variable documented above.
- **The state root is masked inside the sandbox.** `ls ~/.local/share/opencode-sbx`
  from inside shows this repo's directory and the shared copies bound at the
  sandbox's own paths; the shared directory's own path is not visible. A tool
  that walks the state root to work out, say, how much disk the other repos use
  will conclude it is the only one. That is the intended answer, not a broken
  mount.
- **opencode's config and state are shared; a repo's data is not.** To reset the
  shared favourites/config/state, remove `shared/` from the state root. To reset
  one repo's data, caches and tools, use `OPENCODE_SANDBOX_RESET=1` from that
  repo.
- **The old per-repo copies are no longer used.** `prefs/model.json` is read once
  only to seed the shared state when it is missing; each repo's old
  `state/opencode/` and `config/opencode/` are hidden by the shared binds.
  Deleting them after the first new-style run reclaims the space; nothing reads
  them again except that one seed fallback.
- **The first run anywhere is slower**, because it seeds the shared config, and
  the first run of each repo seeds its cache. See the reflink note under
  [State](#state).

## Deliberate; do not "fix"

- `--share-net`. Egress filtering belongs in front of the wrapper, not in it.
- opencode's `config/` and `state/` are one sandbox-wide directory, not per
  repo, bound as a *directory* so opencode's `write(tmp)+rename()` works.
  Per-repo favourites were the bug this fixed; the single-file bind is what
  caused `EBUSY`.
- The host's `~/.config/opencode` readable (only not writable), so a dotfiles
  symlink keeps resolving — except `service.json`, which is masked and stripped
  from the shared copy because it can carry the host-wide server password.
- The per-repo `data/opencode/auth.json` is a real, readable, mode-600 credential
  copy on the host disk, and the v2 provider credential rows are seeded the same
  way into the per-repo `opencode.db` — rows only, the host database itself never
  crosses over. `OPENCODE_SANDBOX_RESET=1` is how you revoke both.
- The shared-state lock race is documented, not fixed.
- The state root is a masked tmpfs, so sibling repos (and the shared root at its
  own path) are invisible from inside — a tool that walks it will under-report.
  That is the intended answer.

## bwrap invariants (only when touching the mount list)

- Order matters: every `--tmpfs` mask and every `--ro-bind-data` mask comes
  **before** the per-repo `--bind`s. bwrap resolves a bind's *source* in the host
  namespace, so this works; the destinations are recreated inside the tmpfs.
- A mount point must exist on the host before bwrap starts — bwrap cannot create
  one underneath `--ro-bind / /`. That is why the `hide_dirs` loop does
  `mkdir -p` and why `mkdir -p "${SBX}/state/opencode" "${SBX}/config/opencode"`
  precedes the shared-state/config binds. Every new tmpfs target needs the same.
- The working-directory bind (`cwd_args`) comes right after `--ro-bind / /`, with
  `--tmpfs /tmp` just before it. A later mount hides an earlier one beneath it:
  bound last, a working directory that was `$HOME` (or a parent of it) hid every
  mask under it, and a working directory under `/tmp` is hidden by a `/tmp` tmpfs
  mounted after it. Never move it after a mask or after `/tmp`.
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
- `--standalone` (gated on `*v[2-9].*`): belongs *after* the subcommand path, and
  not every command accepts it. The table is hard-coded from the v2.1.2 help
  output and is a deny list, so an unknown command gets the flag; re-check it
  when opencode is upgraded. `auth` and `session` are the only commands whose
  second word is part of the path.
- Checks whose subject is absent must report `[ n/a ]` or a skip, never `FAIL`,
  so a minimal host still passes.

## State

Outside the repository on purpose (`git clean -fdx` would destroy session
history). Two shapes under one root:

```
<root>/shared/{config,state}/opencode    # one copy for every repo, never the host's
<root>/<repo>-<sha256[:12]>/{data,cache,tools,state,config}
```

- `shared/config/opencode` is seeded once from the host and shared by every
  sandbox; its `service.json` is stripped because it can carry the host-wide
  server password. `shared/state/opencode` holds model.json, prompt history, kv,
  pins, locks, latest/ and pty, with model.json seeded once from the old
  `prefs/model.json`/host/this repo's old file. Both are bound as real writable
  directories at the sandbox's `OPENCODE_CONFIG_DIR` and
  `$XDG_STATE_HOME/opencode`; model.json is an ordinary file, which is what makes
  temp+rename work.
- The per-repo directory keeps `data/opencode` (auth copies, opencode.db, logs),
  `cache/home` (opencode's cache), `cache/{bun,npm,uv,pip}`, `tools/` and
  `ssh/known_hosts`; `state/opencode` and `config/opencode` there are mount
  points for the shared binds.
- Seeds are copied to a temp name, moved into place, marker `.opencode-seeded`
  written last, and a failed seed warns rather than aborting. Plain files in the
  config copy are snapshots from seed time — only `OPENCODE_SANDBOX_RESET=1`
  re-seeds the config (it keeps the shared state). Symlinks stay live (`cp -a`),
  which is why this host's `~/.config/opencode/opencode.json` symlink into
  `~/profile/playbooks/opencode.json` keeps resolving.
- The seed names dangling symlinks on stderr: a copy that looks complete but
  points at nothing makes opencode start with no providers/MCP/keybinds and no
  explanation. Reflink is used where the filesystem supports it; without it the
  config copy is real (~57 MB of plugin `node_modules` on this host).
- Relocate opencode's config with `OPENCODE_CONFIG_DIR`, never `XDG_CONFIG_HOME`:
  moving the latter relocates `git` and `gh` configuration too. `XDG_CACHE_HOME`
  is safe to move wholesale precisely because opencode resolves its cache as
  `$XDG_CACHE_HOME/opencode` with no variable of its own. The cache stays per
  repo; the config and state do not.
- The package-manager exports (`BUN_INSTALL_CACHE_DIR`, `npm_config_cache`,
  `UV_CACHE_DIR`, `UV_TOOL_DIR`, `UV_TOOL_BIN_DIR`, `PIP_CACHE_DIR`) must stay
  pointed at the per-repo copies while `~/.bun` and `~/.local/share/uv/tools` are
  ro-bound.
