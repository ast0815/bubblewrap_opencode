# bubblewrap_opencode

A wrapper that runs [opencode](https://github.com/sst/opencode) inside a
bubblewrap sandbox, with the escape routes that let an agent in a sandbox act on
the host closed off.

Use it instead of `opencode`:

```sh
./bubblewrap_opencode                    # TUI
./bubblewrap_opencode run "fix the test"
./bubblewrap_opencode session list
./bubblewrap_opencode --help             # what the sandbox does, then opencode's help
```

The sandbox is built by the `bubblewrap_opencode` script; `sandbox-selftest` is
the instrument used to measure it. Both are in this directory.

## Threat model

The thing being defended against is **opencode itself, or a tool it runs, being
prompt-injected into doing something you did not ask for** — writing a payload
into a directory that later shells execute, reading your SSH key, or talking to a
service that runs with your full privileges.

The thing *not* being defended against is a determined human with your account.
This is mitigation, not a security boundary in the seccomp/capabilities sense:
`--share-net` is deliberate, and everything in this document is scoped to what
bubblewrap can actually enforce on an unprivileged Linux host.

Assumptions: a Linux host with unprivileged user namespaces enabled, and
`bubblewrap` on `PATH`. Where a check depends on a daemon being present
(systemd, D-Bus, a desktop session) the selftest reports the socket as absent
rather than failing, so a minimal host is fine.

## What is protected

| Area | How |
| --- | --- |
| **Host IPC control plane** | `$XDG_RUNTIME_DIR`, `/run/user/$(id -u)`, `/run/dbus` and `/run/systemd` are replaced with empty tmpfs mounts. This is what closed the `systemd-run --user` escape. |
| **Ambient credentials** | The host originals — `~/.local/share/opencode/{auth,mcp-auth,account}.json` and `~/.local/state/opencode/service.json` — are masked with 0-byte read-only binds. The first three are copied once into `~/.local/share/opencode-sbx/<repo>-<hash>/data/opencode/` with mode `600` (`rw-------`, same as the host file), and the sandbox reads those copies instead. |
| **Host session history** | `~/.local/share/opencode` and `~/.local/state/opencode` are tmpfs-masked wholesale. |
| **Other repos' state** | The state root `~/.local/share/opencode-sbx/` is a tmpfs, with the running repo's `data/`, `state/`, `cache/`, `tools/` and `config/` bound back into it. Every other repo's directory — including its credential copies — is gone, and so is the `prefs/` directory. Only this repo is left. |
| **Key material** | `~/.ssh` is a tmpfs. No private key, `config` or `known_hosts` from the host is ever visible. |
| **Kernel and namespaces** | `--unshare-all --share-net`, `--unshare-user --disable-userns`, `--cap-drop ALL`, `NoNewPrivs`. Nested user namespaces fail with `ENOSPC`, so a compromised process cannot build a second sandbox. |
| **Code-execution via PATH** | `~/.bun` and `~/.local/share/uv/tools` are read-only, so a downloaded script cannot be edited into a host-side code-execution path. |
| **The opencode download cache** | `~/.cache/opencode` is read-only. opencode downloads and executes provider packages there, so a writable bind would be a code-execution path into any host-wide opencode service sharing the directory. Each repo gets a seeded copy of its own instead (see below). |
| **The opencode config directory** | `~/.config/opencode` stays read-only, and each repo gets a seeded copy at `…/<repo>-<hash>/config/opencode` via `OPENCODE_CONFIG_DIR`. A sandboxed agent can change its own repo's behaviour and no other repo's. |
| **The rest of the filesystem** | `--ro-bind / /`; the only writable host paths are the current working directory, this repo's state directories, and one shared preferences *file* (see below). The state root itself is masked, so it is not one of them. |
| **Host desktop surface** | `DISPLAY`, `WAYLAND_DISPLAY`, `DBUS_SESSION_BUS_ADDRESS`, `XAUTHORITY` and the `XDG_SESSION_*`/`XDG_SEAT*` pointers are unset. |

Hostname inside is `opencode-sandbox`, so a sandboxed process is obvious in
`ps`, `top` and screenshots.

## What is NOT protected

Read this section before trusting the thing.

- **The network is shared, not isolated.** `--share-net` means the sandbox has
  the host's interfaces, so it can reach `127.0.0.1` and the LAN. It can scan
  localhost ports, talk to other machines on your network, and hit services that
  trust the source address. This was a deliberate choice: the agent needs to
  reach model APIs. If you want egress filtering, put it in front of the
  wrapper, not in it.
- **Everything else under `/` is readable.** `--ro-bind / /` hides nothing.
  Other secrets in `$HOME` — other `~/.local/share/*` apps, `~/.gnupg`, browser
  profiles, `~/.config/*/credentials` — are readable and can be exfiltrated
  through the network. Only the opencode and ssh paths were handled.
- **The per-repo `auth.json` copy is readable and usable.** That is the point:
  the sandbox needs credentials. It lives in plaintext at
  `~/.local/share/opencode-sbx/<repo>-<hash>/data/opencode/auth.json`, one set
  per repo, so revoking means deleting the state directory. A compromised
  process can both use it and read it out. Other repos' copies are *not* readable
  — the state root is masked, and this repo's directory is bound back into it —
  so a sandbox cannot lift one repo's account into another. It is the host's
  plaintext account either way, and a process that can already read the network
  can ask the provider directly.
- **`/tmp` is RAM-backed and per-invocation.** Writable, but thrown away when
  the sandbox exits. Do not use it to carry state between runs.
- **The per-repo state directory is on the host disk.** It is keyed on the git
  toplevel; every subdirectory of a repo shares one history, and two different
  repos are isolated from each other but not from you. That isolation is a mount,
  not a convention: the whole state root is replaced by an empty tmpfs and only
  the running repo's own directories are bound back in, so from inside a sandbox
  the state root holds this repo and nothing else. It matters because every
  per-repo directory holds a usable copy of your opencode credentials
  (`data/opencode/auth.json`) — before the root was masked, a sandbox in one repo
  could read another repo's account. That was measured, not suspected.
- **Your model preferences are shared across every repo, by one writable file.**
  `~/.local/share/opencode-sbx/prefs/model.json` is bound read-write at
  `$XDG_STATE_HOME/opencode/model.json`, so a sandboxed agent — or the unsandboxed
  opencode — can change which models you have favourited, for *all* repos. That is
  deliberate: preferences describe the person, not the repository, and per-repo
  favourites were the bug that prompted this. The *directory* holding it is not
  bound, and is masked along with the rest of the state root, so there is nothing
  to enumerate through it; the host's own `~/.local/state/opencode/model.json`
  stays masked at its own path.
- **`OPENCODE_SANDBOX_HOST_PREFS=1` makes the host's `model.json` writable too.**
  That is the only bind here that lets a process inside the sandbox modify host
  state. It buys two-way sync with your unsandboxed opencode. An agent can delete
  your favourites and recents, insert entries, or set variant strings, and those
  entries are what the host's model picker displays and what
  `model.cycle_favorite` walks — so it can steer that picker. It cannot execute
  code, read credentials, or make the host fetch anything: only ids already in the
  host's catalogue and resolvable by the host's own provider have any effect. Off
  by default.
- **The host's `~/.config/opencode` is readable, just not writable.** It is
  deliberately not masked: it is your own configuration, and a dotfiles symlink in
  it (e.g. `opencode.json` pointing into a config repo) has to keep resolving for
  the per-repo copy to be useful. A sandboxed agent can read it and the playbook
  it points at.

## Tested escape routes

`sandbox-selftest` runs *inside* the sandbox. It is the authority for every
claim in this table, and every row was re-run at the commit that added this
README — except the config and preferences rows, which were added later and are
covered by the caveat in "Not tested here" below.

```sh
OPENCODE_SANDBOX_EXEC=1 ./bubblewrap_opencode ./sandbox-selftest [section]
```

`OPENCODE_SANDBOX_EXEC` is just a switch; the command run inside the sandbox is
the wrapper's argument list. Sections: `security` (escape routes), `functional`
(usability), `toolchains` (package-manager writes, slow), or `all` (default).

The selftest adapts to the host: paths come from `$HOME`, the writable-bound
report is derived at runtime, and the read-only toolchain check enumerates
whatever is installed rather than naming a tool. Checks whose subject is absent
(a desktop session socket, a user toolchain) report as absent or skipped rather
than failing.

`SBX_EGRESS_URL` and `SBX_DNS_HOST` override the network probes. Egress has no
hard-coded target — the IANA example domains are unreachable on some networks —
so a short candidate list is tried and whichever answers is named in the
output. Any HTTP status counts, including 401: the assertion is that the
connection is made, not that it is authorised.

### Escape mechanisms — all denied

| Route | Verdict | Evidence |
| --- | --- | --- |
| `systemd-run --user` spawns on the host | CLOSED | `Failed to connect to user scope bus: No such file or directory` |
| `nsenter -t 1` into a host namespace | CLOSED | `reassociate to namespaces failed: Operation not permitted` |
| `machinectl shell` | CLOSED | `Failed to connect to system scope bus: Host is down` |
| Nested user namespace (`unshare -Ur`) | CLOSED | `unshare failed: No space left on device` (seccomp `ENOSPC`) |
| Nested bubblewrap | CLOSED | `nesting depth exceeded (ENOSPC)` |
| `dmesg` | CLOSED | `read kernel buffer failed: Operation not permitted` |
| Write `/proc/sys/kernel/core_pattern` | CLOSED | `Permission denied` |
| `modprobe tun` | CLOSED | `CAP_SYS_MODULE` dropped and `/lib/modules` not writable |
| `mount -t tmpfs` | CLOSED | mount syscall denied |
| `ptrace` another process | CLOSED | `Operation not permitted` |
| `process_vm_readv` another process | CLOSED | `bytes 0` — 0 of 16 bytes read |

### Host IPC sockets — none connectable

Every one is checked with a plain `connect(2)`, because a reachable bus daemon
answers with cheerful errors that look like failures but mean the opposite. The
test then sweeps the whole runtime dir, `/run/dbus` and `/run/systemd` for
sockets that were *not* on the list, so a channel nobody thought of also fails
the run.

| Socket | Verdict |
| --- | --- |
| `systemd` user manager (`systemd/private`, `bus`) | CLOSED |
| D-Bus system bus | CLOSED |
| KDE Wallet | CLOSED |
| Wayland compositor | CLOSED |
| PulseAudio | CLOSED |
| PipeWire | CLOSED |
| Accessibility bus (`at-spi`) | CLOSED |
| PKCS#11 / smartcards | CLOSED |
| gpg-agent | CLOSED |
| systemd journal (log forgery) | CLOSED |
| xdg document portal | CLOSED |
| Unlisted-socket sweep | CLOSED — no socket outside the list was connectable |

### Host files — no content leaks in

| Path | Verdict |
| --- | --- |
| `~/.local/state/opencode/service.json` (host server password) | empty mask |
| `~/.local/state/opencode/model.json` | hidden, dir masked — the shared copy is bound at the per-repo path instead |
| `~/.local/share/opencode/auth.json` | empty mask |
| `~/.local/share/opencode/mcp-auth.json` | empty mask |
| `~/.local/share/opencode/account.json` | empty mask |
| `~/.local/share/opencode/opencode.db` | hidden, dir masked |
| `~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, `~/.ssh/config` | hidden, dir masked |
| `~/.config/opencode/cli.json` | readable (your own config, not a secret) but not writable |
| per-repo `auth.json` copy | **present and non-empty** — required |
| per-repo `config/opencode` copy | **present**, distinct inode from the host's |

Note the two different tests. A 0-byte mask is *openable* but empty, so the
question is "can I read bytes", not "does `open()` succeed". A missing file
inside a tmpfs-masked directory is the other case; that is why
`opencode.db` reads as hidden rather than as "not on this host".

### Other repos' state — not reachable

The state root holds one directory per repo and each one holds a credential copy
at `data/opencode/auth.json`, so "can this sandbox see another repo's directory"
is the question that decides whether the per-repo split means anything.

| Check | Verdict |
| --- | --- |
| This repo's own `data/` and `state/` present and writable | **required** — asserted first, so a masked-out sandbox cannot pass by showing nothing |
| Another repo's state directory visible in the state root | none — the root is a tmpfs holding this repo only |
| Shared preferences directory visible | masked; only its `model.json` is bound in |

Before this check existed the answer was the opposite, and the run proved it: the
sandbox reported a sibling repo by name, and the sibling's `auth.json` parsed as
a live provider credential set. The root is now masked, which is why the check
also asserts the positive half. See "Not tested here" — this table's rows are
the one thing a fresh sandbox run still has to confirm.

### Functionality — nothing lost

| Check | Verdict |
| --- | --- |
| `opencode`, `node`, `bun`, `git`, `python3`, `ssh` | all run |
| Working directory writable, git history readable | OK |
| Filesystem and `HOME` readable, `getent passwd` works | OK |
| DNS resolution, HTTPS egress | OK — the check names whichever endpoint answered; set `SBX_EGRESS_URL` to test one specific provider |
| `/tmp` writable | OK |
| `OPENCODE_CONFIG_DIR` writable, `cli.json` is this repo's copy | OK — the settings dialog needs both |
| No dangling symlinks in the config copy | OK — a broken one costs you providers and MCP servers silently |
| `model.json` writable and shared with every other repo | OK |
| `model.json` parses as `{recent, favorite, variant}` | OK |
| The shared preferences *directory* is not visible | OK — only the file is bound |
| `npm install` + `require` | OK |
| `bun add` + `import` | OK |
| `uvx` a package, `uv tool install` + run | OK |
| `pip install` in a venv | OK |
| A tool in a read-only toolchain dir runs but is not writable | OK — the selftest picks whichever tools it finds on `PATH`, and skips the check if it finds none |

The writable-bound report is part of the selftest output. Expected shape —
every line is derived from `$HOME` at runtime, so paths are shown relative to it:

```
ro        ~/.bun
ro        ~/.local/share/uv/tools
ro        ~/.cache
ro        ~/.cache/opencode
ro        ~/.config/opencode
ro        ~/.config/opencode/cli.json
tmpfs     ~/.local/state/opencode   (writable, empty, ephemeral)
tmpfs     ~/.local/share/opencode   (writable, empty, ephemeral)
tmpfs     ~/.ssh                    (writable, empty, ephemeral)
repo-local <state dir>/cache/home   (this repo's own state dir)
repo-local <state dir>/config        (this repo's own config copy)
shared     <state dir>/state/opencode/model.json   (bind of <state root>/prefs/model.json)
```

A `WRITABLE` line naming a path outside the per-repo state directory is the
finding to read, not a cosmetic note: it marks a directory where sandbox writes
land on a real host filesystem that something else may also use. A `tmpfs` line
is writable but empty and discarded at exit.

Every writable path is classified by asking the kernel which host file is really
behind it, via `/proc/self/mountinfo` — not by comparing path prefixes. That
matters for `model.json`, which is *opened* at a path inside this repo's own
state directory but is really a bind of a file shared by every repo. A path
comparison would call it `repo-local` and miss precisely the thing worth
reporting, so the report names the shared file instead.

Read-only package caches are not enough on their own: a `ro` bind looks fine
until something tries to install into it, so each package manager is redirected
at a per-repo cache directory via `BUN_INSTALL_CACHE_DIR`, `npm_config_cache`,
`UV_CACHE_DIR`, `UV_TOOL_DIR`, `UV_TOOL_BIN_DIR` and `PIP_CACHE_DIR`.

`repo-local` and `shared` are the two expected writable results. `repo-local`
means writes land in this repo's own directory, not in anything shared with the
host or with another repo. `shared` is the single preferences file, and the
report prints the host path behind it so the sharing is visible rather than
implied. A red `WRITABLE` line naming a path outside either is the finding to
watch for. The cache paths are listed separately on purpose — `XDG_CACHE_HOME` is
the per-repo copy and must come back writable, while the host's
`~/.cache/opencode` must come back read-only.

The config paths are listed for the same reason: `OPENCODE_CONFIG_DIR` is the
per-repo copy and must come back writable, while the host's
`~/.config/opencode` and its `cli.json` must come back read-only.

### Confirmed to work end to end

- A real `opencode run` completes and prints `PATH OK` / `SANDBOX OK`.
- State persists across wrapper invocations in the same folder: a marker file
  written in run 1 is present in run 2, and the per-repo `opencode.db` grows from
  empty. Sessions are listed from the per-repo database.
- `session list`, `auth list`, `debug paths`, `models`, `stats` and `serve` all
  work, including `--standalone` being placed and detected per leaf subcommand.
- A model favourited in one repo is present in another, and a TUI setting changed
  in one repo is not. Confirmed inside a real sandbox for the single-repo half:
  the preferences file was verified to be a bind of
  `<state root>/prefs/model.json` rather than this repo's own copy, with the
  directory masked and nothing else in it. Still to be confirmed on a normal
  login: the two-repo round trip, and the state-root mask that sits in front of
  it — see "Not tested here".

### SSH agent forwarding — verified

With `OPENCODE_SANDBOX_SSH=1` and a live agent exported, the checks are:

| Property | Result |
| --- | --- |
| `SSH_AUTH_SOCK` inside the sandbox | same path as the host, and a live socket |
| `ssh-add -l` | lists the identity the host agent offers |
| `~/.ssh` contents | empty — no private key, no `config` |
| `known_hosts` | per-repo copy, bound after the tmpfs mask |

The wrapper forwards the agent socket only. It never creates an agent, so it
depends on `$SSH_AUTH_SOCK` already being a live socket. If it is not, the
wrapper warns and continues without SSH, and git-over-SSH fails to
authenticate. Agents differ by desktop, so start or export one first:

```sh
eval "$(ssh-agent -s)"                                          # or
export SSH_AUTH_SOCK="$(gpgconf --list-dirs agent-ssh-socket)"  # gpg-agent
```

Not verified: authentication against a real private remote. Everything up to
the `connect(2)` is confirmed; the last hop needs a repository you control.

### Not tested here

**The state directory at its default location.** The selftest runs recorded
here were made from a session with a read-only `$HOME`, so they exercised the
fallback `~/.cache/opencode-sbx/...` rather than the default
`~/.local/share/opencode-sbx/<repo>-<hash>/`. Run the selftest from an ordinary
login to cover the default.

**The state-root mask.** The per-repo config and the shared preferences were
verified inside a real sandbox, but a sandbox started *before* this change — so
its mount table predates the mask. The `CROSS-REPO ISOLATION` section therefore
reports the leak it was written to catch, which is the correct verdict for that
mount table and confirms the check works. What is not yet confirmed is the
post-mask behaviour: that the state root really is a tmpfs, that this repo's five
directories come back through it, and that the preferences file still lands. All
three are the ordering `--tmpfs` then `--bind`, which the SSH socket bind has
already used successfully in this wrapper. One run from an ordinary login covers
it:

```sh
OPENCODE_SANDBOX_EXEC=1 ./bubblewrap_opencode ./sandbox-selftest security
OPENCODE_SANDBOX_HOST_PREFS=1 OPENCODE_SANDBOX_EXEC=1 \
    ./bubblewrap_opencode ./sandbox-selftest security   # must report the flip
```

## Environment variables

`./bubblewrap_opencode --help` prints a summary of the sandbox followed by this
list, one line per variable, before opencode's own help.

| Variable | Effect |
| --- | --- |
| `OPENCODE_SANDBOX_SSH=1` | Forward the SSH **agent socket only** (plus a per-repo `known_hosts` copy, public keys). Requires `$SSH_AUTH_SOCK` to already be a live socket — the wrapper never starts an agent, and warns and continues if it is not set. Key material is never exposed either way. |
| `OPENCODE_SANDBOX_EXEC` | Any non-empty value makes the wrapper run its **own arguments** inside exactly the sandbox opencode would get, instead of running opencode. The value is only a switch, never the command — so `OPENCODE_SANDBOX_EXEC=1 ./bubblewrap_opencode hostname` prints `opencode-sandbox`, and `./bubblewrap_opencode hostname` without it runs opencode and errors. Unset before exec so it cannot leak inward. |
| `OPENCODE_SANDBOX_HOME=<dir>` | Override the state root. Must be writable and **not under `/tmp`**: `/tmp` is a tmpfs inside the sandbox, so a state directory there would be masked and invisible. The directory itself is replaced by an empty tmpfs inside the sandbox, with this repo's subdirectories bound back in, so pointing it too high costs visibility rather than breaking the run. |
| `OPENCODE_SANDBOX_RESET=1` | Delete this repo's `data/`, `state/`, `cache/` and `config/` before starting. This is how you revoke the copied credentials, and it is also how a config change on the host reaches a repo that was seeded earlier. The shared preferences survive it. |
| `OPENCODE_SANDBOX_SYNC_PREFS=1` | Re-read `~/.local/state/opencode/model.json` from the host and overwrite the shared preferences file with it, before the sandbox starts. For after a session with the *unsandboxed* opencode. One way — a favourite added inside a sandbox still does not travel back to the host — and it only reads the host file, so it opens no new channel. |
| `OPENCODE_SANDBOX_HOST_PREFS=1` | Bind the host's own `~/.local/state/opencode/model.json` read-write instead of the shared copy, so the sandboxed and unsandboxed opencode edit one file and stay in sync in both directions. The only bind in this wrapper that lets a process inside the sandbox modify host state; see "What is NOT protected" for exactly what that permits. |

## State layout

```
~/.local/share/opencode-sbx/       # masked: an empty tmpfs inside the sandbox,
│                                  # with only the running repo's directory bound
│                                  # back in, so no sibling repo is reachable
├── prefs/
│   └── model.json     # the ONE shared file: favourites, recents, variants. Bound
│                      # read-write into every sandbox; the directory is not bound
├── <repo>-<sha256[:12]>/       # key = git toplevel basename + path hash
    ├── data/opencode/ # XDG_DATA_HOME: auth.json, mcp-auth.json, account.json (copies of
    │                  # the host files, mode 600), plus opencode.db, storage, logs
    ├── state/         # XDG_STATE_HOME: locks, prompt history, session.json, latest/tui
    │   └── opencode/model.json   # mount point for the shared prefs bind, not a second copy
    ├── config/opencode/  # OPENCODE_CONFIG_DIR: a seeded copy of the host's ~/.config/opencode
    │   └── .opencode-seeded  # marker, written last, so an interrupted seed re-runs
    ├── cache/home/    # XDG_CACHE_HOME: a seeded copy of the host's ~/.cache/opencode
    │   └── .opencode-seeded   # marker, written last, so an interrupted seed re-runs
    ├── cache/{bun,npm,uv,pip}
    ├── tools/bin      # uv tool executables
    ├── ssh/known_hosts    # only when OPENCODE_SANDBOX_SSH=1
    └── meta           # the git toplevel this key came from. Not bound into the
                       # sandbox: it is the wrapper's own bookkeeping
```

### Three kinds of state

The wrapper sorts everything opencode reads or writes into three categories, and
each one gets exactly one home. The rule per row is the whole design:

| Category | Files | Home | Why |
| --- | --- | --- | --- |
| **The agent's own configuration** | `config/opencode/` — providers, MCP, plugins, agents, permissions, keybinds, theme | per repo, seeded from the host | an agent can change its own repo's behaviour and no other repo's |
| **The repo's data** | `data/`, `state/` — db, snapshots, logs, prompt history, pins, tabs, credentials copies | per repo | session data must not leak between repositories |
| **You** | `prefs/model.json` — favourites, recents, variants | one shared file | these describe the person, not the repository; isolating them per repo was the bug |

A single writable path per category is what makes the boundary easy to state, and
`OPENCODE_SANDBOX_RESET=1` has a correspondingly simple meaning: drop the first
two rows and re-seed them from the host, leave the third alone. It is not a
credential and not repo state, so revoking a compromised sandbox should not throw
it away.

### The per-repo config

`OPENCODE_CONFIG_DIR` points at `config/opencode` rather than leaving opencode on
the host's `~/.config/opencode`, which stays read-only. Two things need that: the
TUI settings store `cli.json` (theme, keybinds, scroll, diffs), which the settings
dialog cannot write at all while the host copy is read-only, and plugin
installation, which opencode package-manages inside this very directory. Same
reasoning as the cache, applied to the config.

The variable is `OPENCODE_CONFIG_DIR` and **not** `XDG_CONFIG_HOME`. opencode
relocates its config directory through that one variable on both sides — the TUI
client resolves the Global service from it, which is where `cli.json` is read and
written, and the server takes it explicitly as `config.directory` — while
project-level `opencode.json` in the working directory stays a separate,
unaffected layer. Moving `XDG_CONFIG_HOME` would relocate every *other* tool's
configuration too: `git` reads `$XDG_CONFIG_HOME/git/config`, `gh` reads its own
subdirectory, and both would silently stop seeing their global settings inside the
sandbox.

One nuance worth knowing before you trust it: **plain files in the copy are a
snapshot from seed time**, so a config change on the host reaches an existing
repo only via `OPENCODE_SANDBOX_RESET=1`. Symlinks are the exception and stay
live — `cp -a` preserves them, so an `opencode.json` symlinked at a dotfiles
repository keeps resolving to the same host file (read-only here), and edits to it
apply to every repo immediately.

That is also why the seed checks for symlinks that do not resolve. A dangling
`opencode.json` is the worst failure mode here: the copy looks complete, opencode
starts, and it has no providers and no MCP servers, with nothing in the log to say
why. The wrapper names any such symlink on stderr at seed time.

The seed copies the whole directory, which on this host is ~57 MB of
plugin-SDK `node_modules`. Reflink makes that close to free on btrfs and XFS;
without reflink it is a real copy per repo, and the wrapper says which case you
are in.

### The shared preferences file

`model.json` is the one file bound from outside a repo's own directory. The
*file* is bound; its *directory* is not, and is masked along with the rest of the
state root, so a sandbox cannot enumerate or read any other repo's state through
it. It is seeded once — from the host's `model.json` if the unsandboxed opencode
has one, otherwise promoted from this repo's existing file so favourites built up
by an older version of the wrapper survive — and the host file is only ever read.

Two honest caveats:

- **The host's own `model.json` stays masked at its own path**, in both the
  default and `OPENCODE_SANDBOX_HOST_PREFS=1` modes. The bind only replaces the
  file at the per-repo path, so the host's state directory is still an empty tmpfs
  from inside.
- **Writes from two repos do not exclude each other.** opencode locks such a
  store as `dirname(file)/locks/<hash of the full path>`, and inside a sandbox
  that path is this repo's, so the two repos take different locks. Concurrent
  toggles can lose one. The file is a few hundred bytes and is rewritten whole, so
  the outcome is one dropped favourite, never a corrupt file.

### The seeded cache

`XDG_CACHE_HOME` points at `cache/home` rather than the host's `~/.cache`, so
opencode's download-and-execute cache is per repo and the host's copy is
read-only. It moves wholesale rather than just opencode's subdirectory because
opencode resolves its cache as `$XDG_CACHE_HOME/opencode` and has no separate
variable for it; anything else following `XDG_CACHE_HOME` is redirected too.

The seed is a one-time copy of the host's `~/.cache/opencode`, taken with
`cp --reflink=always` where the filesystem supports it. On btrfs and XFS the
copy shares extents until something writes to one, so it costs essentially
nothing: measured here, seeding a 505 MB / 35,356-file cache plus a real
opencode run together cost **0.9 MiB** and about 2.5 s. Where reflink is not
supported the copy is real, and the wrapper says so on stderr rather than
letting you discover it as a surprise 505 MB bill. `OPENCODE_SANDBOX_RESET=1`
discards it along with the rest.

The seed logic is a single function shared with the config copy, so the
guarantees are the same for both: the copy goes to a temporary name and is moved
into place, and the marker file is written last, so an interrupted seed cannot
leave a half-populated directory that the marker then vouches for. Failing to copy
is never fatal — the wrapper warns and carries on, so a bad source degrades to
"opencode starts without it" rather than "the wrapper refuses to start".

It lives outside the repository on purpose: `git clean -fdx` or deleting a
worktree would otherwise destroy irreplaceable session history. The cost is
disk, and a one-off re-download per repo.

## Gotchas

- **Check which copy you are running.** If you installed a copy on `PATH`
  (typically `~/.local/bin`) at some point, an old version there takes
  precedence over this directory and will quietly ignore every variable
  documented above. Run `./bubblewrap_opencode`, or reinstall this version over
  the one on `PATH`.
- **`OPENCODE_SANDBOX_EXEC` is a switch, not a command** — see the table above.
- **The credential copies are real files on the host disk**, under
  `~/.local/share/opencode-sbx/`, one set per repo. `OPENCODE_SANDBOX_RESET=1`
  deletes them.
- **The state root is masked inside the sandbox.** `ls ~/.local/share/opencode-sbx`
  from inside shows this repo's directory and nothing else. A tool that walks the
  state root to find, say, how much disk other repos use will conclude it is the
  only one. That is the intended answer, not a broken mount.
- **`--ro-bind / /` hides nothing.** Read-only is not invisible; see the risk
  list above.
- **The first run of a repo is slower** — it seeds the cache copy and the config
  copy. Reflink makes both cheap on btrfs/XFS and slow on a filesystem without
  it; the wrapper warns when that is the case.
- **Config edits on the host do not reach a repo that already exists.** The
  per-repo config copy is a snapshot, and the only thing that re-seeds it is
  `OPENCODE_SANDBOX_RESET=1`, which also throws away that repo's sessions and
  credential copies. Symlinked config files are the exception and stay live.
- **Favourites are shared; everything else about a repo is not.** If you want
  per-repo favourites back, unset nothing — just edit the per-repo
  `state/opencode/model.json` directly, or run without the shared bind by
  removing `prefs/model.json`.
