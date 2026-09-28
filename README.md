# bubblewrap_opencode

Runs [opencode](https://github.com/sst/opencode) inside a bubblewrap sandbox
with the escape routes that would let a prompt-injected agent act on the host
closed off. Use it instead of `opencode`:

```sh
./bubblewrap_opencode                    # TUI
./bubblewrap_opencode run "fix the test"
./bubblewrap_opencode session list
./bubblewrap_opencode --help             # sandbox summary, then opencode's help
```

`bubblewrap_opencode` builds the sandbox; `sandbox-selftest` measures it from
the inside. Both are in this directory.

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
| **Host credentials and history** | `~/.local/share/opencode` and `~/.local/state/opencode` are tmpfs-masked wholesale, and `auth.json`, `mcp-auth.json`, `account.json` and `service.json` additionally get 0-byte read-only binds. The three auth files are copied once into this repo's own `data/opencode/` at mode `600`; the sandbox reads those copies. |
| **Key material** | `~/.ssh` is a tmpfs — no private key, `config` or `known_hosts` from the host is ever visible. Agent forwarding is opt-in and forwards the socket only. |
| **Other repos' state** | The state root is a tmpfs with only this repo's `data/`, `state/`, `cache/`, `tools/` and `config/` bound back in, so no sibling repo's directory — and therefore no sibling repo's credential copy — is visible. |
| **Kernel and namespaces** | `--unshare-all --share-net`, `--unshare-user --disable-userns`, `--cap-drop ALL`, `NoNewPrivs`, `--new-session`. Nested user namespaces fail with `ENOSPC`, so a compromised process cannot build a second sandbox. |
| **Code execution via PATH** | `~/.bun` and `~/.local/share/uv/tools` are read-only, so a downloaded script cannot be edited into a host-side code-execution path. The package managers are redirected at per-repo caches so installing still works. |
| **opencode's cache and config** | The host's `~/.cache/opencode` is read-only — opencode downloads and executes provider packages there — and so is `~/.config/opencode`, whose `cli.json` the TUI writes and into which plugins install. Each repo gets a seeded copy of each, via `XDG_CACHE_HOME` and `OPENCODE_CONFIG_DIR`. |
| **The rest of the filesystem** | `--ro-bind / /`. The only writable host paths are the working directory, this repo's state, and one shared preferences *file*; the state root holding the latter is itself masked. `/tmp` is a fresh tmpfs. |
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
  one set per repo, so revoking means deleting the state directory. A compromised
  process can both use it and read it out. Other repos' copies are *not*
  readable, so a sandbox cannot lift one repo's account into another; but this is
  the host's plaintext account either way, and anything that can already read the
  network can ask the provider directly.
- **The host's `~/.config/opencode` is readable, just not writable.** It is
  deliberately not masked: a dotfiles symlink in it (e.g. `opencode.json` pointing
  into a config repo) has to keep resolving for the per-repo copy to be useful. A
  sandboxed agent can read it and the playbook it points at.
- **Model preferences are shared across every repo, by one writable file.**
  `~/.local/share/opencode-sbx/prefs/model.json` is bound read-write at
  `$XDG_STATE_HOME/opencode/model.json`, so a sandboxed agent can change your
  favourites for *all* repos. Deliberate: preferences describe the person, not
  the repository, and per-repo favourites were the bug that prompted this. The
  *directory* holding the file is not bound and is masked along with the rest of
  the state root, so there is nothing to enumerate through it.
- **`OPENCODE_SANDBOX_HOST_PREFS=1` makes the host's `model.json` writable too.**
  That is the only bind in this wrapper that lets a process inside modify host
  state, and it buys two-way sync with your unsandboxed opencode. An agent can
  delete your favourites and recents, insert entries, or set variant strings, and
  those entries are what the host's model picker displays and what
  `model.cycle_favorite` walks — it can steer that picker. It cannot execute
  code, read credentials, or make the host fetch anything: only ids already in
  the host's catalogue have any effect. Off by default.
- **`/tmp` is RAM-backed and per-invocation.** Writable, but thrown away when the
  sandbox exits. Do not use it to carry state between runs.
- **The per-repo state directory is on the host disk.** It is keyed on the git
  toplevel, so every subdirectory of a repo shares one history. Two repos are
  isolated from each other by a mount rather than by a convention, and that
  separation was measured failing — a sandbox in one repo read another repo's
  `auth.json` — before the state root was masked.

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
| `HOST FILES` | The host `auth.json`, `mcp-auth.json`, `account.json` and `service.json` read back empty; the host `opencode.db` and the host's `~/.ssh` contents are absent; this repo's credential copy is present and non-empty. A 0-byte mask is openable but empty, so the test is "can I read bytes", not "does `open()` succeed". |
| `CROSS-REPO ISOLATION` | This repo's own state is writable — asserted first, so a sandbox that masked too much cannot pass by showing nothing — no sibling repo is visible, and the shared preferences directory is masked. |
| `FUNCTIONALITY`, `OPENCODE CONFIG`, `PREFERENCES` | The toolchain runs, the working directory is writable, git history and DNS and egress work, `/tmp` is writable, the config copy is this repo's own inode and writable with no dangling symlinks, and the preferences file parses and comes from outside this repo's directory. |
| `TOOLCHAIN WRITES` | `npm`, `bun`, `uv` and `pip` installs land in per-repo caches, and the read-only toolchain dirs stay read-only. Slow — it downloads packages. |

`FUNCTIONALITY` also prints every writable path in the sandbox, classified as
`repo-local`, `shared`, `tmpfs` or `ro`. The classification comes from the
kernel's own `/proc/self/mountinfo`, not from comparing path prefixes, because
the preferences file is *opened* inside this repo's state directory while really
being a bind of a file every repo shares. A `WRITABLE` line naming a path
outside the per-repo state directory is the finding to read, not a cosmetic note.

The selftest adapts to the host: paths come from `$HOME`, the read-only
toolchain check enumerates whatever is installed rather than naming a tool, and
checks whose subject is absent report absent or skipped. `SBX_EGRESS_URL` and
`SBX_DNS_HOST` pin the network probes. Egress has no hard-coded target — the
IANA example domains are unreachable on some networks — so a short candidate
list is tried and whichever answers is named; any HTTP status counts, including
401, because the assertion is that the connection was made.

Every claim above was re-measured at the commit that introduced it, except the
per-repo config and the shared preferences, which came later.

### Not tested here

**The state directory at its default location.** The runs recorded in this
repository were made from a session with a read-only `$HOME`, so they exercised
the fallback `~/.cache/opencode-sbx/…` rather than the default
`~/.local/share/opencode-sbx/<repo>-<hash>/`. Run the selftest from an ordinary
login to cover the default.

**The state-root mask.** The per-repo config and the shared preferences were
verified inside a real sandbox, but one started *before* the mask existed, so
its mount table predates it. `CROSS-REPO ISOLATION` therefore reports the leak
the check was written to catch, which is the correct verdict for that mount
table and confirms the check works. What is still unconfirmed is the post-mask
behaviour: that the state root really is a tmpfs, that this repo's five
directories come back through it, and that the preferences file still lands.
All three are the ordering `--tmpfs` then `--bind`, which the SSH socket bind
already uses successfully in this wrapper. One run covers it:

```sh
OPENCODE_SANDBOX_EXEC=1 ./bubblewrap_opencode ./sandbox-selftest security
OPENCODE_SANDBOX_HOST_PREFS=1 OPENCODE_SANDBOX_EXEC=1 \
    ./bubblewrap_opencode ./sandbox-selftest security   # must report the flip
```

**Two small gaps** remain, of different kinds. That a favourite added in one
repo is visible in another (and a TUI setting is not) has been verified only for
the single-repo half — the file was confirmed to be a bind of
`<state root>/prefs/model.json` with its directory masked — so it needs the same
run from an ordinary login. SSH agent forwarding is verified up to `connect(2)`
only; authenticating against a real private remote needs a repository you
control.

## Environment variables

All optional, all read before the sandbox starts. `./bubblewrap_opencode --help`
prints this list ahead of opencode's own help.

| Variable | Effect |
| --- | --- |
| `OPENCODE_SANDBOX_SSH=1` | Forward the SSH **agent socket only**, plus a per-repo `known_hosts` copy of public host keys. Requires `$SSH_AUTH_SOCK` to already be a live socket — the wrapper never starts an agent, and warns and continues without SSH if it is not set, in which case git-over-SSH will not authenticate. Key material is never exposed either way. |
| `OPENCODE_SANDBOX_EXEC` | Any non-empty value runs the wrapper's **own arguments** in exactly the sandbox opencode would get, instead of running opencode. The value is only a switch, never the command. It is unset before exec so it cannot leak inward. |
| `OPENCODE_SANDBOX_HOME=<dir>` | Override the state root. Must be writable and **not under `/tmp`**: `/tmp` is a tmpfs inside the sandbox, so state stored there would be masked and invisible. The directory itself is replaced by an empty tmpfs with this repo's subdirectories bound back in, so pointing it too high costs visibility rather than breaking the run. |
| `OPENCODE_SANDBOX_RESET=1` | Delete this repo's `data/`, `state/`, `cache/` and `config/` before starting, so the next run re-seeds them from the host. This is how you revoke the copied credentials, and how a host config change reaches a repo that was seeded earlier. The shared preferences survive it. |
| `OPENCODE_SANDBOX_SYNC_PREFS=1` | Re-read `~/.local/state/opencode/model.json` from the host and overwrite the shared preferences file with it, before the sandbox starts — for after a session with the *unsandboxed* opencode. One way only, and it only reads the host file, so it opens no new channel. |
| `OPENCODE_SANDBOX_HOST_PREFS=1` | Bind the host's own `~/.local/state/opencode/model.json` read-write instead of the shared copy, so the sandboxed and unsandboxed opencode edit one file and stay in sync both ways. The only bind that lets a process inside the sandbox modify host state; see "What is NOT protected" for exactly what that permits. |

## State

```
~/.local/share/opencode-sbx/       # masked: an empty tmpfs inside the sandbox,
│                                  # with only the running repo's directory bound
│                                  # back in, so no sibling repo is reachable
├── prefs/
│   └── model.json     # the ONE shared file: favourites, recents, variants. The
│                      # directory is not bound, so nothing else can be put there
├── <repo>-<sha256[:12]>/       # key = git toplevel basename + path hash
│   ├── data/opencode/ # XDG_DATA_HOME: auth/mcp-auth/account.json (copies of
│   │                  # the host files, mode 600), plus opencode.db, logs, storage
│   ├── state/         # XDG_STATE_HOME: locks, prompt history, session.json
│   │   └── opencode/model.json   # mount point for the shared prefs bind
│   ├── config/opencode/  # OPENCODE_CONFIG_DIR: seeded copy of the host's ~/.config/opencode
│   ├── cache/home/    # XDG_CACHE_HOME: seeded copy of the host's ~/.cache/opencode
│   ├── cache/{bun,npm,uv,pip}
│   ├── tools/bin      # uv tool executables
│   ├── ssh/known_hosts    # only with OPENCODE_SANDBOX_SSH=1
│   └── meta           # the git toplevel this key came from. Not bound into the
│                      # sandbox: it is the wrapper's own bookkeeping
```

A `.opencode-seeded` marker beside each copy — in `config/` and in `cache/home/` —
is the only thing that says a seed finished.

It lives outside the repository on purpose: `git clean -fdx` or deleting a
worktree would otherwise destroy irreplaceable session history. The cost is
disk, and a one-off re-download per repo.

Three kinds of state, one home each. The rule per row is the whole design:

| Category | Files | Home | Why |
| --- | --- | --- | --- |
| **The agent's own configuration** | `config/opencode/` — providers, MCP, plugins, agents, permissions, keybinds, theme | per repo, seeded from the host | an agent can change its own repo's behaviour and no other repo's |
| **The repo's data** | `data/`, `state/` — db, snapshots, logs, prompt history, pins, credential copies | per repo | session data must not leak between repositories |
| **You** | `prefs/model.json` — favourites, recents, variants | one shared file | these describe the person, not the repository; isolating them per repo was the bug |

A single writable path per category is what makes the boundary easy to state, and
`OPENCODE_SANDBOX_RESET=1` then has a correspondingly simple meaning: drop the
first two rows and re-seed them, leave the third alone. It is not a credential
and not repo state, so revoking a compromised sandbox should not throw it away.

Four things about the two seeded copies, all of which bite in practice:

- **Plain files in a copy are a snapshot from seed time.** A config change on the
  host reaches an existing repo only via `OPENCODE_SANDBOX_RESET=1`, which also
  throws away that repo's sessions and credential copies. Symlinks are the
  exception and stay live — `cp -a` preserves them, so an `opencode.json`
  symlinked into a dotfiles repository keeps resolving (read-only here) and
  edits to it apply to every repo immediately.
- **That is why the seed names symlinks that do not resolve.** A dangling
  `opencode.json` is the worst failure mode here: the copy looks complete,
  opencode starts, and it has no providers, no MCP servers and no keybinds, with
  nothing in the log to say why.
- **The seed is atomic and never fatal.** The copy goes to a temporary name, is
  moved into place, and the marker is written last, so an interrupted seed cannot
  leave a half-populated directory that the marker vouches for. Failing to copy
  warns and carries on, so a bad source degrades to "opencode starts without it".
- **Reflink makes the big copies nearly free where the filesystem supports it.**
  `cp --reflink=always` on btrfs and XFS shares extents until something writes to
  one; measured here, seeding a 505 MB / 35,356-file cache plus a real opencode
  run together cost 0.9 MiB and about 2.5 s. Without reflink the copy is real —
  the config alone is ~57 MB of plugin-SDK `node_modules` on this host — and the
  wrapper says so on stderr rather than letting you discover it as a surprise
  500 MB bill.

`OPENCODE_CONFIG_DIR` relocates opencode's config and `XDG_CACHE_HOME` its cache,
and deliberately not the other way round. opencode honours `OPENCODE_CONFIG_DIR`
on both sides — the TUI client resolves its Global service from it, which is where
`cli.json` is read and written, and the server takes it as `config.directory` —
while project-level `opencode.json` in the working directory stays a separate,
unaffected layer. Moving `XDG_CONFIG_HOME` instead would relocate every *other*
tool's configuration too: `git` reads `$XDG_CONFIG_HOME/git/config`, `gh` reads
its own subdirectory, and both would silently stop seeing their global settings.

Two warts, documented rather than fixed:

- **The host's own `model.json` stays masked at its own path**, in both the
  default and `OPENCODE_SANDBOX_HOST_PREFS=1` modes. The bind only replaces the
  file at the per-repo path, so the host's state directory is still an empty
  tmpfs from inside.
- **Writes from two repos do not exclude each other.** opencode locks such a
  store as `dirname(file)/locks/<hash of the full path>`, and inside a sandbox
  that path is this repo's, so the two repos take different locks and a
  concurrent toggle can be lost. The file is a few hundred bytes rewritten whole,
  so the outcome is one dropped favourite, never a corrupt file.

## Gotchas

- **Check which copy you are running.** An older `bubblewrap_opencode` installed
  on `PATH` (typically `~/.local/bin`) takes precedence over this directory and
  will quietly ignore every variable documented above.
- **The state root is masked inside the sandbox.** `ls ~/.local/share/opencode-sbx`
  from inside shows this repo's directory and nothing else. A tool that walks the
  state root to work out, say, how much disk the other repos use will conclude it
  is the only one. That is the intended answer, not a broken mount.
- **Favourites are shared; everything else about a repo is not.** To get
  per-repo favourites back, edit `state/opencode/model.json` in that repo's own
  state directory, or remove `prefs/model.json` from the state root so the
  wrapper falls back to per-repo files.
- **The first run of a repo is slower**, because it seeds the cache and config
  copies. See the reflink note above.
