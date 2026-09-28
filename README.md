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
| **Host credentials and history** | `~/.local/share/opencode` and `~/.local/state/opencode` are tmpfs-masked wholesale, and `auth.json`, `mcp-auth.json`, `account.json` and `service.json` additionally get 0-byte read-only binds. The three auth files are copied once into this repo's own `data/opencode/` at mode `600`, and the v2 provider credential *rows* are copied out of the host's `opencode.db` into this repo's own database — only those rows; the host database itself, with all its session history, stays masked. The sandbox reads those copies. |
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
  one set per repo, so revoking means deleting the state directory. The v2
  provider credential rows sit in this repo's own `opencode.db` — the same keys,
  readable by the same process — so nothing is exposed that the file did not
  already expose. A compromised
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
- **`OPENCODE_SANDBOX_SSH=1` hands the sandbox a signing oracle.** Not a key —
  the crypto stays in the agent on the host — but anything inside can ask that
  agent to authenticate to any host you can reach, repeatedly, and a plain
  `ssh-agent` will not ask you first. A keyring agent that prompts per use is
  what keeps this small. See [SSH agent forwarding](#ssh-agent-forwarding).
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
| `HOST FILES` | The host `auth.json`, `mcp-auth.json`, `account.json` and `service.json` read back empty; the host `opencode.db` and the host's `~/.ssh` contents are absent; this repo's credential copy is present and non-empty, and this repo's own `opencode.db` holds at least one provider credential row. A 0-byte mask is openable but empty, so the test is "can I read bytes", not "does `open()` succeed". |
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

## Environment variables

All optional, all read before the sandbox starts. `./bubblewrap_opencode --help`
prints this list ahead of opencode's own help.

| Variable | Effect |
| --- | --- |
| `OPENCODE_SANDBOX_SSH=1` | Forward the SSH **agent socket only**, plus a per-repo `known_hosts` copy of public host keys. Requires `$SSH_AUTH_SOCK` to already be a live socket — the wrapper never starts an agent, and warns and continues without SSH if it is not set, in which case git-over-SSH will not authenticate. Key material is never exposed either way. How to use it, and the two things it still gets you wrong: [SSH agent forwarding](#ssh-agent-forwarding). |
| `OPENCODE_SANDBOX_EXEC` | Any non-empty value runs the wrapper's **own arguments** in exactly the sandbox opencode would get, instead of running opencode. The value is only a switch, never the command. It is unset before exec so it cannot leak inward. |
| `OPENCODE_SANDBOX_HOME=<dir>` | Override the state root. Must be writable and **not under `/tmp`**: `/tmp` is a tmpfs inside the sandbox, so state stored there would be masked and invisible. The directory itself is replaced by an empty tmpfs with this repo's subdirectories bound back in, so pointing it too high costs visibility rather than breaking the run. |
| `OPENCODE_SANDBOX_RESET=1` | Delete this repo's `data/`, `state/`, `cache/` and `config/` before starting, so the next run re-seeds them from the host. This is how you revoke the copied credentials — the auth files and the seeded credential rows both live under `data/` — and how a host config change reaches a repo that was seeded earlier. The shared preferences survive it. |
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
│   │                  # the host files, mode 600), opencode.db (this repo's own
│   │                  # database; the v2 provider credential rows are seeded
│   │                  # into it from the host, and nothing else crosses over),
│   │                  # plus logs, storage
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
| **The repo's data** | `data/`, `state/` — db, snapshots, logs, prompt history, pins, credential copies (auth files and the db's credential rows) | per repo | session data must not leak between repositories |
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
  `authorized_keys`. Nothing under the per-repo state directory is a credential,
  which is why `OPENCODE_SANDBOX_RESET=1` does not touch `ssh/`.

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
  from inside shows this repo's directory and nothing else. A tool that walks the
  state root to work out, say, how much disk the other repos use will conclude it
  is the only one. That is the intended answer, not a broken mount.
- **Favourites are shared; everything else about a repo is not.** To get
  per-repo favourites back, edit `state/opencode/model.json` in that repo's own
  state directory, or remove `prefs/model.json` from the state root so the
  wrapper falls back to per-repo files.
- **The first run of a repo is slower**, because it seeds the cache and config
  copies. See the reflink note above.
