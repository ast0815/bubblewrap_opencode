# bubblewrap_opencode

A wrapper that runs [opencode](https://github.com/sst/opencode) inside a
bubblewrap sandbox, with the escape routes that let an agent in a sandbox act on
the host closed off.

Use it instead of `opencode`:

```sh
./bubblewrap_opencode                    # TUI
./bubblewrap_opencode run "fix the test"
./bubblewrap_opencode session list
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
| **Key material** | `~/.ssh` is a tmpfs. No private key, `config` or `known_hosts` from the host is ever visible. |
| **Kernel and namespaces** | `--unshare-all --share-net`, `--unshare-user --disable-userns`, `--cap-drop ALL`, `NoNewPrivs`. Nested user namespaces fail with `ENOSPC`, so a compromised process cannot build a second sandbox. |
| **Code-execution via PATH** | `~/.bun` and `~/.local/share/uv/tools` are read-only, so a downloaded script cannot be edited into a host-side code-execution path. |
| **The rest of the filesystem** | `--ro-bind / /`; the only writable host binds are the current working directory and the per-repo state directory. |
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
- **`~/.cache/opencode/node_modules` is writable and shared.** opencode
  downloads and executes provider packages at runtime, so this bind has to stay.
  A compromised sandbox can write there, and the host-wide opencode service
  executes from the same directory. Two fixes, neither applied: retire that
  service (the wrapper now always passes `--standalone`, so nothing needs it), or
  give it a separate `XDG_CACHE_HOME`.
- **Everything else under `/` is readable.** `--ro-bind / /` hides nothing.
  Other secrets in `$HOME` — other `~/.local/share/*` apps, `~/.gnupg`, browser
  profiles, `~/.config/*/credentials` — are readable and can be exfiltrated
  through the network. Only the opencode and ssh paths were handled.
- **The per-repo `auth.json` copy is readable and usable.** That is the point:
  the sandbox needs credentials. It lives in plaintext at
  `~/.local/share/opencode-sbx/<repo>-<hash>/data/opencode/auth.json`, one set
  per repo, so revoking means deleting the state directory. A compromised
  process can both use it and read it out.
- **`/tmp` is RAM-backed and per-invocation.** Writable, but thrown away when
  the sandbox exits. Do not use it to carry state between runs.
- **The per-repo state directory is on the host disk.** It is keyed on the git
  toplevel; every subdirectory of a repo shares one history, and two different
  repos are isolated from each other but not from you.

## Tested escape routes

`sandbox-selftest` runs *inside* the sandbox. It is the authority for every
claim in this table, and every row was re-run at the commit that added this
README.

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
| `~/.local/share/opencode/auth.json` | empty mask |
| `~/.local/share/opencode/mcp-auth.json` | empty mask |
| `~/.local/share/opencode/account.json` | empty mask |
| `~/.local/share/opencode/opencode.db` | hidden, dir masked |
| `~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, `~/.ssh/config` | hidden, dir masked |
| per-repo `auth.json` copy | **present and non-empty** — required |

Note the two different tests. A 0-byte mask is *openable* but empty, so the
question is "can I read bytes", not "does `open()` succeed". A missing file
inside a tmpfs-masked directory is the other case; that is why
`opencode.db` reads as hidden rather than as "not on this host".

### Functionality — nothing lost

| Check | Verdict |
| --- | --- |
| `opencode`, `node`, `bun`, `git`, `python3`, `ssh` | all run |
| Working directory writable, git history readable | OK |
| Filesystem and `HOME` readable, `getent passwd` works | OK |
| DNS resolution, HTTPS egress | OK — the check names whichever endpoint answered; set `SBX_EGRESS_URL` to test one specific provider |
| `/tmp` writable | OK |
| `npm install` + `require` | OK |
| `bun add` + `import` | OK |
| `uvx` a package, `uv tool install` + run | OK |
| `pip install` in a venv | OK |
| A tool in a read-only toolchain dir runs but is not writable | OK — the selftest picks whichever tools it finds on `PATH`, and skips the check if it finds none |

The writable-bound report is part of the selftest output. Expected shape —
every line is derived from `$HOME` at runtime, so paths are shown relative to it:

```
ro       ~/.bun
ro       ~/.local/share/uv/tools
ro       ~/.cache
tmpfs    ~/.local/state/opencode   (writable, empty, ephemeral)
tmpfs    ~/.local/share/opencode   (writable, empty, ephemeral)
tmpfs    ~/.ssh                    (writable, empty, ephemeral)
WRITABLE ~/.cache/opencode         <-- the known risk above
```

A `WRITABLE` line here is the finding to read, not a cosmetic note: it marks a
directory where sandbox writes land on a real host filesystem. A `tmpfs` line is
writable but empty and discarded at exit.

Read-only package caches are not enough on their own: a `ro` bind looks fine
until something tries to install into it, so each package manager is redirected
at a per-repo cache directory via `BUN_INSTALL_CACHE_DIR`, `npm_config_cache`,
`UV_CACHE_DIR`, `UV_TOOL_DIR`, `UV_TOOL_BIN_DIR` and `PIP_CACHE_DIR`.

### Confirmed to work end to end

- A real `opencode run` completes and prints `PATH OK` / `SANDBOX OK`.
- State persists across wrapper invocations in the same folder: a marker file
  written in run 1 is present in run 2, and the per-repo `opencode.db` grows from
  empty. Sessions are listed from the per-repo database.
- `session list`, `auth list`, `debug paths`, `models`, `stats` and `serve` all
  work, including `--standalone` being placed and detected per leaf subcommand.

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

## Environment variables

| Variable | Effect |
| --- | --- |
| `OPENCODE_SANDBOX_SSH=1` | Forward the SSH **agent socket only** (plus a per-repo `known_hosts` copy, public keys). Requires `$SSH_AUTH_SOCK` to already be a live socket — the wrapper never starts an agent, and warns and continues if it is not set. Key material is never exposed either way. |
| `OPENCODE_SANDBOX_EXEC` | Any non-empty value makes the wrapper run its **own arguments** inside exactly the sandbox opencode would get, instead of running opencode. The value is only a switch, never the command — so `OPENCODE_SANDBOX_EXEC=1 ./bubblewrap_opencode hostname` prints `opencode-sandbox`, and `./bubblewrap_opencode hostname` without it runs opencode and errors. Unset before exec so it cannot leak inward. |
| `OPENCODE_SANDBOX_HOME=<dir>` | Override the state root. |
| `OPENCODE_SANDBOX_RESET=1` | Delete this repo's `data/`, `state/` and `cache/` before starting. This is how you revoke the copied credentials. |

## State layout

```
~/.local/share/opencode-sbx/<repo>-<sha256[:12]>/    # key = git toplevel basename + path hash
├── data/opencode/     # XDG_DATA_HOME: auth.json, mcp-auth.json, account.json (copies of the
│                      # host files, mode 600), plus opencode.db, storage, logs
├── state/             # XDG_STATE_HOME: locks, prompt history, model.json
├── cache/{bun,npm,uv,pip}
├── tools/bin          # uv tool executables
├── ssh/known_hosts    # only when OPENCODE_SANDBOX_SSH=1
└── meta               # the git toplevel this key came from
```

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
- **`--ro-bind / /` hides nothing.** Read-only is not invisible; see the risk
  list above.
