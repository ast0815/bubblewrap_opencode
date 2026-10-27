# bubblewrap_opencode

Runs [opencode](https://github.com/sst/opencode) inside a bubblewrap sandbox.
Use it instead of `opencode`:

```sh
./bubblewrap_opencode                    # TUI
./bubblewrap_opencode run "fix the test"
./bubblewrap_opencode session list
./bubblewrap_opencode --help             # sandbox summary, then opencode's help
```

`bubblewrap_opencode` builds the sandbox; `sandbox-selftest` measures it from
inside. Design notes, threat model and verification live in
[AGENTS.md](AGENTS.md).

## Filesystem

Read-write:

| Path | Notes |
| --- | --- |
| the current directory | the one writable host path. Read-only if it is `$HOME` or a parent of it, unless `OPENCODE_SANDBOX_HOME_RW=1`; `/` is refused. |
| `<state root>/shared/{config,state}/opencode` | opencode's config and runtime state, shared by every sandbox, never the host's. |
| `<state root>/<repo>-<hash>/{data,cache,tools}` | this repo's session DB, credential copies, caches and tool executables. |
| `/tmp` | a fresh tmpfs, discarded on exit. |

Read-only:

| Path | Notes |
| --- | --- |
| `/` | `--ro-bind / /`. |
| `~/.bun`, `~/.local/share/uv/tools` | host toolchains. |
| `~/.cache/opencode`, `~/.config/opencode` | host opencode cache/config; `service.json` is masked empty. |

Masked with an empty tmpfs:

| Path | Notes |
| --- | --- |
| `$XDG_RUNTIME_DIR`, `/run/user/<uid>`, `/run/dbus`, `/run/systemd` | host IPC. |
| `~/.local/share/opencode`, `~/.local/state/opencode` | host opencode data/state. |
| `~/.ssh` | no key material. |
| `<state root>` | only the paths above are bound back in. |

The state root defaults to `~/.local/share/opencode-sbx`.
`DISPLAY`, `WAYLAND_DISPLAY`, `DBUS_SESSION_BUS_ADDRESS`, `XAUTHORITY` and the
`XDG_SESSION_*`/`XDG_SEAT*` pointers are unset. The hostname inside is
`opencode-sandbox`.

## Environment variables

All optional, read before the sandbox starts. `./bubblewrap_opencode --help`
prints this list ahead of opencode's own help.

| Variable | Effect |
| --- | --- |
| `OPENCODE_SANDBOX_SSH=1` | Forward the SSH agent socket only, no key material, plus a per-repo `known_hosts`. |
| `OPENCODE_SANDBOX_GH_TOKEN=1` | Resolve the gh CLI's token on the host and pass it in as `GH_TOKEN`. |
| `OPENCODE_SANDBOX_EXEC` | Any non-empty value runs the wrapper's own arguments in the sandbox instead of opencode. The value is only a switch. |
| `OPENCODE_SANDBOX_HOME=<dir>` | Override the state root. Must be writable and not under `/tmp`. |
| `OPENCODE_SANDBOX_HOME_RW=1` | Make a working directory that is `$HOME` or a parent of it writable. |
| `OPENCODE_SANDBOX_RESET=1` | Delete this repo's `data/`, `cache/`, `tools/` and the shared config, then re-seed them; the shared state is kept. |
| `OPENCODE_SANDBOX_SYNC_PREFS=1` | Copy the host's `model.json` into the shared state before starting (one way). |
| `OPENCODE_SANDBOX_HOST_PREFS` | Removed; the wrapper warns if it is set. Use `OPENCODE_SANDBOX_SYNC_PREFS=1`. |
