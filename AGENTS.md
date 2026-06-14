# Repository Guidelines

## Working Agreements

- This is `fapolicyd`, an autotools C project for the daemon, CLI, policy
  rules, trust database backends, and package manager integration helpers.
- Before changing files, inspect `git status --short --branch`. Keep `main`
  clean; work on a focused branch and leave unrelated local changes alone.
- Prefer `rg`/`rg --files` for search. Make surgical changes that match the
  existing module and style.

## Build And Test

- Normal local build:

  ```sh
  ./autogen.sh
  ./configure --with-audit --disable-shared
  make -j$(nproc)
  ```

- `--with-rpm` is the default when librpm is available. Use `--without-rpm`
  if rpm development libraries are missing.
- On Fedora/RHEL hosts, skip Debian/libdpkg support unless `libdpkg` and
  `libmd` are confirmed installed.
- Useful optional configure flags: `--with-asan`, `--with-perf-test`, and
  `--enable-stress`.
- Run `make check` when feasible. For a targeted test after configuring, use
  the Automake form, for example `make -C src/tests check TESTS=rules_test`.
- The stress helper is opt-in: configure with `--enable-stress`, then build or
  test under `src/tests/stress`. See `src/tests/stress/README.md` before using
  it against a running daemon.
- If you created autotools build artifacts, run `make maintainer-clean` before
  finishing unless the user explicitly wants the build tree preserved.

## Project Map

- `src/library`: shared policy, rules, trust DB, event, cache, metrics, and
  utility code used by the daemon and CLI.
- `src/daemon`: daemon entry point, fanotify handling, mounts, and state
  reporting.
- `src/cli`: `fapolicyd-cli`, rule linting, ignore-mount checks, and related
  user-facing commands.
- `src/handler`: package-manager helper programs such as the RPM loader.
- `src/perf-test`: optional installed performance test utility.
- `src/tests`: unit and regression tests; `src/tests/stress` is a separate
  non-installed stress harness.
- `init`: default config, magic database inputs, systemd unit, tmpfiles, and
  bash completion.
- `doc`: man pages and manpage checks.
- `rules.d`: policy rule units consumed by `fagenrules`.
- `dnf`, `deb`, `CI`, `.fmf`: packaging, integration, and CI metadata.

## C Style

- Follow Linux kernel style: tabs are 8 columns, keep lines near 80 columns,
  match existing brace style, and avoid unrelated whitespace churn.
- New C functions need a short comment describing purpose, inputs, and return
  behavior. Prefer comments that explain why edge-case code exists.
- Try hard to keep functions at 4 arguments or fewer. If more data is needed,
  consider a focused struct or smaller functions.
- Keep `.c` files class-like and focused. Add small local helpers to the file
  they support; extract a new module only when a related helper cluster has its
  own state, lifecycle, naming prefix, or reusable purpose.
- Preserve existing names and patterns unless the change requires otherwise.

## Rules And Policy Files

- The authoritative rule syntax reference is `doc/fapolicyd.rules.5`.
- Keep `rules.d` files in the numbered groups documented in
  `rules.d/README-rules`, and preserve natural sort order because first match
  wins.
- Do not add new `dir=untrusted` policy. It is deprecated and should be
  replaced with explicit trust-based object matching.

## Commits

- Commit only when asked. Make one logical commit per issue.
- Do not commit on `main`.
- Commit messages should have a concise subject plus body paragraphs explaining
  what was wrong, how it was fixed, and what tests were added or run.
