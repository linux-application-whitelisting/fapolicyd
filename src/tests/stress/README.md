# fapolicyd stress harness

`fapolicyd-stress` is a non-installed test helper for generating high-rate
fanotify decision traffic against a running `fapolicyd` daemon. It is intended
for development, QE, sizing, and regression work. It is not installed by
`make install`.

The helper creates configurable process trees and runs workloads that exercise
process startup tracking, subject cache collisions, object cache churn,
interpreter handling, no-shebang script handling, file opens, execs, and large
file reads.

## Building

The helper is built only when configure is run with `--enable-stress`:

```
./configure --enable-stress 
```

The binary is built in:

```
src/tests/stress/fapolicyd-stress
```

`--enable-stress` defaults to off. A normal build does not enter this
directory and does not build the helper.

## Trust Setup

When `fapolicyd` is running in enforcing mode, this helper is just another
locally built executable. It is not trusted by package metadata. On a typical
policy it can be blocked before the stress workload starts.

The interpreter workloads use committed scripts from
`src/tests/stress/scripts`. Add both the helper and that scripts directory to
the file trust database before running against an enforcing daemon:

```
stress_dir="$PWD/src/tests/stress"
fapolicyd-cli --file add "$stress_dir/fapolicyd-stress"
fapolicyd-cli --file add "$stress_dir/scripts"
fapolicyd-cli --update
```

Run these commands as root. If you rebuild the helper, refresh the helper
entry because the size or hash may have changed. The same paths can be passed
to `fapolicyd-cli --file update`, followed by `fapolicyd-cli --update`.

The harness still creates data, hash, and churn files under its temporary
work directory. Those generated files are workload inputs, not persistent test
programs.

## Privileges

The workload generator itself does not need to run as root. It forks, execs,
opens files, creates temporary files, and reads generated data using ordinary
user permissions.

Root is needed for the administrative parts:

- Adding or updating the stress helper and scripts in the trust database.
- Reliably collecting daemon status with `--status`.
- Using `--timing`, because manual decision timing requests are privileged.

If `--timing` is used as a non-root user, the harness exits before starting
the workload and reports that the option requires root or equivalent
privilege. If status collection is requested by a non-root user, the harness
prints a warning because the request usually cannot signal a root-owned daemon.

For local workload-only smoke tests, use `--no-status` and omit `--timing`.

## fapolicyd.conf Settings

No special `fapolicyd.conf` setting is required for basic stress generation or
for plain status snapshots.

`timing_collection=manual` is required when using `--timing`. The harness asks
the running daemon for a status report and verifies that the active
`Timing collection mode` is `manual` before starting the workload. If the
active mode is not `manual`, the harness exits with an explicit error.

`reset_strategy` is not required by the harness. The harness does not reset
daemon counters. It collects status before and after the workload and computes
deltas from the reported counters. For easiest interpretation, leave
`reset_strategy=never`, which is the default. If `reset_strategy=auto` and an
interval report resets counters during the stress run, before/after deltas can
undercount the workload. The harness reads `/etc/fapolicyd/fapolicyd.conf` for
`report_interval` and `reset_strategy`, and it prefers the active
`reset_strategy` from the daemon status report when that report is available.
If it sees `reset_strategy=auto` with a nonzero `report_interval`, it prints a
warning before the workload starts.

`report_interval` is not required. The harness asks the daemon for status
reports through `fapolicyd-cli --check-status`. If interval reports are enabled
with `reset_strategy=auto`, avoid running an interval reset in the middle of a
stress measurement unless that reset behavior is what you are testing.

`subj_cache_size`, `obj_cache_size`, and `q_size` control how much pressure is
needed before collisions, evictions, or queueing appear. The `early-evict`
preset is deliberately wide so it can trigger subject cache collisions on many
systems.

## Command Form And Terms

A representative full command is:

```
src/tests/stress/fapolicyd-stress --workload fork-exec --roots 32 \
  --fanout 8 --depth 1 --iterations 0 --seconds 60 --timing
```

The important terms are:

- `workload`: The kind of activity each leaf process performs.
- `root process`: A top-level worker forked by the harness parent.
- `fanout`: Number of children each non-leaf process creates.
- `depth`: Number of process-tree levels below each root process.
- `leaf process`: A process at the bottom of the tree. Leaf processes run the
  workload.
- `iteration`: One pass through the selected workload in a leaf process.
- `operation`: A local harness action, such as an exec attempt, open, or large
  file read. One operation is not the same as one daemon decision.
- `workdir`: The temporary directory for generated data, hash, and churn
  files.
- `status`: Before/after daemon state snapshots.
- `timing`: A daemon decision timing window wrapped around the workload.

The estimated leaf process count is:

```
roots * fanout ^ depth
```

The harness does not use pthreads. Concurrency comes from processes. More
root processes, fanout, or depth create more concurrent PIDs, which is the
pressure needed for subject-cache collisions. On large systems, increase those
process-tree controls to keep more CPUs busy.

## Harmless Default Commands

When no `--command` option is given, the harness uses harmless installed
system commands. For each command name it chooses the first executable path
from `/usr/bin` and `/bin`:

- `who`
- `users`
- `uname`
- `pwd`
- `printenv`
- `nproc`
- `ls`
- `hostid`
- `env`
- `dir`
- `date`
- `arch`
- `groups`
- `hostname`
- `id`
- `whoami`

If none of those are available, it falls back to `true` from `/usr/bin` or
`/bin`.

These commands are normally present on Linux systems, short-lived, read-only
for normal users, and safe to run repeatedly. They can still generate
substantial `fapolicyd` work because each exec produces permission events and
process startup state. The harness redirects their stdout and stderr to
`/dev/null` so repeated runs do not create command output logs.

Use `--command PATH` to replace the default target set. It takes one
executable path per option and may be repeated:

```
src/tests/stress/fapolicyd-stress --command /usr/bin/date \
  --command /usr/bin/id --workload fork-exec
```

`--command` is not comma separated. It is not a single shell string containing
multiple commands. If a path contains shell metacharacters or spaces, quote it
for the shell that launches `fapolicyd-stress`.

## Script Workloads

The script workloads use these committed, inspectable files:

- `src/tests/stress/scripts/with-shebang.sh`
- `src/tests/stress/scripts/without-shebang`

`with-shebang.sh` has `#!/bin/sh`, accepts the generated data file path as its
first argument, and loops four times running:

```
cat "$data" >/dev/null
```

`without-shebang` has no `#!` line, accepts the generated data file path as
its first argument, and loops four times running:

```
test -r "$data"
```

The harness runs these scripts in place from `src/tests/stress/scripts`. The
trust setup above adds that directory to file trust. The generated data file
is created under the harness work directory for each run.

## Workloads

Select a workload with `-w NAME` or `--workload NAME`.

- `fork-exec`: Tight fork/exec loop. Each leaf process repeatedly forks a
  child that execs one configured harmless command. This is the default
  workload and the best starting point for subject-cache and startup-state
  pressure.

- `exec-open`: Opens every configured command path and also executes one
  target per iteration. This adds object open traffic around the exec stream.

- `interpreter`: Runs `with-shebang.sh` directly and through the selected
  shell. This exercises interpreter and script startup handling.

- `noshebang`: Attempts a direct exec of `without-shebang`, treating
  `ENOEXEC` as expected, then runs the same script through the selected shell.
  This exercises no-shebang programmatic content paths.

- `hash`: Creates a generated large file and repeatedly reads it while
  computing a small local hash. This produces large file open/read activity
  and is useful when daemon integrity settings or policy cause file hashing.

- `churn`: Creates many distinct small files and opens them in rotation. This
  is meant to churn the object cache and expose object collisions or evictions.

- `all`: Runs every workload in each leaf iteration. Use this for broad
  coverage, not for isolating a single bottleneck.

## Process Tree Controls

- `-r N`, `--roots N`: Number of root processes to fork. Default: `4`.

- `-f N`, `--fanout N`: Number of child processes created by each non-leaf
  process. Default: `1`.

- `-d N`, `--depth N`: Number of process-tree levels below each root.
  Default: `0`.

More leaves increase parallel pressure. Wide process trees are the main way to
create PID modulo collisions in the subject cache.

## Run Length Controls

- `-i N`, `--iterations N`: Number of workload iterations per leaf process.
  Default: `100`. Use `0` only with `--seconds`.

- `-s N`, `--seconds N`: Wall-clock run length. Default: `0`, meaning the run
  is iteration-limited. When nonzero, the parent stops remaining workers after
  the deadline.

At least one of `--iterations` or `--seconds` must be nonzero.

## Workload Input Controls

- `-c PATH`, `--command PATH`: Add one executable target for `fork-exec` and
  `exec-open`. May be repeated. If omitted, the harmless default commands
  listed above are used.

- `--hash-mb N`: Size of the generated large file for the `hash` workload.
  Default: `16`.

- `--churn-files N`: Number of generated files for the `churn` workload.
  Default: `2048`.

- `--workdir DIR`: Base directory where the harness creates a private
  temporary work directory. Default: `/tmp`.

- `--keep-workdir`: Keep generated files after the run. This is useful for
  debugging policy denials against generated data, hash, or churn files.
  Without this option, the harness removes generated files before it exits.

- `--shell PATH`: Shell used for the shell-invoked half of the interpreter
  workloads. Default selection is `/bin/sh`, then `/usr/bin/sh`.

## Daemon Report Controls

By default, the harness tries to find `fapolicyd-cli` and capture daemon
status before and after the workload.

- `--status`: Capture daemon status. This is the default.

- `--no-status`: Do not capture daemon status. Use this for local smoke tests,
  unprivileged runs, or systems where `fapolicyd` is not running.

- `--timing`: Ask the daemon to start manual decision timing before the
  workload and stop it after the workload. This requires root or equivalent
  privilege and active `timing_collection=manual`.

- `--cli PATH`: Explicit `fapolicyd-cli` path. If omitted, the harness
  searches relative to itself, then common system paths.

- `-v`, `--verbose`: Print helper command failures, such as failed status or
  timing captures.

- `-h`, `--help`: Print the command-line help and exit.

The complete daemon state and timing reports are written by the daemon under
`/run/fapolicyd/`. The harness parses selected fields for its summary.

## Presets

`--preset early-evict` expands to an aggressive fork/exec collision workload:

```
--workload fork-exec --roots 32 --fanout 8 --depth 1 --iterations 0 --seconds 60
```

This creates an estimated 256 leaf processes. It is designed to go wide enough
that many unrelated PIDs map to the same subject-cache slots. When one process
is still in startup pattern detection and another process collides with its
slot, the daemon may report early subject cache evictions.

This preset is intentionally noisy. Run it on a test system.

## Examples

Build and run a short local smoke test without daemon reports:

```
./configure --enable-stress --without-deb
make -j32
src/tests/stress/fapolicyd-stress --no-status --workload fork-exec \
  --roots 2 --iterations 10
```

Run a timed fork/exec pressure test against a configured daemon:

```
src/tests/stress/fapolicyd-stress --workload fork-exec --roots 32 \
  --seconds 30 --timing
```

Run the early subject eviction preset:

```
src/tests/stress/fapolicyd-stress --preset early-evict --timing
```

Run broad mixed coverage:

```
src/tests/stress/fapolicyd-stress --workload all --roots 8 --fanout 4 \
  --depth 1 --seconds 60 --timing
```

## Harness Output

The first section echoes the run configuration:

- `workload`
- `roots`
- `fanout`
- `depth`
- `estimated leaf processes`
- `iterations per leaf`
- `seconds`
- `workdir`

The local workload summary is generated by the harness itself:

- `operations`: Count of local workload operations attempted. The exact
  meaning depends on the workload. For example, an exec attempt, a file open,
  or a generated large file read counts as an operation.

- `errors`: Local workload failures. Nonzero errors can mean policy denied one
  of the generated operations, an executable was missing, a temporary file
  could not be opened, or a child process failed. Use `--verbose` and daemon
  logs to separate policy denials from local setup problems.

- `throughput_ops_per_sec`: Local harness operations per second. This is not
  the same as daemon decision throughput because one local operation can
  generate zero, one, or multiple fanotify permission events.

## Daemon Status Output

When status collection succeeds, the harness prints `Daemon status deltas`.
These are parsed from `fapolicyd-cli --check-status` before and after the run.

Important fields:

- `Inter-thread max queue depth`: Highest daemon userspace queue depth seen.
  If this grows near `q_size`, the decision thread is not keeping up with
  event intake.

- `Early subject cache evictions`: Subject cache entries evicted before
  startup pattern detection completed. These are the main signal for the
  early-eviction problem. The `early-evict` preset is built to make this
  counter move.

- `Subject collisions`: Populated subject cache slots whose full process
  identity did not match the current event. This should rise during wide
  process pressure and helps confirm that early evictions were
  collision-driven.

- `Subject evictions`: Subject cache entries evicted and reused. Compare this
  with subject collisions and early subject evictions. Many evictions with no
  early evictions usually means churn happened after subject state was
  complete.

- `Object collisions` and `Object evictions`: Object cache churn indicators.
  These should move during `churn`, `all`, and workloads that touch many
  distinct files.

- `Allowed accesses` and `Denied accesses`: Policy decisions during the
  interval. Denials are expected if the selected workload intentionally hits
  policy-blocked script or programmatic paths. They are not expected for a pure
  throughput run using only trusted commands.

- `Kernel queue overflows`: Lost kernel fanotify visibility. Any nonzero value
  is a serious signal that the workload exceeded what the daemon and kernel
  queue could observe.

- `Reply errors`: Failed fanotify response writes. Any nonzero value needs
  investigation.

If the harness prints:

```
Daemon status: not observed
```

then it did not successfully collect both before and after status reports.
Common causes are:

- `fapolicyd-cli` was not found.
- `fapolicyd` was not running.
- The user could not signal the daemon or read the report.
- The daemon timed out while writing the report.

Use `--verbose` to show status capture failures. If `--no-status` was used,
the harness skips this section entirely instead of printing `not observed`.

## Timing Output

With `--timing`, the harness verifies the active timing mode, then wraps the
workload in:

```
fapolicyd-cli --timing-start
fapolicyd-cli --timing-stop
```

The daemon writes `/run/fapolicyd/fapolicyd.timing`, and the CLI prints it.
The harness parses a short summary from that report:

- `Decisions`: Number of completed daemon decisions timed during the run.

- `Max queue depth during timing`: Highest userspace queue depth observed
  during the timing window.

- `Timed throughput`: Daemon decisions per wall-clock second while timing was
  armed.

- `Active decision rate`: Decisions per second using accumulated
  `decision:total` worker time. This can differ from wall-clock throughput
  when the workload is bursty or when more than one decision worker is active.

- `Decision latency`: Parsed average, maximum, and p95 bucket for
  `decision:total`.

If the harness prints:

```
Decision timing: not observed
```

then no timing summary was parsed. Common causes are:

- `fapolicyd-cli` was not found.
- The daemon was not running.
- The daemon did not write `/run/fapolicyd/fapolicyd.timing`.
- The timing report format did not contain the fields parsed by the harness.

Use `--verbose` to show timing command failures. Also check the normal state
report fields `Timing collection mode` and `Timing collection armed`. If
`--timing` was omitted, the harness skips this section entirely instead of
printing `not observed`.

## Using The Timing Report

Use the full timing report with the harness output. The harness tells you what
load was generated and gives a compact summary; the timing report tells you
where the daemon spent time.

Start with the run summary:

- `Decisions` should be nonzero. If it is zero, the workload did not generate
  daemon decisions during the timing window.
- `Max queue depth` shows whether events backed up while timing was armed.
- Compare `Throughput` and `Active decision rate`. If wall-clock throughput is
  low but active decision rate is high, the workload may be bursty or idle
  part of the time. If both are low, decision work is expensive.

Then review these timing sections:

- `Overall decision latency`: Look at average, max, p95 bucket, and tail
  percentages. A high p95 means the slow path is common. A high max with a low
  p95 usually means rare outliers.

- `Queueing`: High average or p95 queue wait means requests are waiting before
  evaluation. If queue wait is high and max queue depth is near `q_size`,
  increase pressure carefully and consider whether the daemon needs tuning.

- `Decision phase timing`: Shows whether time is mostly in event build, rule
  evaluation, or response formatting.

- `Combined lazy helper attribution`: Useful for finding expensive helpers
  that are called lazily from rules or response formatting.

- `Detailed stage timing`: Sorts observed stages by total time. Use this to
  identify the main cost center.

Common interpretations:

- High `event_build:proc_fingerprint` means process identity lookups are a
  large cost. This is common in fork/exec-heavy tests.
- High `event_build:fd_stat` means object fingerprinting is expensive.
- High `evaluation:lock_wait` means the decision path waited for the rule
  lock.
- High `evaluation:total` with low helper cost points to rule traversal or
  rule matching cost.
- High `evaluation:mime_detection:*` or
  `response:mime_detection:*` points to file type detection cost.
- High `evaluation:mime_detection:libmagic_fallback` means fast MIME
  classification was not enough and libmagic was used often or expensively.
- High `evaluation:hash_sha:total` or `evaluation:hash_ima:total` means file
  integrity work is significant. The `hash` workload is useful for making this
  visible.
- High `evaluation:trust_db_lookup:*` means trust database lookup or lock/read
  time is material.
- High `response:syslog_debug_format:total` means reporting/debug formatting
  is dominating response cost. This can be more visible in debug-heavy runs
  than in normal daemon operation.
- High `response:fanotify_write` means completing the kernel permission
  response is expensive or blocked.

Use one workload at a time when isolating a bottleneck. Use `all` only after
you understand the individual workload costs.

## State Report Review Checklist

After a run, collect a normal state report:

```
fapolicyd-cli --check-status
```

Review:

- `Inter-thread max queue depth`
- `Allowed accesses`
- `Denied accesses`
- `Kernel Queue Overflow`
- `Reply Errors`
- `Subject cache size`
- `Subject slots in use`
- `Subject hits`
- `Subject misses`
- `Subject collisions`
- `Subject evictions`
- `Early subject cache evictions`
- `Object cache size`
- `Object slots in use`
- `Object hits`
- `Object misses`
- `Object collisions`
- `Object evictions`

For early subject eviction testing, the strongest evidence is:

- `Subject collisions` increased.
- `Early subject cache evictions` increased.
- The workload was wide enough to create many concurrent process startups.

For object cache testing, look for increased object misses, collisions, and
evictions during `churn` or `all`.

For queue pressure, compare `Inter-thread max queue depth` with configured
`q_size` and correlate it with the timing report's `Queueing` section.
