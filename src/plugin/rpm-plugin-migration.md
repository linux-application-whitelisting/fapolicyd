# Migrating the RPM transaction plugin to fapolicyd

This document describes how an RPM-based distribution can move the fapolicyd
transaction plugin from the RPM source package to the fapolicyd source package
without losing trust updates or running two active plugins.

The ownership transfer was requested in
[fapolicyd issue 316](https://github.com/linux-application-whitelisting/fapolicyd/issues/316)
after RPM 4.20 made its plugin API public. The immediate reason to complete the
transfer is the nonblocking FIFO failure exposed by
[fapolicyd issue 438](https://github.com/linux-application-whitelisting/fapolicyd/issues/438).
Existing releases still need the corresponding fix tracked in
[RPM issue 4110](https://github.com/rpm-software-management/rpm/issues/4110)
in the RPM-owned plugin.

## Components and names

The two plugins must have different loader identities while both packages are
available:

| Owner | Binary package | DSO | RPM macro | Daemon endpoint |
| --- | --- | --- | --- | --- |
| RPM (legacy) | `rpm-plugin-fapolicyd` | `fapolicyd.so` | `__transaction_fapolicyd` | `/run/fapolicyd/fapolicyd.fifo` |
| fapolicyd | `fapolicyd` | `fapolicyd_rpm.so` | `__transaction_fapolicyd_rpm` | `/run/fapolicyd/fapolicyd-update.fifo` |

The fapolicyd-owned plugin requires RPM's public plugin API. Upstream RPM first
provided it in 4.20. Configure tests for the API itself so a distribution can
use a complete backport without changing RPM's version number.

The record format is intentionally unchanged. This migration changes the
loader identity and endpoint, not the protocol.

## RPM version boundary and RHEL

The RPM version boundary makes this a staged migration rather than a single
cross-distribution cutover:

| Platform | RPM baseline | Public plugin API | Action |
| --- | --- | --- | --- |
| RHEL 9 | 4.16 | No | Keep RPM's plugin and apply its EAGAIN fix |
| RHEL 10 | 4.19 | No | Keep RPM's plugin unless the API is backported |
| RPM 4.20 or later | 4.20+ | Yes | Move ownership to fapolicyd |
| RHEL 11 | To be confirmed | Capability-dependent | Migrate if its RPM exposes the public API |

The RHEL baselines are documented in Red Hat's
[RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/considerations_in_adopting_rhel_9/assembly_software-management_considerations-in-adopting-rhel-9)
and
[RHEL 10](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/considerations_in_adopting_rhel_10/index#notable-changes-to-rpm_software-management)
migration guides. As a result, the natural RHEL landing is likely RHEL 11, but
the buildroot's API is authoritative. RHEL 10 can migrate earlier only if its
RPM receives a supported backport of the public header and plugin ABI.

Fapolicyd is prepared for that internal-to-external transition. Its configure
check detects the public API by compiling against `rpm/rpmplugin.h` rather than
requiring an RPM 4.20 version string. It also derives the plugin directory from
RPM's `libdir` when the newer `rpmplugindir` pkg-config variable is absent.
Therefore, an RPM 4.19-based distribution can enable the fapolicyd-owned plugin
after RPM exposes a supported API backport; no artificial version bump or
fapolicyd compatibility shim is needed. The distribution must still validate
that the backported ABI matches the installed `rpm-libs` and perform the
package/FIFO transition described below.

This capability check is also an explicit handoff path for RPM maintainers. If
the public API is backported into a release which currently builds the plugin
inside RPM, fapolicyd is ready to build and own the external plugin from that
same RPM release. The distribution can enable the `rpm_plugin` build condition
in `fapolicyd.spec`; it does not have to keep the internal copy until the next
RPM major version.

Until a distribution crosses that boundary, RPM remains responsible for its
copy. The fix for RPM issue 4110 must be applied to upstream and maintained
distribution branches which still ship `rpm-plugin-fapolicyd`. The fix stops
retrying `EAGAIN` in the inner nonblocking write loop and lets the existing
bounded reconnect loop sleep and enforce its timeout. Moving the plugin in an
RPM development branch does not fix RHEL 9 or RHEL 10 packages.

## Why an endpoint change is required

RPM loads every configured transaction plugin at the beginning of a
transaction. If two plugins write to the same daemon FIFO, both report every
file and control event. Giving the new plugin a separate endpoint lets the
daemon select one generation without depending on RPM plugin load order.

The new daemon creates only `fapolicyd-update.fifo`. The legacy plugin attempts
to open only `fapolicyd.fifo`; when that path is absent, its initialization
leaves the connection closed and all later hooks are no-ops.

The new plugin tries the new endpoint first. It falls back to the legacy
endpoint only when the new path does not exist. The fallback supports the
period after package replacement but before the running daemon has been
restarted.

## Transaction ordering

The transition relies on these RPM properties:

1. RPM discovers and loads transaction plugins before changing installed
   packages.
2. Removing the package which supplied a loaded DSO does not unload that DSO
   from the running RPM process.
3. The plugin `tsm_post` hook runs after package scriptlets and transaction file
   triggers.

Consequently, the legacy plugin which began the migration transaction can
finish that transaction even when its package is replaced along the way. The
running legacy daemon must not be restarted before `tsm_post`, or the loaded
plugin loses its endpoint before sending the final trust reload and cache flush
records.

## Package relationships

The main `fapolicyd` binary package should own `fapolicyd_rpm.so`,
`macros.transaction_fapolicyd_rpm`, its manual page, and this migration guide
when the public plugin API is available. Keeping the daemon and plugin in one
binary package ensures that their private protocol remains version-aligned.
The main package should also:

- provide the legacy `rpm-plugin-fapolicyd` capability for dependency
  compatibility; and
- obsolete the distribution's RPM-owned `rpm-plugin-fapolicyd` package.

Use distribution-appropriate version bounds on `Obsoletes`. The old RPM source
package and the new fapolicyd source package may coexist in repositories, but
the solver should replace the installed legacy binary package. RPM derives the
new plugin's `rpm-libs` dependency from its linked shared libraries, while
removing the legacy subpackage's exact dependency on the matching RPM build.

Do not ask administrators to remove the old package manually, and do not invoke
RPM recursively from a package scriptlet.

## Deferring the one-time restart

Some distributions, including Fedora, defer service restarts through systemd
transaction file triggers. The `%postun` script embedded in the previously
installed fapolicyd package may mark the service for restart even when the new
specification no longer does so. Changing only the new `%postun` is therefore
insufficient.

The new package's `%posttrans` should detect a running legacy daemon and cancel
only that queued restart. Runtime endpoints are a more reliable condition than
querying the old package, which may already have been obsoleted:

```sh
legacy=/run/fapolicyd/fapolicyd.fifo
current=/run/fapolicyd/fapolicyd-update.fifo

if test -p "$legacy" && test ! -p "$current"; then
        systemctl set-property fapolicyd.service \
                Markers=-needs-restart || :
        touch /run/fapolicyd/restart-required
        chown root:fapolicyd /run/fapolicyd/restart-required
        chmod 0640 /run/fapolicyd/restart-required
        echo "fapolicyd is using its legacy RPM plugin endpoint;" \
             "restart the service or reboot to complete the plugin migration" >&2
fi
```

This example uses the systemd marker facility available on current Fedora and
RHEL-family systems. Other distributions should use the equivalent mechanism
provided by their service packaging macros. Verify the exact scriptlet and
file-trigger ordering used by the target distribution.

The running old daemon then receives the final records from the loaded old
plugin. In later transactions before a restart, the installed new plugin uses
its legacy fallback and continues updating that daemon.

When the plugin is not built, the daemon retains the legacy endpoint. This is
required on distributions whose RPM predates the public plugin API and which
must continue using RPM's copy of the plugin.

## Administrator notification

The transition does not require a manual package removal. It requires one
service restart or reboot to activate the new daemon endpoint.

The package scriptlet creates `/run/fapolicyd/restart-required` and emits a
transaction notice. The new `fapolicyd-cli --check-status` also reports this
marker. A successful startup of the new daemon removes it after opening the new
FIFO. Because the marker is under `/run`, a reboot clears it as well.

Distribution tools such as `needs-restarting` may provide an additional notice
that the running executable was replaced, but they should not be the only
notification mechanism.

## When RPM can remove its copy

RPM can remove `plugins/fapolicyd.c`, its activation macro, manual page, build
option, and package file list after all of the following are true for the
target distribution:

1. A released fapolicyd builds the new plugin against RPM's public plugin API.
2. The distribution ships the plugin in `fapolicyd` with replacement metadata.
3. The main fapolicyd package owns the plugin DSO and activation macro.
4. An upgrade test confirms the old daemon finishes the migration transaction
   and the new plugin handles transactions both before and after restart.

The RPM-side EAGAIN fix should remain in maintained branches that still ship
the legacy plugin. Removing the plugin from RPM development does not repair
already released packages.

## Validation checklist

Test at least these cases in a disposable system:

- fresh installation with only the new plugin;
- upgrade while fapolicyd is running;
- another package transaction before restarting fapolicyd;
- service restart followed by another package transaction;
- upgrade while fapolicyd is stopped;
- failed and interrupted RPM transactions;
- RPM FIFO backpressure returning `EAGAIN`;
- rollback to packages using the legacy endpoint; and
- reboot with the restart-required marker present.
