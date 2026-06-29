# fapolicyd systemd watchdog

When fapolicyd is built with systemd watchdog support, the installed service
uses `Type=notify` and starts the daemon with `--foreground`. This lets systemd
track the real daemon process directly. The daemon sends `READY=1` after
startup has completed and sends `WATCHDOG=1` only while the health monitor sees
decision workers making progress.

The `--debug` and `--debug-deny` modes disable systemd notification at runtime,
even if `NOTIFY_SOCKET` or `WATCHDOG_*` variables are inherited from the
environment. The production `--foreground` mode used by the service remains
notify-capable.

The default service sets:

```ini
[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/sbin/fapolicyd --foreground
WatchdogSec=10s
Restart=on-failure
RestartSec=1s
```

`WatchdogSec=` is the worker stall deadline. The health monitor checks workers
at half that interval and uses the same deadline when deciding whether queued
work has stopped making progress. If a worker stalls, fapolicyd records the
`worker_stall` failure action and terminates the daemon. Systemd then applies
the service restart policy.

Slow external storage can make a decision worker look stalled while the kernel
waits for a device to respond. Increase the watchdog timeout with a drop-in
rather than editing the packaged unit:

```ini
# /etc/systemd/system/fapolicyd.service.d/watchdog-timeout.conf
[Service]
WatchdogSec=30s
```

To disable watchdog restarts while keeping `Type=notify` readiness reporting:

```ini
# /etc/systemd/system/fapolicyd.service.d/no-watchdog.conf
[Service]
WatchdogSec=0
```

After adding or changing a drop-in, run:

```sh
systemctl daemon-reload
systemctl restart fapolicyd
```

Builds configured with `--disable-systemd-watchdog` install a legacy forking
unit instead:

```ini
[Service]
Type=forking
PIDFile=/run/fapolicyd.pid
ExecStart=/usr/sbin/fapolicyd
Restart=on-failure
RestartSec=1s
```
