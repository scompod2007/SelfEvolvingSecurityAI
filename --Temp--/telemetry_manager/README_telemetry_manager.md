# Telemetry Manager

Drop the `telemetry/` folder, `main.py`, and `config.json` into your
`SelfEvolvingSecurityAI/` project root, alongside your existing
`collectors/` and `database/` folders. No changes to any collector
file are required.

```
SelfEvolvingSecurityAI/
    collectors/          <- unchanged
    database/             <- unchanged
    data/
    telemetry/             <- new
        __init__.py
        telemetry_manager.py
        collector_wrapper.py
        config_loader.py
        health_monitor.py
        statistics.py
        logger.py
    main.py                 <- new
    config.json             <- new
    requirements.txt
```

Run it with:

```
python main.py
```

## Why a `collector_wrapper.py` (not in the suggested file list)

The spec's "collector.start() / collector.stop()" flow assumes a
uniform, non-blocking interface, but the four existing collectors
don't quite have one:

| Collector        | Constructor        | Blocking entry point | `stop()`? |
|-------------------|--------------------|-----------------------|-----------|
| `ProcessMonitor`  | `interval`         | `monitor()`           | No — just a public `running` flag |
| `FileMonitor`     | `watch_path`       | `start()`             | Yes |
| `RegistryMonitor` | none (event-driven)| `start()`             | Yes |
| `NetworkMonitor`  | `interval`         | `start()`             | Yes |

All four entry points (`monitor()`/`start()`) already contain their
own `while self.running:` loop and manage their own internal
threads — calling them directly from the manager would block it.
`CollectorWrapper` (in `collector_wrapper.py`) is a small adapter
that:

1. Runs each collector's existing blocking entry point on its own
   manager-owned thread — it never adds a second monitoring loop.
2. Stops each collector the way that collector actually supports:
   `.stop()` where it exists, or setting `.running = False` directly
   for `ProcessMonitor`.
3. Exposes a uniform `start() / stop() / restart() / is_alive()` to
   `TelemetryManager`, so `telemetry_manager.py` never needs to know
   which collector is quirky.

This is why Ctrl+C is only ever caught in `TelemetryManager.run()`:
once a collector's entry point runs on a background thread,
`KeyboardInterrupt` can no longer reach it directly (Python only
delivers it to the main thread), so each collector's own
`except KeyboardInterrupt` block is effectively dead code once it's
under the manager. Shutdown is deterministic instead: the manager
calls `stop()` on every collector explicitly.

## Config keys that exist but aren't used by v1 collectors

- `registry_interval` — `RegistryMonitor` is event-driven
  (`RegNotifyChangeKeyValue`), not polling, so it takes no interval.
- `file_interval` — `FileMonitor` uses `watchdog`'s event-driven
  `Observer`, not polling.
- `file_watch_path` — the current `FileMonitor` auto-discovers every
  mounted drive and ignores its `watch_path` constructor arg.

These keys are kept in `config.json` / `config_loader.py` purely for
forward compatibility, so a future polling-based revision of those
collectors works with zero config or manager changes. They're logged
as intentionally-unused in code comments, not silently dropped.

## Statistics without hammering the database

`telemetry/statistics.py` keeps `Statistics` counts (uptime, restart
count, health-check count) purely in memory. The one thing that
does require a database read — per-collector event counts — is
refreshed on its own background timer (`stats_refresh_interval`,
default 10s) and served from an in-memory cache in between, so
`print_status()` / `update_statistics()` never touch the database
directly, however often they're called.

## Extending with a future collector (e.g. Memory Monitor)

1. Add `"memory"` to `TelemetryManager.COLLECTOR_ORDER`.
2. Add a `_build_memory_spec()` method returning a `CollectorSpec`
   (see the four existing `_build_*_spec` methods for the pattern).
3. Add `"memory_monitor": true` (and any interval key it needs) to
   `config.json` / `DEFAULT_CONFIG`.

Nothing else in `telemetry_manager.py`, `collector_wrapper.py`,
`health_monitor.py`, or `statistics.py` needs to change.

## Verified behavior

This was smoke-tested end-to-end with stand-in collectors that
reproduce the real ones' exact interface shapes (blocking
`start()`/`monitor()`, no `stop()` on the process collector, etc.),
including one collector deliberately raising an exception mid-run.
Observed: all four start correctly on their own threads, the crash
is detected and the collector auto-restarted with a fresh instance
within one health-check cycle, and shutdown stops every collector
cleanly with a final status report — no hangs, no leaked threads.
