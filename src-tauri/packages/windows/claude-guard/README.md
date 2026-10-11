# Auto Chain Claude guard

The Windows build invokes `build.ps1` to compile the filter manager. The installer applies
the guard and registers the `Clash Verge Auto Chain Claude Guard` SYSTEM task.
It discovers installed Claude packages and Claude Code binaries at startup,
logon, and every minute, verifying existing rules before adding missing ones.
The most recent successful scan is recorded in
`%ProgramData%\ClashVergeAutoChainProtection\auto-chain-guard-status.json`;
Task Scheduler reports a nonzero result when discovery or verification fails.

The guard blocks non-loopback IPv4 and IPv6 connections for discovered Claude
executables. Loopback services remain accessible on all ports. Browser filters,
system proxy settings, DNS, and routes are not changed. LAN browser access still
passes through Auto Chain's local proxy and its DIRECT rules.

Rules persist when Auto Chain exits. New paths have a discovery window of up to
one scan interval (longer if the scheduled task fails). This is not a guarantee
against connections opened before a new path is protected. Restart an already
running Claude after repairing missing rules. Unknown executable locations and
traffic forwarded by another local service are outside this path-based policy.

Uninstall removes the discovery task but retains persistent blocking rules to
avoid silently enabling direct access. `reconcile.ps1 -Action Audit`, run as an
administrator from the installed package, checks currently discovered paths
without changing rules.
