# Windows Logs Lab

Self-built labs for Windows event log analysis. In each lab I generate the
activity myself in a Windows 10 VM, collect the logs as evidence, and work
them as a small case. The point is to learn one concept at a time by causing
an event and then finding its trace in the logs.

Every lab follows the same loop:

1. **Generate** — run a script in the VM to produce a realistic set of events.
2. **Collect** — export the relevant `.evtx` logs to CSV and work from copies.
3. **Investigate** — reconstruct what happened from the logs alone.
4. **Finding** — write a short analyst note: what happened, the evidence, the
   verdict, and what the logs do not show.

## Lab environment

| Item | Detail |
|---|---|
| Host | Windows 10 VM (`DESKTOP-O3RKO1P`), account `DFIR` |
| Logging | Sysmon with a community config; command-line auditing for 4688; PowerShell script block logging |
| Tools | Eric Zimmerman's EvtxECmd (parsing) and Timeline Explorer (analysis) |
| Snapshots | `clean`, then `logging-ready` as the starting point for every lab |

## Labs

| # | Lab | Focus | Key Event IDs |
|---|---|---|---|
| 01 | [Logon brute-force](lab-01-logon-bruteforce/) | Failed vs successful network logons | 4625, 4624, 4634 |

More labs are added as I work through each concept.
