# APT29 Day 1: Windows Event Log Investigation

> **Status: in progress.** Phases 1 and 2 are written up. Phases 3 to 5 (network, persistence, credentials and lateral movement) are next.

A hands-on investigation of a multi-host attack simulation, using only Windows event logs (Sysmon, Security and PowerShell).

## Goal

Reconstruct what an attacker did across four Windows machines in about 33 minutes, starting from one suspicious file, using only log evidence. The core technique is tracing the execution tree (`ProcessGuid` → `ParentProcessGuid`) and recording only what the logs prove.

## Lab setup and tools

| Item | Detail |
|---|---|
| Lab | Windows 10 VM set up for DFIR work (Defender disabled so artifacts are generated, snapshots for clean states) |
| Analysis | Eric Zimmerman's Timeline Explorer (main tool), Python and pandas for conversion and helper scripts |
| Decoding | CyberChef for Base64 and gzip |
| Reference | MITRE ATT&CK, Sysmon documentation |

## Dataset

- **Source:** the APT29 evaluation (day 1, manual run) from the [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) project, which comes from the MITRE ATT&CK Evaluations emulation.
- **Size:** about 196,000 rows and 388 columns after converting the JSON export to CSV.
- **Hosts:** `SCRANTON`, `NASHUA`, `NEWYORK`, `UTICA`. **Time window:** 2020-05-02, about 02:55 to 03:28 UTC.
- **The data is not included in this repo.** Download it from the source above and use the scripts in `scripts/` to reproduce my working files.

Most rows are noise for a first pass. Registry (Sysmon 12, 13) and process-access (Sysmon 10) events make up more than half of them, while process creation (Sysmon 1) is only 447 rows. I created two small working files so Timeline Explorer stays fast:

- `STEP1_process_creation_Sysmon1.csv`: process creation (447 rows)
- `STEP3_network_Sysmon3.csv`: network connections (1,229 rows)

## Method

1. Scope the data: hosts, time range, event types.
2. Find an **anchor**: the earliest process that doesn't belong.
3. Walk down the tree using `ParentProcessGuid` = the process's `ProcessGuid`.
4. Pivot sideways on the same `ProcessGuid` into network, file and registry events.
5. Write each finding as: `time | host | process | what it did | proof (ProcessGuid)`.
6. Separate **proven** (in the logs) from **inferred** (a reasonable guess).

## Progress

| Phase | Topic | Status |
|---|---|---|
| 1 | [Initial access](investigation/phase-1-initial-access.md) | Done |
| 2 | [Execution and tools](investigation/phase-2-execution-and-tools.md) | Process tree done. Privilege escalation and payload analysis in progress |
| 3 | Command and control (network) | Next |
| 4 | Persistence and cleanup | Next |
| 5 | Credentials and lateral movement | Next |

## What I've found so far

On **SCRANTON**, user `DMEVALS\pbeesly` ran a file named `<RTLO>cod.3aka3.scr` from `C:\ProgramData\victim\`. It was launched by `explorer.exe`, which means a person double-clicked it. The file then opened two `cmd.exe` sessions about 68 seconds apart and several `powershell.exe` processes. The second session also started `sdclt.exe` three times, which I'm investigating as a possible privilege-escalation step. A long PowerShell command references `monkey.png`, and I'm analysing it as a possible hidden-payload technique.

Mapping to MITRE ATT&CK so far:

| Technique | Evidence | Confidence |
|---|---|---|
| T1204.002 User Execution: Malicious File | `explorer.exe` starts the `.scr` | Confirmed |
| T1036.002 Masquerading: Right-to-Left Override | `<RTLO>` character in the file name | Confirmed |
| T1059.003 Windows Command Shell | `.scr` starts `cmd.exe` twice | Confirmed |
| T1059.001 PowerShell | `powershell.exe` under `cmd.exe` | Confirmed |
| T1548.002 Bypass User Account Control | three `sdclt.exe` launches by `cmd.exe` | Hypothesis, to confirm with `IntegrityLevel` |
| T1027.003 Obfuscated Files: Steganography | command line reads `monkey.png` pixel by pixel | Observed in the command line, payload not yet analysed |

## Dataset quirks (worth knowing before you start)

- **Mixed-case channel names.** `Channel` contains both `Security` and `security`. Filtering on one silently drops about half the Security rows.
- **Two clocks.** Sysmon rows have `UtcTime`. Security and other rows only have `EventTime`, which is local time (UTC-4). My script adds 4 hours so there is one `Time_UTC` column.
- **Garbled filename character.** The right-to-left override (U+202E) appears as `â€®` after conversion. The scripts show it as `<RTLO>`.
- **Windows reuses PIDs.** Always build trees from `ProcessGuid`, not `ProcessId`.

## Repo layout

```
APT29-Day1-Investigation/
├── README.md                      this file
├── resources.md                   datasets, lab setup, tools, reference docs
├── concepts.md                    key concepts in plain language
├── investigation/
│   ├── phase-1-initial-access.md
│   └── phase-2-execution-and-tools.md
├── images/                        Timeline Explorer screenshots used as evidence
└── scripts/
    ├── make_step_files.py         full CSV -> STEP1 / STEP3 working files
    └── process_tree.py            print the process tree under a ProcessGuid
```

## Reproduce

```bash
python3 -I scripts/make_step_files.py apt29_evals_day1_manual.csv out/
python3 -I scripts/process_tree.py out/STEP1_process_creation_Sysmon1.csv "{47ab858c-e13c-5eac-a903-000000000400}"
```

## Credits

- **Dataset:** [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets), built on the [MITRE ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/) APT29 emulation.
- **Tools:** [Timeline Explorer and EvtxECmd](https://ericzimmerman.github.io/) by Eric Zimmerman, [CyberChef](https://gchq.github.io/CyberChef/) by GCHQ, and the Python library pandas.
- **Practice logs:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by Samir Bousseaden.
