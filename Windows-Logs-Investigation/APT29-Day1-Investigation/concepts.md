# Concepts

Key concepts used in this case, in plain language.

## Reading a process-creation row (Sysmon EventID 1)

| Field | Meaning |
|---|---|
| `Image` | The program file of the process that was created |
| `CommandLine` | How *this* process was started |
| `ParentImage` | The program file of the process that started it |
| `ParentCommandLine` | How the *parent* process was started (one level up). It is not something the parent passed to the child |
| `ProcessGuid` | A unique ID for this one process |
| `ParentProcessGuid` | The `ProcessGuid` of its parent |

## Why GUIDs and not process IDs (PIDs)?

Windows reuses PIDs. Once a process exits, an unrelated process can get the same number, so "PID 4120" can mean several different programs over time, and the same PID repeats across machines. A GUID (globally unique identifier) from Sysmon identifies exactly one process on one machine, so it is safe to filter on:

- `ProcessGuid` = *this process*. Use it to find everything it did (network, files, registry).
- `ParentProcessGuid` = *its parent*. Filter on a process's `ProcessGuid` to find its **children**.

## Judge a process by its chain, not alone

A plain `powershell` with no arguments is harmless on its own. Always ask three things together:

1. Who started it? (parent)
2. Is that parent normal for this program?
3. What did it do next? (children, files, network)

## Proven vs inferred

Write down what the logs prove, and label guesses as guesses. Example: the logs prove the user launched the `.scr` from `explorer.exe`. They do not prove it arrived by phishing.

## Techniques seen so far

- **Right-to-left override (RTLO):** a hidden Unicode character that reverses how text is displayed, so `cod.3aka3.scr` shows as `rcs.3aka3.doc`.
- **Auto-elevating binaries (such as `sdclt.exe`):** Windows programs that run with high privileges without a UAC prompt, which attackers abuse.
- **Steganography:** hiding data in an ordinary file, here a PNG read pixel by pixel.
- **Base64 + gzip wrapper in PowerShell:** decode Base64, gunzip, read as text, then run. The prefix `H4sI` is how a gzip file looks after Base64 encoding.

## Timeline Explorer tips

- Type in the row under a column header, or use the filter icon, to filter a column. Paste a full GUID including the braces.
- Drag a column header into the grey bar above the grid to group by it. Grouping by `ParentImage` shows "who starts what" quickly.
- The search box finds a value in any column.
- Searching a GUID shows both the process itself and its children, so count carefully.

## Hiding from a person is not hiding from the logs

Obfuscation hides code from a human reader. It does not hide it from the logs: the command line is recorded (Security 4688, Sysmon 1), and PowerShell script-block logging (EventID 4104) records the decoded script.
