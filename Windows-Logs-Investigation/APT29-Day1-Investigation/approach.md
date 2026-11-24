# Working method: from 196,000 rows to a timeline

The dataset is too large to read, and a real case is larger. This page records the method I use to stay oriented, the checks I apply before I believe a finding, and the skills I'm building next.

## 1. Don't read the data, ask it questions

| Step | What I do | Example from this case |
|---|---|---|
| Scope | Count rows by host, event type and time range | 4 hosts, about 33 minutes, mostly Sysmon 12, 13, 10 and 7 |
| Anchor | Find the first thing that doesn't belong | A `.scr` file started by `explorer.exe` |
| Walk | Follow `ProcessGuid` → `ParentProcessGuid` | cmd → sdclt → control → PowerShell |
| Pivot | Take one fact (GUID, IP, file name) and search the whole file for it | `monkey.png` → create, read, delete, network |
| Pair | Match each network row with the 4104 script blocks in the same minute | Three "normal" web IPs belong to an exfiltration script |
| Count the rare | Group by `Image` or `DestinationIp` and read the smallest groups first | The one `python.exe` talking 348 times to one address |
| Write | One line per finding: `time \| host \| process \| what \| proof` | `timeline-and-attack-map.md` |

## 2. Keep each question small

- One question, one event type, one host, a time window of a minute or two.
- Hide every column except the five or six the question needs.
- Tag the interesting rows as I go, so I can return to them.
- Decode with CyberChef (Base64, gunzip) and read long script blocks in a text editor with word wrap.

## 3. Checks before I believe a finding

1. **Use the GUID, not the PID.** PIDs are reused. A process is identified by `ProcessGuid`.
2. **Convert time first.** Sysmon rows are UTC; Security and PowerShell rows only have local time (UTC−4). One wrong conversion shifts two events by four hours and breaks the story.
3. **Check the filter.** `Channel` has `Security` and `security`. A filter on one drops half the rows.
4. **Prove, then infer.** Each timeline row has an evidence column. If no single log row proves a statement, I label it inferred.
5. **Look for the empty result too.** "No scheduled task, no WMI, no log clearing" is a finding.
6. **Pair the sources.** Sysmon says what ran. Security 4688 adds token elevation. PowerShell 4104 shows the script text. A claim that rests on only one of them is weaker.
7. **Treat a detection title as a hypothesis.** A rule called "CosmicDuke" matched a pattern. The evidence is still the service, the account and the binary.
8. **State what the logs cannot show.** The LSASS access is proven. A credential dump is not.

## 4. Things I learned to watch for

- An attacker's tools often arrive as ordinary-looking files: a picture, a Java-named service, a `python.exe`. The *parent*, *location* and *behaviour* give them away.
- Benign destinations can sit inside malicious activity (the module downloads), so network rows need script context.
- A restart is not log clearing, and it resets session numbers: after the reboot, GUIDs end in `-000000000500`.
- A noisy rule is useful once: read three rows, understand the cause, then filter it out.

## 5. Tools I use, and what I'm adding

| Tool | Role | Status |
|---|---|---|
| Timeline Explorer | Filtering, grouping, tagging | In use |
| CyberChef | Decoding | In use |
| Hayabusa (Sigma rules) | Fast rule-based timeline as a second view | In use, see [the cross-check](investigation/detection-rules-cross-check.md) |
| Takajo | Analysis of Hayabusa output (process timelines, ATT&CK summary) | Next |
| EvtxECmd | Parsing raw `.evtx` into columns | Next |
| Timesketch | Collaborative timeline and written case narrative | Later |

## 6. Next practice

- Re-run each question in the investigation notes on the original CSV in Timeline Explorer, without opening the write-up first, and compare.
- Move from converted CSV to raw `.evtx` collections parsed with EvtxECmd.
- Add a second case with a different attack style (credential theft and persistence by scheduled task) to test the method on a new chain.
