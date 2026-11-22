# Resources and tools

The data, tools and references I use to build my own lab and work through this case. All are free. "Used" means I have used it in this investigation, and "Next" means it is planned.

## Datasets and lab data

| Resource | What it is | Status |
|---|---|---|
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | Pre-recorded log datasets from simulated attacks, including the APT29 evaluation (day 1) | Used |
| [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (Samir Bousseaden) | Single-technique `.evtx` samples, organised by attack technique | Used |
| [MITRE ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/) | Emulation plans and results for APT29, the answer key for this dataset | Next (compare only after my own hunt) |
| [Threat Hunter Playbook](https://threathunterplaybook.com/) | Hunts and notebooks built on the same datasets | Next |
| [DFIR Madness](https://dfirmadness.com/) | Raw evidence cases for end-to-end practice | Next |
| [CyberDefenders](https://cyberdefenders.org/) | Blue-team challenges, including endpoint forensics | Next |

## Lab environment

- A Windows 10 virtual machine set up for DFIR work: Windows Defender disabled so artifacts are generated, and snapshots used to return to a clean state.
- Sysmon-style event data (Sysmon, Security and PowerShell logs), analysed from converted CSV files and, in the next phase, from raw `.evtx` files.

## Tools

| Tool | Use | Status |
|---|---|---|
| [Timeline Explorer and EvtxECmd](https://ericzimmerman.github.io/) (Eric Zimmerman) | Filtering and parsing event logs | Used |
| [EvtxECmd maps](https://github.com/EricZimmerman/evtx) | Normalise `.evtx` payloads into columns | Next (raw `.evtx` phase) |
| Python and pandas | Format conversion, process trees, helper scripts | Used (`scripts/`) |
| [CyberChef](https://gchq.github.io/CyberChef/) | Base64, gunzip and other decoding | Used |
| [SigmaHQ rules](https://github.com/SigmaHQ/sigma) | Detection logic written as rules | Next |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) and [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | Run Sigma rules over `.evtx` quickly. I plan to use them as a checker after my own manual work | Next |
| [Timesketch](https://timesketch.org/) | Collaborative timeline analysis | Later |

## Reference documentation

| Reference | Why it helps |
|---|---|
| [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Field list for every Sysmon event |
| [Ultimate Windows Security: Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/) | Meaning of Security event IDs such as 4624, 4688 and 4697 |
| [MITRE ATT&CK](https://attack.mitre.org/) | Technique IDs for the findings |
| [SANS "Hunt Evil" poster](https://www.sans.org/posters/hunt-evil/) | Normal parents and children for core Windows processes |
| [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) | A well-known Sysmon configuration to compare against |

## Workflow in one line

Scope the data → find an anchor → walk the process tree by GUID → pivot into network, file and registry events → write down what each event proves → check my work.
