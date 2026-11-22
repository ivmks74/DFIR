#!/usr/bin/env python3
"""Create small, easy-to-open CSVs from the full APT29 Day 1 export.

The full file is ~190k rows x ~390 columns, which is slow in Timeline Explorer.
This script keeps only what the lab questions need:

  STEP1_process_creation_Sysmon1.csv  - Sysmon EventID 1 (process creation)
  STEP3_network_Sysmon3.csv           - Sysmon EventID 3 (network connection)

Fixes applied on the way (see README, "Dataset quirks"):
  * one clean UTC time column (Time_UTC)
  * Channel capitalisation normalised (Security / security)
  * the hidden right-to-left-override character is shown as <RTLO>

Usage:
    python3 -I make_step_files.py <full_export.csv> <output_dir>
"""
import sys
from pathlib import Path

import pandas as pd

# The file name garbles the RTLO character (U+202E) into these characters.
GARBLED_RTLO = "â€®"  # what "U+202E" looks like after double encoding
RTLO = "‮"


def clean_text(series: pd.Series) -> pd.Series:
    return (
        series.astype(str)
        .str.replace(GARBLED_RTLO, "<RTLO>", regex=False)
        .str.replace(RTLO, "<RTLO>", regex=False)
    )


def main(src: str, out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(src, low_memory=False, encoding="utf-8-sig")

    # Sysmon rows have UtcTime. Other rows only have EventTime, which is local
    # time (UTC-4 in this dataset), so shift it by +4 hours.
    utc = pd.to_datetime(df["UtcTime"], errors="coerce")
    local = pd.to_datetime(df["EventTime"], errors="coerce") + pd.Timedelta(hours=4)
    df["Time_UTC"] = utc.fillna(local)

    df["Channel"] = df["Channel"].astype(str).str.title()
    df["Host"] = df["Hostname"].astype(str).str.split(".").str[0]

    sysmon = df[df["Channel"].str.contains("Sysmon", na=False)]

    proc = sysmon[sysmon["EventID"] == 1][
        [
            "Time_UTC", "Host", "User", "Image", "CommandLine",
            "ParentImage", "ParentCommandLine", "ProcessGuid", "ParentProcessGuid",
        ]
    ].sort_values("Time_UTC")
    for col in ("Image", "CommandLine", "ParentImage", "ParentCommandLine"):
        proc[col] = clean_text(proc[col])
    proc.to_csv(out / "STEP1_process_creation_Sysmon1.csv", index=False, encoding="utf-8-sig")

    net = sysmon[sysmon["EventID"] == 3][
        ["Time_UTC", "Host", "User", "Image", "DestinationIp", "DestinationPort", "ProcessGuid"]
    ].sort_values("Time_UTC")
    net["Image"] = clean_text(net["Image"])
    net.to_csv(out / "STEP3_network_Sysmon3.csv", index=False, encoding="utf-8-sig")

    print(f"STEP1: {len(proc)} rows, STEP3: {len(net)} rows -> {out}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
