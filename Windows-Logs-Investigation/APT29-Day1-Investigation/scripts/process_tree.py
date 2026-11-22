#!/usr/bin/env python3
"""Print the process tree below a given ProcessGuid.

Works on STEP1_process_creation_Sysmon1.csv (made by make_step_files.py).
Uses ProcessGuid / ParentProcessGuid, not PIDs, because Windows reuses PIDs.

Usage:
    python3 -I process_tree.py <STEP1.csv> "<ProcessGuid>"
"""
import sys

import pandas as pd


def main(path: str, start_guid: str) -> None:
    df = pd.read_csv(path, encoding="utf-8-sig").sort_values("Time_UTC")
    children = df.groupby("ParentProcessGuid")

    def show(guid: str, depth: int, seen: set) -> None:
        if guid in seen or guid not in children.groups:
            return
        seen.add(guid)
        for _, row in children.get_group(guid).iterrows():
            name = str(row["Image"]).split("\\")[-1]
            cmd = str(row["CommandLine"])[:140]
            print(f"{'  ' * depth}{row['Time_UTC']}  {name}  |  {cmd}")
            show(row["ProcessGuid"], depth + 1, seen)

    root = df[df["ProcessGuid"] == start_guid]
    if root.empty:
        sys.exit(f"ProcessGuid not found: {start_guid}")
    r = root.iloc[0]
    print(f"START  {r['Time_UTC']}  {r['Host']}  {r['User']}  {r['Image']}")
    show(start_guid, 1, set())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
