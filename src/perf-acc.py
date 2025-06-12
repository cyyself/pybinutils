#!/usr/bin/env python3

import sys
from analyze.perfutil import extract_perf_from_file

if __name__ == "__main__":
    perf_data_file = sys.argv[1] if len(sys.argv) > 1 else None
    if perf_data_file is None:
        print("Usage: python perf-acc.py <perf_data_file>")
        sys.exit(1)
    total_counts = dict()
    aslr_map = dict()
    data = extract_perf_from_file(perf_data_file)
    for file in data:
        for event in data[file]:
            for pc in data[file][event]:
                if event not in total_counts:
                    total_counts[event] = 0
                total_counts[event] += data[file][event][pc]
    for event, count in total_counts.items():
        print(f"{event}:{count}")
