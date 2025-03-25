#!/usr/bin/env python3

import os
import sys

NR_STATS = 3

if __name__ == "__main__":
    dir = sys.argv[1]
    for root, dirs, files in os.walk(dir):
        for workload in dirs:
            workload_dir = os.path.join(dir, workload)
            # each workload
            function_hotness = dict()
            bb_hotness = dict()
            for root, dirs, files in os.walk(workload_dir):
                for bb_file in files:
                    function_name = bb_file[:bb_file.rfind('_')]
                    bb_addr = bb_file[bb_file.rfind('_') + 1:bb_file.rfind('.')]
                    stats = dict()
                    with open(os.path.join(workload_dir, bb_file), 'r') as f:
                        stat_lines = f.readlines()[:NR_STATS]
                        for line in stat_lines:
                            key, value = line.strip().split(':')
                            if key.startswith('# '):
                                key = key[2:]
                            if value.endswith('%'):
                                value = float(value[:-1]) / 100
                            elif value.startswith('2**'):
                                value = 2 ** float(value[3:])
                            stats[key] = value
                    function_hotness[function_name] = stats['function hotness']
                    if function_name not in bb_hotness:
                        bb_hotness[function_name] = dict()
                    bb_hotness[function_name][bb_addr] = stats['basic block hotness']
            print(f"├── {workload}")
            for function_name in sorted(function_hotness, key=lambda x: function_hotness[x], reverse=True):
                print(f"│   ├── {function_name}(f): {function_hotness[function_name]*100:.2f}%")
                for bb_addr in sorted(bb_hotness[function_name], key=lambda x: bb_hotness[function_name][x], reverse=True):
                    print(f"│   │   ├── {bb_addr}(b): {bb_hotness[function_name][bb_addr]*100:.2f}%")
