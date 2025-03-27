#!/usr/bin/env python3

import os
import argparse

NR_STATS = 3

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Export tree structure of basic block hotness')
    parser.add_argument('-d', '--dir', type=str, help='output dir from dump_all_hot_bb')
    parser.add_argument('-t', '--threshold', type=float, default=0.0, help='function threshold')
    parser.add_argument('-l', '--limit', type=float, default=0.0, help='limit for top basic blocks')
    parser.add_argument('-c', '--coverage', type=float, default=1.0, help='function coverage threshold')
    parser.add_argument('-b', '--bb-coverage', type=float, default=1.0, help='basic block coverage threshold')
    parser.add_argument('-n', '--max-func', type=int, default=1e9, help='max function to dump')
    parser.add_argument('-m', '--max-bb', type=int, default=1e9, help='max basic block per function to dump')
    args = parser.parse_args()
    dir = args.dir
    for root, dirs, files in os.walk(dir):
        for workload in dirs:
            workload_dir = os.path.join(dir, workload)
            # each workload
            function_hotness = dict()
            bb_hotness = dict()
            bb_size = dict()
            for root, dirs, files in os.walk(workload_dir):
                for bb_file in files:
                    function_name = bb_file[:bb_file.rfind('_')]
                    bb_addr = bb_file[bb_file.rfind('_') + 1:bb_file.rfind('.')]
                    stats = dict()
                    with open(os.path.join(workload_dir, bb_file), 'r') as f:
                        lines = f.readlines()
                        stat_lines = lines[:NR_STATS]
                        cur_bb_size = len([line for line in lines if not line.startswith('#')])
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
                    if function_name not in bb_size:
                        bb_size[function_name] = dict()
                    bb_hotness[function_name][bb_addr] = stats['basic block hotness']
                    bb_size[function_name][bb_addr] = cur_bb_size
            print(f"├── {workload}")
            function_count = 0
            function_coverage = 0
            for function_name in sorted(function_hotness, key=lambda x: function_hotness[x], reverse=True):
                if function_hotness[function_name] < args.threshold:
                    continue
                print(f"│   ├── {function_name}(f): {function_hotness[function_name]*100:.2f}%")
                bb_count = 0
                bb_coverage = 0
                for bb_addr in sorted(bb_hotness[function_name], key=lambda x: bb_hotness[function_name][x], reverse=True):
                    if bb_hotness[function_name][bb_addr] < args.limit:
                        continue
                    print(f"│   │   ├── {bb_addr}(b): {bb_hotness[function_name][bb_addr]*100:.2f}%: {bb_size[function_name][bb_addr]}")
                    bb_count += 1
                    bb_coverage += bb_hotness[function_name][bb_addr]
                    if bb_count >= args.max_bb or bb_coverage >= args.bb_coverage:
                        break
                function_count += 1
                function_coverage += function_hotness[function_name]
                if function_count >= args.max_func or function_coverage >= args.coverage:
                    break
