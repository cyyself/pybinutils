#!/usr/bin/env python3

import argparse
import math
from analyze.perfutil import extract_perf_from_file_with_symbol

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Dump hotspot from perf data file')
    parser.add_argument('-p', '--perf', type=str, help='Perf data file')
    parser.add_argument('-e', '--event', type=str, help='main event')
    parser.add_argument('-t', '--threshold', type=float, default=0.03, help='threshold')
    args = parser.parse_args()
    if args.perf is None or args.event is None:
        parser.print_help()
        exit(1)
    perf_extract_symbol = extract_perf_from_file_with_symbol(args.perf)
    hotspots_mainevent = [] # (file, symbol, count)
    all_count = dict()
    events = set()
    for file in perf_extract_symbol:
        events.update(perf_extract_symbol[file].keys())
        for event in perf_extract_symbol[file]:
            for symbol in perf_extract_symbol[file][event]:
                if event == args.event:
                    hotspots_mainevent.append((file, symbol, perf_extract_symbol[file][event][symbol]))
                if event not in all_count:
                    all_count[event] = 0
                all_count[event] += perf_extract_symbol[file][event][symbol]
    hotspots_mainevent.sort(key=lambda x: x[2], reverse=True)
    for hotspot in hotspots_mainevent:
        if hotspot[2] / all_count[args.event] < args.threshold:
            break
        all_events = dict()
        for event in events:
            if event not in perf_extract_symbol[hotspot[0]]:
                continue
            if hotspot[1] not in perf_extract_symbol[hotspot[0]][event]:
                continue
            all_events[event] = perf_extract_symbol[hotspot[0]][event][hotspot[1]]
        for each_event in sorted(all_events.keys()):
            print(f"{hotspot[1]}\t{each_event}\t{math.log2(all_events[each_event]):.2f}({all_events[each_event] / all_count[each_event] * 100:.2f}%)")
