#!/usr/bin/env python3

import argparse
import sys
from arch.arch import arch_tools
from analyze.bb_utils import basic_block_size
from analyze.cfg import cfg_builder
from analyze.perfutil import extract_perf_from_file, perf_extract_deaslr_per_file

def perf_to_bb_count(perf_extract, bb_size: basic_block_size):
    # Count how many time a basic block is executed
    res = dict() # event => bb_addr => count
    for event in perf_extract:
        res[event] = dict()
        for pc in perf_extract[event]:
            bb_index = bb_size.query_bb_id(pc)
            if bb_index is None:
                continue
            bb_addr = bb_size.query_bb_addr(bb_index)
            if bb_addr not in res[event]:
                res[event][bb_addr] = 0
            res[event][bb_addr] += perf_extract[event][pc] / bb_size.query_bb_size(bb_index)
    return res

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Draw CFG and Dominator Tree from ELF file')
    parser.add_argument('-e', '--elf', type=str, help='ELF file')
    parser.add_argument('-p', '--perf', type=str, help='Perf data file')
    parser.add_argument('-s', '--symbol', type=str, help='Symbol name')
    parser.add_argument('-c', '--cfg', type=str, help='CFG output dot file')
    parser.add_argument('-d', '--dom', type=str, help='Dominator Tree output dot file')
    parser.add_argument('-t', '--scctree', type=str, help='SCC Tree output dot file')
    parser.add_argument('-m', '--metric', type=str, help='perf metric name')
    args = parser.parse_args()
    if args.elf is None and args.symbol is None:
        parser.print_help()
        exit(1)
    elf = None
    perf_file = None
    cur_elf_path = args.elf
    aslr_map = dict()
    if cur_elf_path:
        aslr_map[cur_elf_path] = dict() # dummy
    if args.perf is not None:
        perf_extract = extract_perf_from_file(args.perf, aslr_map)
        for file in perf_extract:
            if file == '[kernel.kallsyms]' or file == '[vdso]' or file == '[unknown]':
                continue
            try:
                curelf = arch_tools.open_elf(file)
                if args.symbol in curelf.read_textdump():
                    elf = curelf
                    cur_elf_path = file
                    perf_file = perf_extract[file]
            except:
                print(f"Warning: Unable to process {file}", file=sys.stderr)
        if elf is None:
            print(f"Error: Unable to find {args.symbol} in perf data", file=sys.stderr)
            exit(1)
    else:
        elf = arch_tools.open_elf(args.elf)
    textdump = elf.read_textdump()
    perf_file = perf_extract_deaslr_per_file(perf_file, aslr_map[cur_elf_path], textdump)
    bb, trans_edge = elf.read_basic_blocks(textdump)
    dwarf = elf.read_dwarf()
    bb_size = basic_block_size(bb)
    bb_count = None
    if perf_file is not None:
        bb_count_event = perf_to_bb_count(perf_file, bb_size)
        if args.metric is None:
            if len(bb_count_event) > 1:
                print("Error: Multiple events found in perf data, please use -m specify the event to use:", file=sys.stderr)
                print("Available events:", file=sys.stderr)
                for event in bb_count_event:
                    print(f"{event}", file=sys.stderr)
                exit(1)
            else:
                bb_count = bb_count_event[list(bb_count_event.keys())[0]]
        else:
            if args.metric not in bb_count_event:
                print("Error: Event not found in perf data, please use -m specify the event to use:", file=sys.stderr)
                print("Available events:", file=sys.stderr)
                for event in bb_count_event:
                    print(f"{event}", file=sys.stderr)
                exit(1)
            else:
                bb_count = bb_count_event[args.metric]
    cfg = cfg_builder(bb, bb_size, trans_edge, args.symbol, dwarf, bb_count)
    if args.cfg is not None:
        cfg.build_graphviz(args.cfg)
    if args.dom is not None:
        cfg.build_domtree_graphviz(args.dom)
    if args.scctree is not None:
        cfg.build_scctree_graphviz(args.scctree)
