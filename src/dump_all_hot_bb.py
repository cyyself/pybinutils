#!/usr/bin/env python3

import argparse
import sys
import os
from arch.arch import arch_tools
from analyze.bb_utils import basic_block_size
from analyze.perfutil import extract_perf_from_file_with_symbol, extract_perf_from_file, perf_extract_deaslr_per_file
from analyze.source_cache import source_cache

def perf_to_bb_count(perf_extract, bb_size: basic_block_size):
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
            res[event][bb_addr] += perf_extract[event][pc]
    return res

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Dump func_hotspot from perf data file')
    parser.add_argument('-p', '--perf', type=str, help='Perf data file')
    parser.add_argument('-e', '--event', type=str, help='main event')
    parser.add_argument('-t', '--threshold', type=float, default=0.03, help='function threshold')
    parser.add_argument('-l', '--limit', type=float, default=0.03, help='limit for top basic blocks')
    parser.add_argument('-o', '--output', type=str, help='output folder')
    args = parser.parse_args()
    if args.perf is None or args.event is None:
        parser.print_help()
        exit(1)
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    perf_extract_symbol = extract_perf_from_file_with_symbol(args.perf)
    func_hotspots_mainevent = [] # (file, symbol, count)
    event_count = dict()
    events = set()
    for file in perf_extract_symbol:
        # perf events
        events.update(perf_extract_symbol[file].keys())
        for event in perf_extract_symbol[file]:
            for symbol in perf_extract_symbol[file][event]:
                if event == args.event:
                    func_hotspots_mainevent.append((file, symbol, perf_extract_symbol[file][event][symbol]))
                if event not in event_count:
                    event_count[event] = 0
                event_count[event] += perf_extract_symbol[file][event][symbol]
    func_hotspots_mainevent.sort(key=lambda x: x[2], reverse=True)
    # func hotspots
    aslr_map = dict()
    perf_extract = extract_perf_from_file(args.perf, aslr_map)
    elf_files = dict()
    bbs = dict()
    trans_edges = dict()
    dwarfs = dict() # source_file => dwarf
    bb_sizes = dict()
    bb_count = dict()
    dwarf_indecies = dict()
    for file in perf_extract:
        # elf
        try:
            curelf = arch_tools.open_elf(file)
            elf_files[file] = curelf
            textdump = curelf.read_textdump()
            perf_extract[file] = perf_extract_deaslr_per_file(perf_extract[file], aslr_map.get(file, dict()), textdump)
            bbs[file], trans_edges[file] = curelf.read_basic_blocks(textdump)
            dwarfs[file] = curelf.read_dwarf()
            bb_sizes[file] = basic_block_size(bbs[file])
            bb_count[file] = perf_to_bb_count(perf_extract[file], bb_sizes[file])
            # build dwarf index
            dwarf_indecies[file] = dict()
            for source_file in dwarfs[file]:
                for entry in dwarfs[file][source_file]:
                    pc = entry['pc']
                    if pc not in dwarf_indecies[file]:
                        dwarf_indecies[file][pc] = []
                    entry['filename'] = source_file
                    dwarf_indecies[file][pc].append(entry)
        except:
            print(f"Warning: Unable to process {file}", file=sys.stderr)
            elf_files[file] = None
            bbs[file] = None
            trans_edges[file] = None
            dwarfs[file] = None
            bb_sizes[file] = None
    src_cache = source_cache()
    for func_hotspot in func_hotspots_mainevent:
        cur_event_count = func_hotspot[2]
        if cur_event_count / event_count[args.event] < args.threshold:
            break
        file = func_hotspot[0]
        symbol = func_hotspot[1]
        if (file not in bbs) or (bbs[file] is None) or (symbol not in bbs[file]):
            continue
        cur_symbol_bb = set(bbs[file][symbol]['bb'].keys())
        top_bbs = []
        for bb_addr in cur_symbol_bb:
            if bb_addr in bb_count[file][args.event] and bb_count[file][args.event][bb_addr] / cur_event_count > args.limit:
                top_bbs.append(bb_addr)
        for bb_addr in top_bbs:
            outbuf = [
                f"# function hotness: {cur_event_count / event_count[args.event] * 100:.2f}%",
                f"# basic block hotness: {bb_count[file][args.event][bb_addr] / cur_event_count * 100:.2f}%"
            ]
            # cal dwarf
            instr_addrs = bbs[file][symbol]['bb'][bb_addr]
            for instr_addr in instr_addrs:
                if instr_addr in dwarf_indecies[file]:
                    for entry in dwarf_indecies[file][instr_addr]:
                        filename, line = entry['filename'], entry['line']
                        outbuf.append(f"# {src_cache.get_source(filename, line).strip()}")
                outbuf.append(f"{instr_addrs[instr_addr][1]}")
            with open(f"{args.output}/{symbol}_{hex(bb_addr)}.s", 'w') as f:
                f.write("\n".join(outbuf))
