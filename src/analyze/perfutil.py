#!/usr/bin/env python3

import tempfile
import os
import re
import sys
import subprocess

# return: (symbol, offset)
def split_target_symbol(symbol_addr):
    if symbol_addr == '[unknown]':
        return None
    elif '+' in symbol_addr:
        try:
            symbol, offset = symbol_addr.split('+')
            offset = int(offset, 16)
            match = re.match("^[A-Za-z_][A-Za-z0-9_.]*$", symbol)
            assert match is not None
            return (symbol, offset)
        except:
            return None
    else:
        match = re.match("^[A-Za-z_][A-Za-z0-9_.]*$", symbol_addr)
        if match is not None:
            return (symbol_addr, 0)
        else:
            return None

# file: perf.data
# return: {file: {event: {pc: count}}}
def extract_perf_from_file(file, aslr_map=None):
    with tempfile.NamedTemporaryFile() as tmp:
        os.system("perf script -i {} --no-demangle --full-source-path > {}".format(file, tmp.name))
        with open(tmp.name, 'r') as f:
            lines = f.readlines()
            res = dict()
            for line in lines:
                colon_pos = line.find(":")
                if colon_pos == -1:
                    continue
                line_split = line[colon_pos+1:].split()
                freq = int(line_split[0])
                event = line_split[1][:-1]
                pc = int(line_split[2], 16)
                if aslr_map is not None:
                    symbol_addr = line_split[3]
                    target_tuple = split_target_symbol(symbol_addr)
                    if target_tuple:
                        if file not in aslr_map:
                            aslr_map[file] = dict()
                        aslr_map[file][pc] = target_tuple
                    else:
                        if symbol_addr != '[unknown]':
                            print(f"Warning: Unable to process {symbol_addr}", file=sys.stderr)
                file = line_split[-1].strip()[1:-1]
                if file not in res:
                    res[file] = dict()
                if event not in res[file]:
                    res[file][event] = dict()
                if pc not in res[file][event]:
                    res[file][event][pc] = 0
                res[file][event][pc] += freq
            return res

# file: perf.data
# return: {file: {event: {symbol: count}}} (has_symbol_offset = False)
# return: {file: {event: {symbol: {offset: count}}}} (has_symbol_offset = True)
def extract_perf_from_file_with_symbol(file, has_symbol_offset=False):
    result = subprocess.run(["perf", "script", "-i", file, "--no-demangle", "--full-source-path"], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    res = dict()
    for line in lines:
        colon_pos = line.find(":")
        if colon_pos == -1:
            continue
        line_split = line[colon_pos+1:].split()
        freq = int(line_split[0])
        event = line_split[1][:-1]
        symbol = line_split[3]
        offset = 0
        if symbol == '[unknown]':
            continue
        if '+' in symbol:
            offset = int(symbol.split('+')[1], 16)
            symbol = symbol.split('+')[0]
        file = line_split[-1].strip()[1:-1]
        if file not in res:
            res[file] = dict()
        if event not in res[file]:
            res[file][event] = dict()
        if symbol not in res[file][event]:
            if has_symbol_offset:
                res[file][event][symbol] = dict()
            else:
                res[file][event][symbol] = 0
        if has_symbol_offset:
            if offset not in res[file][event][symbol]:
                res[file][event][symbol][offset] = 0
            res[file][event][symbol][offset] += freq
        else:
            res[file][event][symbol] += freq
    return res

def perf_extract_deaslr_per_file(perf_extract_file, aslr_map_file, textdump):
    # de-aslr perf data
    res = dict()
    for event in perf_extract_file:
        res[event] = dict()
        for pc in perf_extract_file[event]:
            new_pc = pc
            if pc in aslr_map_file:
                symbol, offset = aslr_map_file[pc]
                if symbol in textdump:
                    new_pc = textdump[symbol]['addr'] + offset
            res[event][new_pc] = perf_extract_file[event][pc]
    return res
