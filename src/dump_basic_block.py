#!/usr/bin/env python3

import argparse
import sys
from arch.arch import arch_tools
from analyze.bb_utils import basic_block_size
from analyze.perfutil import extract_perf_from_file

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Dump basic block objdump from ELF file')
    parser.add_argument('-e', '--elf', type=str, help='ELF file')
    parser.add_argument('-p', '--perf', type=str, help='Perf data file')
    parser.add_argument('-l', '--location', type=lambda x: int(x,0), help='Location (PC) to dump')
    parser.add_argument('-m', '--mca', action='store_true')
    args = parser.parse_args()
    elf = None
    elf_textdump = None
    if args.elf is None:
        # Try to find PC from perf data
        if args.perf is None:
            parser.print_help()
            exit(1)
        perf_extract = extract_perf_from_file(args.perf)
        for file in perf_extract:
            if file == '[kernel.kallsyms]' or file == '[vdso]' or file == '[unknown]':
                continue
            try:
                curelf = arch_tools.open_elf(file)
                elf_textdump = curelf.read_textdump()
                for symbol in elf_textdump:
                    if args.location in elf_textdump[symbol]['instr']:
                        elf = curelf
                        break
            except:
                print(f"Warning: Unable to process {file}", file=sys.stderr)
        if elf is None:
            print(f"Error: Unable to find {hex(args.location)} in perf data", file=sys.stderr)
            exit(1)
    else:
        elf = arch_tools.open_elf(args.elf)
    textdump = elf.read_textdump()
    bb, trans_edge = elf.read_basic_blocks(textdump)
    dumped = False
    for symbol in bb:
        for bbstart in bb[symbol]['bb']:
            cur_bb = bb[symbol]['bb'][bbstart]
            if args.location in cur_bb:
                assert not dumped, "Basic block found multiple times"
                for addr, instr_tuple in cur_bb.items():
                    if args.mca:
                        buf = instr_tuple[1].strip()
                        print(buf)
                    else:
                        print(f"  {str(hex(addr))[2:]}:\t{instr_tuple[0]:08x} \t{instr_tuple[1].strip()}")
                dumped = True
    assert dumped, "Basic block not found"