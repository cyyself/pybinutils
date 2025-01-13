#!/usr/bin/env python3

import sys
from arch.arch import arch_tools
from analyze.bb_utils import basic_block_size
from analyze.cfg import cfg_builder

if __name__ == "__main__":
    elf_file = sys.argv[1]
    symbol_name = sys.argv[2]
    cfg_dot_out = sys.argv[3]
    domtree_dot_out = sys.argv[4]
    elf = arch_tools.open_elf(elf_file)
    textdump = elf.read_textdump()
    bb, trans_edge = elf.read_basic_blocks(textdump)
    dwarf = elf.read_dwarf()
    bb_size = basic_block_size(bb)
    cfg = cfg_builder(bb, bb_size, trans_edge, symbol_name, dwarf)
    cfg.build_graphviz(cfg_dot_out)
    cfg.build_domtree_graphviz(domtree_dot_out)
