#!/usr/bin/env python3

import posixpath
import tempfile
import os
import re
from collections import OrderedDict
import sys

def lpe_filename(line_program, file_index):
    lp_header = line_program.header
    file_entries = lp_header["file_entry"]
    if lp_header.version < 5:
        file_index -= 1
    if file_index == -1:
        return None
    file_entry = file_entries[file_index]
    dir_index = file_entry["dir_index"]
    if dir_index == 0 and lp_header.version < 5:
        return file_entry.name.decode()
    if lp_header.version < 5:
        dir_index -= 1
    directory = lp_header["include_directory"][dir_index]
    return posixpath.join(directory, file_entry.name).decode()

skip_target = set()

class arch_tools:
    def open_elf(self, elf_path):
        assert False, "Not implemented"

    # Return ({filename: [line, col, pc, is_stmt, basic_block, end_sequence, prologue_end]})
    def read_dwarf(self):
        res = {}
        dwarfinfo = self.elf.get_dwarf_info()
        for CU in dwarfinfo.iter_CUs():
            line_program = dwarfinfo.line_program_for_CU(CU)
            if line_program is None:
                continue
            lp_entries = line_program.get_entries()
            for lpe in lp_entries:
                if not lpe.state:
                    continue
                filename = lpe_filename(line_program, lpe.state.file)
                if filename is None:
                    continue
                line_num = lpe.state.line
                col_num = lpe.state.column
                pc = lpe.state.address
                is_stmt = True if lpe.state.is_stmt else False
                basic_block = True if lpe.state.basic_block else False
                end_sequence = True if lpe.state.end_sequence else False
                prologue_end = True if lpe.state.prologue_end else False
                if filename not in res:
                    res[filename] = []
                res[filename].append([line_num, col_num, pc, is_stmt, basic_block, end_sequence, prologue_end])
        return res

    # Return {symbol_name: {addr: address, instr: {addr: (hex_code, instr)}}}
    def read_textdump(self, objdump_opts=''):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            if os.system(f'{self.objdump} {objdump_opts} -d {self.elf_path} > {tmp.name}') != 0:
                raise Exception('Failed to objdump ELF file')
            section_re = re.compile(r'^Disassembly of section ([^:]+):$')
            symbol_re = re.compile(r'^([0-9a-fA-F]+)\s+<([^>]+)>:$')
            symbols = OrderedDict()
            current_symbol = None
            current_section = None
            with open(tmp.name, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if line == "" or line == "...":
                        continue
                    s = section_re.match(line)
                    if s:
                        current_section = s.group(1)
                        continue
                    m = symbol_re.match(line)
                    if m and m.group(2).startswith("."):
                        continue
                    if m:
                        address = m.group(1)
                        symbol_name = m.group(2)
                        current_symbol = symbol_name
                        if symbol_name not in symbols:
                            symbols[symbol_name] = {'addr': int(address, 16), 'instr': OrderedDict()}
                    else:
                        if current_symbol and current_section == '.text':
                            # decode address
                            instr_tuple = line.split("\t")
                            addr = int(instr_tuple[0].strip()[:-1], 16)
                            hex_code = int(instr_tuple[1].strip(), 16)
                            rest = "\t".join(instr_tuple[2:])
                            symbols[current_symbol]['instr'][addr] = (hex_code, rest)
            return symbols

    def is_control_flow_instr(self, instr):
        assert False, "Not implemented"

    def is_control_flow_end(self, instr):
        assert False, "Not implemented"

    # Return ({symbol_name: {addr: address, bb: {bbstart: {addr: address, instr: {addr: (hex_code, instr)}}}}}, {trans_dst: [trans_src]})
    def read_basic_blocks(self, textdump):
        # Split basic blocks based on textdump
        trans_in = set()
        trans_out = set()
        trans_edge = dict()
        for sym in textdump:
            instrs = textdump[sym]['instr']
            addr_list = list(instrs.keys())
            for idx in range(len(addr_list)):
                addr = addr_list[idx]
                instr = instrs[addr]
                if self.is_control_flow_instr(instr):
                    trans_out.add(addr)
                    pos_l = instr[1].rfind('<')
                    pos_r = instr[1].rfind('>')
                    target_addr = None
                    if pos_l != -1 and pos_r != -1:
                        target = instr[1][pos_l+1:pos_r]
                        if '+' in target:
                            target_tuple = target.split('+')
                            if target_tuple[0] in textdump:
                                target_addr = textdump[target_tuple[0]]['addr'] + int(target_tuple[1], 16)
                            else:
                                if target not in skip_target:
                                    print(f"Warning: Unable to decode target address {target}", file=sys.stderr)
                                    skip_target.add(target)
                        elif '-' in target:
                            target_tuple = target.split('-')
                            if target_tuple[0] in textdump:
                                target_addr = textdump[target_tuple[0]]['addr'] - int(target_tuple[1], 16)
                            else:
                                if target not in skip_target:
                                    print(f"Warning: Unable to decode target address {target}", file=sys.stderr)
                                    skip_target.add(target)
                        else:
                            if target in textdump:
                                target_addr = textdump[target]['addr']
                            else:
                                try:
                                    target_addr = int(target, 16)
                                except:
                                    if target not in skip_target:
                                        print(f"Warning: Unable to decode target address {target}", file=sys.stderr)
                                        skip_target.add(target)
                    if target_addr:
                        trans_in.add(target_addr)
                        if addr not in trans_edge:
                            trans_edge[addr] = set()
                        trans_edge[addr].add(target_addr)
                    if not self.is_control_flow_end(instr) and idx + 1 < len(addr_list):
                        next_addr = addr_list[idx+1]
                        trans_in.add(next_addr)
                        if addr not in trans_edge:
                            trans_edge[addr] = set()
                        trans_edge[addr].add(next_addr)
        # Split basic blocks
        res = dict()
        for sym in textdump:
            instrs = textdump[sym]['instr']
            bb = OrderedDict()
            cur_bb = None
            cur_instr = OrderedDict()
            addr_list = list(sorted(instrs.keys()))
            for idx in range(len(addr_list)):
                addr = addr_list[idx]
                if cur_bb is None:
                    cur_bb = addr
                if addr in trans_in:
                    # Check last edge exist in basic block
                    if idx > 0:
                        last_addr = addr_list[idx-1]
                        if last_addr not in trans_out:
                            if last_addr not in trans_edge:
                                trans_edge[last_addr] = set()
                            trans_edge[last_addr].add(addr)
                    # Add current basic block
                    if len(cur_instr) > 0:
                        bb[cur_bb] = cur_instr
                    cur_instr = OrderedDict()
                    cur_bb = addr
                cur_instr[addr] = instrs[addr]
                if addr in trans_out:
                    if len(cur_instr) > 0:
                        bb[cur_bb] = cur_instr
                    cur_instr = OrderedDict()
                    cur_bb = None
            if len(cur_instr) > 0:
                bb[cur_bb] = cur_instr
            res[sym] = {'addr': textdump[sym]['addr'], 'bb': bb}
        return (res, trans_edge)
