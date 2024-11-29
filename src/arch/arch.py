#!/usr/bin/env python3

import posixpath
import tempfile
import os
import re

def lpe_filename(line_program, file_index):
    lp_header = line_program.header
    file_entries = lp_header["file_entry"]
    file_entry = file_entries[file_index - 1]
    dir_index = file_entry["dir_index"]
    if dir_index == 0:
        return file_entry.name.decode()
    directory = lp_header["include_directory"][dir_index - 1]
    return posixpath.join(directory, file_entry.name).decode()

class arch_tools:
    def open_elf(self, elf_path):
        assert False, "Not implemented"

    # Return ({filename: {line: {col: [pc, ...] }}}, {pc: [(filename, line, col)] })
    def read_dwarf(self):
        file_loc_pc = dict() # {filename: {line: {col: [pc, ...] }}}
        pc_loc_file = dict() # {pc: [(filename, line, col)] }
        dwarfinfo = self.elf.get_dwarf_info()
        for CU in dwarfinfo.iter_CUs():
            line_program = dwarfinfo.line_program_for_CU(CU)
            if line_program is None:
                continue
            lp_entries = line_program.get_entries()
            for lpe in lp_entries:
                if not lpe.state or lpe.state.file == 0:
                    continue
                filename = lpe_filename(line_program, lpe.state.file)
                line_num = lpe.state.line
                col_num = lpe.state.column
                pc = lpe.state.address
                if filename not in file_loc_pc:
                    file_loc_pc[filename] = dict()
                if line_num not in file_loc_pc[filename]:
                    file_loc_pc[filename][line_num] = dict()
                if col_num not in file_loc_pc[filename][line_num]:
                    file_loc_pc[filename][line_num][col_num] = []
                file_loc_pc[filename][line_num][col_num].append(pc)
                if pc not in pc_loc_file:
                    pc_loc_file[pc] = []
                pc_loc_file[pc].append((filename, line_num, col_num))
        return (file_loc_pc, pc_loc_file)

    # Return {symbol_name: {addr: address, instr: {addr: (hex_code, instr)}}}
    def read_textdump(self, objdump_opts=''):
        with tempfile.NamedTemporaryFile() as tmp:
            if os.system(f'{self.objdump} {objdump_opts} -d {self.elf_path} > {tmp.name}') != 0:
                raise Exception('Failed to objdump ELF file')
            section_re = re.compile(r'^Disassembly of section ([^:]+):$')
            symbol_re = re.compile(r'^([0-9a-fA-F]+)\s+<([^>]+)>:$')
            symbols = {}
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
                            symbols[symbol_name] = {'addr': int(address, 16), 'instr': {}}
                    else:
                        if current_symbol:
                            # decode address
                            instr_tuple = line.split("\t")
                            addr = int(instr_tuple[0].strip()[:-1], 16)
                            hex_code = int(instr_tuple[1].strip(), 16)
                            rest = "\t".join(instr_tuple[2:])
                            symbols[current_symbol]['instr'][addr] = (hex_code, rest)
            return symbols
