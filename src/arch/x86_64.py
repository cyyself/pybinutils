#!/usr/bin/env python3

from arch.arch import arch_tools, insn_db_path
from elftools.elf.elffile import ELFFile
import tempfile
import os
import json
import sys

class x86_64_tools(arch_tools):
    def __init__(self, elf_path, ldflags='-no-pie', ld='x86_64-linux-gnu-ld', objdump='x86_64-linux-gnu-objdump', insn_db=insn_db_path()):
        self.elf_path = elf_path
        self.objdump = objdump
        self.openfiles = []
        self.tmpfiles = []
        f = open(self. elf_path, 'rb')
        self.elf = ELFFile(f)
        if self.elf['e_type'] == 'ET_REL':
            tf = tempfile.NamedTemporaryFile(delete=False)
            self.elf_path = tf.name
            self.tmpfiles.append(tf.name)
            if os.system(f'{ld} -o {tf.name} {elf_path} {ldflags} --warn-unresolved-symbols 2>/dev/null') != 0:
                raise Exception('Failed to compile ELF file')
            f.close()
            f = open(tf.name, 'rb')
            self.elf = ELFFile(f)
        self.openfiles.append(f)
        self.insn_db_x86_64 = None

    def __del__(self):
        for f in self.openfiles:
            f.close()
        for f in self.tmpfiles:
            os.remove(f)

    def read_dwarf(self):
        return super().read_dwarf()

    def read_textdump(self):
        return super().read_textdump('-M no-aliases --insn-width=20')

    def is_control_flow_instr(self, instr):
        # instr should be (hex_code, instr, control_flow_dir) from read_textdump
        if self.is_control_flow_end(instr):
            return True
        if instr[2] == 'X' or instr[2] == '-':
            return True
        return False

    def is_control_flow_end(self, instr):
        instr = instr[1].split("\t")[0].strip()
        if '.' in instr:
            instr = instr.split('.')[0]
        return instr in ['ret'] # TODO: check other return instructions
