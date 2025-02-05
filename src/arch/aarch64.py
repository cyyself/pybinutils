#!/usr/bin/env python3

from arch.arch import arch_tools
from elftools.elf.elffile import ELFFile
import tempfile
import os

class aarch64_tools(arch_tools):
    def __init__(self, elf_path, ldflags='-no-pie', ld='aarch64-linux-gnu-ld', objdump='aarch64-linux-gnu-objdump'):
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

    def __del__(self):
        for f in self.openfiles:
            f.close()
        for f in self.tmpfiles:
            os.remove(f)

    def read_dwarf(self):
        return super().read_dwarf()

    def read_textdump(self):
        return super().read_textdump('-M no-aliases')

    def is_control_flow_instr(self, instr):
        # instr should be (hex_code, instr) from read_textdump
        instr = instr[1].split("\t")[0].strip()
        if '.' in instr:
            instr = instr.split('.')[0]
        return instr in [
            'b', 'bl', 'br', 'blr', 'ret', # v8-branch
            'cbz', 'cbnz', # v8-compbranch
            'tbnz', 'tbz', # v8-testbranch
            'b.c', # v8-condbranch
            'braa', 'brab', 'blraa', 'blrab', 'braaz', 'brabz', 'blraaz', 'blrabz', 'retaa', 'retab' # pauth-branch
        ]

    def is_control_flow_end(self, instr):
        instr = instr[1].split("\t")[0].strip()
        if '.' in instr:
            instr = instr
        return instr in ['ret', 'retaa', 'retab']
