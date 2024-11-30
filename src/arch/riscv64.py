#!/usr/bin/env python3

from arch.arch import arch_tools
from elftools.elf.elffile import ELFFile
import tempfile
import os

class riscv64_tools(arch_tools):
    def __init__(self, elf_path, cflags='-no-pie', cc='riscv64-linux-gnu-gcc', objdump='riscv64-linux-gnu-objdump'):
        self.elf_path = elf_path
        self.cc = cc
        self.objdump = objdump
        self.openfiles = []
        self.tmpfiles = []
        f = open(self. elf_path, 'rb')
        self.elf = ELFFile(f)
        if self.elf['e_type'] == 'ET_REL':
            tf = tempfile.NamedTemporaryFile(delete=False)
            self.elf_path = tf.name
            self.tmpfiles.append(tf.name)
            if os.system(f'{self.cc} -o {tf.name} {elf_path} {cflags} -g -Wl,--warn-unresolved-symbols 2>/dev/null') != 0:
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
        return super().read_textdump('-M no-aliases -M,max')

    def is_control_flow_instr(self, instr):
        # instr should be (hex_code, instr) from read_textdump
        instr = instr[1].split("\t")[0].strip()
        return instr in [
            'beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu', 'jal', 'jalr', # RV64I
            'c.beqz', 'c.bnez', 'c.jr', 'c.jalr', 'c.j' # RV64C
        ]
