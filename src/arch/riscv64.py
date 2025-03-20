#!/usr/bin/env python3

from arch.arch import arch_tools, insn_db_path
from elftools.elf.elffile import ELFFile
import tempfile
import os
import json
import sys

class riscv64_tools(arch_tools):
    def __init__(self, elf_path, ldflags='-no-pie', ld='riscv64-linux-gnu-ld', objdump='riscv64-linux-gnu-objdump', insn_db=insn_db_path()):
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
        self.insn_db_riscv64 = None
        if insn_db:
            try:
                with open(insn_db / "riscv64-class.json", 'r') as f:
                    self.insn_db_riscv64 = json.load(f)
            except:
                print("Error: Cannot open riscv64-class.json", file=sys.stderr)

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

    def is_control_flow_end(self, instr):
        instr_split_t = instr[1].split("\t")
        instr0 = instr_split_t[0].strip()
        if instr[0] in ['c.j', 'c.jal', 'c.jr', 'c.jalr']:
            return True
        if instr0 in ['jal', 'jalr']:
            instr1 = instr_split_t[1].strip() if len(instr_split_t) > 1 else ""
            if not instr1.startswith('ra'):
                return True
        return False

    def get_insn_class_by_instr(self, instr):
        instr = instr[1].split("\t")[0].strip()
        if self.insn_db_riscv64:
            if instr in self.insn_db_riscv64:
                return self.insn_db_riscv64[instr]
        return None
