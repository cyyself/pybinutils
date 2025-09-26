#!/usr/bin/env python3

import subprocess
import tempfile

class dasm_query:
    def __init__(self, cmd='riscv64-linux-gnu-objdump', enable_cache=True):
        if cmd.endswith('objdump'):
            self.cmd = cmd
            self.mode = 'objdump'
        elif cmd == 'spike-dasm':
            self.cmd = cmd
            self.mode = 'spike-dasm'
            self.spike = subprocess.Popen(
                [self.cmd],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        if enable_cache:
            self.cache = {}
        else:
            self.cache = None
    def dasm(self, instr):
        if self.cache is not None and instr in self.cache:
            return self.cache[instr]
        if self.mode == 'spike-dasm':
            self.spike.stdin.write(f"DASM(0x{hex(int(instr, 16))})\n")
            self.spike.stdin.flush()
            res = self.spike.stdout.readline().strip()
            if self.cache is not None:
                self.cache[instr] = res
            return res
        elif self.mode == 'objdump':
            # write instr.to_bytes(4, byteorder='little')
            with tempfile.NamedTemporaryFile() as f:
                f.write(instr.to_bytes(4, byteorder='little'))
                f.flush()
                res = subprocess.run(
                    [self.cmd, '-b', 'binary', '-m', 'riscv:rv64', '-M,max', '-D', f.name],
                    capture_output=True,
                    text=True
                )
                lines = res.stdout.splitlines()
                for line in lines:
                    if line.startswith("   0:\t"):
                        res = "\t".join(line.split("\t")[2:])
                        if self.cache is not None:
                            self.cache[instr] = res
                        return res
                return ""
