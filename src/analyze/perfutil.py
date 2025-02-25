#!/usr/bin/env python3

import tempfile
import os

# file: perf.data
# return: {file: {event: {pc: count}}}
def extract_perf_from_file(file):
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
                file = line_split[-1].strip()[1:-1]
                if file not in res:
                    res[file] = dict()
                if event not in res[file]:
                    res[file][event] = dict()
                if pc not in res[file][event]:
                    res[file][event][pc] = 0
                res[file][event][pc] += freq
            return res
