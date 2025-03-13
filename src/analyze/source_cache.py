#!/usr/bin/env python3

class source_cache:
    def __init__(self):
        self.source_cache = dict() # filename => list of lines
    def get_source(self, filename, line):
        if filename not in self.source_cache:
            try:
                with open(filename, 'r', errors='ignore') as f:
                    self.source_cache[filename] = f.readlines()
            except:
                self.source_cache[filename] = []
        if line < len(self.source_cache[filename]):
            return self.source_cache[filename][line - 1]
        else:
            return ""
