#!/usr/bin/env python3

from bisect import bisect_right

class basic_block_size:
    def __init__(self, bb):
        all_basic_block = []
        max_bb_size = 0
        for symbol in bb:
            for bb_addr in bb[symbol]['bb']:
                all_basic_block.append((bb_addr, len(bb[symbol]['bb'][bb_addr])))
                max_bb_size = max(max_bb_size, len(bb[symbol]['bb'][bb_addr]))
        self.max_bb_size = max_bb_size
        self.all_basic_block = sorted(set(all_basic_block))

    def query_bb_id(self, addr):
        bb_index = bisect_right(self.all_basic_block, (addr, self.max_bb_size)) - 1
        if bb_index == -1:
            return None
        return bb_index

    def query_bb_addr(self, id):
        return self.all_basic_block[id][0]

    def query_bb_size(self, id):
        return self.all_basic_block[id][1]
