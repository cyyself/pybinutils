#!/usr/bin/env python3

import posixpath
import tempfile
import os
import re
from bisect import bisect_left, bisect_right
from collections import OrderedDict
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.descriptions import describe_form_class
import pathlib

def insn_db_path():
    cur_dir = pathlib.Path(os.path.realpath(__file__))
    insn_db_path = cur_dir.parent.parent.parent / 'ext' / 'insn-db' / 'out'
    if 'INSN_DB' in os.environ:
        return pathlib.Path(os.environ['INSN_DB'])
    elif insn_db_path.exists():
        return insn_db_path
    else:
        return None

def lpe_filename(line_program, file_index, comp_dir):
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
    if directory[0] != b'/' or directory[0] == b'.':
        directory = posixpath.join(comp_dir, directory)
    return posixpath.join(directory, file_entry.name).decode()

skip_target = set()

class arch_tools:
    def open_elf(elf_path):
        from arch.aarch64 import aarch64_tools
        from arch.riscv64 import riscv64_tools
        from arch.x86_64 import x86_64_tools
        f = open(elf_path, 'rb')
        elf = ELFFile(f)
        if elf['e_machine'] == 'EM_AARCH64':
            return aarch64_tools(elf_path)
        elif elf['e_machine'] == 'EM_X86_64':
            return x86_64_tools(elf_path)
        elif elf['e_machine'] == 'EM_RISCV':
            return riscv64_tools(elf_path)
        else:
            raise Exception('Unsupported ELF file')

    # Return {symbol_name: [{'addr': address, 'size': size, 'type': type, 'bind': bind, 'section': section_name}, ...]}
    def read_symbol_table(self):
        symbols = dict()
        for section in self.elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for sym in section.iter_symbols():
                name = sym.name
                if not name:
                    continue
                value = sym.entry['st_value']
                if value == 0:
                    continue
                if name not in symbols:
                    symbols[name] = []
                section_name = None
                shndx = sym.entry['st_shndx']
                if isinstance(shndx, int) and shndx < self.elf.num_sections():
                    section_name = self.elf.get_section(shndx).name
                symbols[name].append({
                    'addr': value,
                    'size': sym.entry['st_size'],
                    'type': sym.entry['st_info']['type'],
                    'bind': sym.entry['st_info']['bind'],
                    'section': section_name
                })
        return symbols

    def _decode_name(self, value):
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode(errors='replace')
        return str(value)

    def _get_die_name(self, die):
        if die is None:
            return None
        attrs = die.attributes
        for key in ('DW_AT_linkage_name', 'DW_AT_MIPS_linkage_name', 'DW_AT_name'):
            if key in attrs:
                name = self._decode_name(attrs[key].value)
                if name:
                    return name
        return None

    def _die_ranges(self, dwarfinfo, cu, die):
        attrs = die.attributes
        ranges = []

        if 'DW_AT_ranges' in attrs:
            range_lists = dwarfinfo.range_lists()
            offset = attrs['DW_AT_ranges'].value
            try:
                raw_ranges = range_lists.get_range_list_at_offset(offset, cu=cu)
            except TypeError:
                raw_ranges = range_lists.get_range_list_at_offset(offset)

            base_addr = 0
            if 'DW_AT_low_pc' in attrs:
                base_addr = attrs['DW_AT_low_pc'].value
            else:
                top_attrs = cu.get_top_DIE().attributes
                if 'DW_AT_low_pc' in top_attrs:
                    base_addr = top_attrs['DW_AT_low_pc'].value

            for entry in raw_ranges:
                if hasattr(entry, 'base_address'):
                    base_addr = entry.base_address
                    continue
                begin = entry.begin_offset
                end = entry.end_offset
                if getattr(entry, 'is_absolute', False):
                    ranges.append((begin, end))
                else:
                    ranges.append((base_addr + begin, base_addr + end))
            return ranges

        if 'DW_AT_low_pc' in attrs and 'DW_AT_high_pc' in attrs:
            low_pc = attrs['DW_AT_low_pc'].value
            high_pc_attr = attrs['DW_AT_high_pc']
            high_pc_class = describe_form_class(high_pc_attr.form)
            if high_pc_class == 'address':
                high_pc = high_pc_attr.value
            else:
                high_pc = low_pc + high_pc_attr.value
            return [(low_pc, high_pc)]

        return ranges

    # Return {symbol: [(start_pc, end_pc), ...]}
    # Keep original symbol name as-is (including '.' if present).
    def read_functions_ranges(self):
        res = dict()
        dwarfinfo = self.elf.get_dwarf_info()

        for CU in dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                if DIE.tag != 'DW_TAG_subprogram':
                    continue
                symbol_name = self._get_die_name(DIE)
                if symbol_name is None:
                    continue
                try:
                    ranges = self._die_ranges(dwarfinfo, CU, DIE)
                except Exception:
                    ranges = []
                if len(ranges) == 0:
                    continue
                if symbol_name not in res:
                    res[symbol_name] = []
                res[symbol_name].extend(ranges)

        symbol_table = self.read_symbol_table()
        for symbol_name, entries in symbol_table.items():
            for entry in entries:
                if entry.get('type') != 'STT_FUNC':
                    continue
                start = entry.get('addr', 0)
                size = entry.get('size', 0)
                if start == 0 or size == 0:
                    continue
                if symbol_name not in res:
                    res[symbol_name] = []
                res[symbol_name].append((start, start + size))

        return res

    # Read inline_info from DWARF.
    # Return {symbol: {inlined_symbol: [(offset_from_symbol_start, offset_from_symbol_end), ...], ...}, ...}
    # If symbol is specified, only matching symbols are returned.
    def read_inline_info(self):
        def add_inline_from_die(res, dwarfinfo, cu, die):
            if die.tag != 'DW_TAG_inlined_subroutine':
                return
            if 'DW_AT_abstract_origin' not in die.attributes:
                return
            try:
                origin_DIE = die.get_DIE_from_attribute('DW_AT_abstract_origin')
            except Exception:
                return
            origin_name = self._get_die_name(origin_DIE)
            if origin_name is None:
                return
            try:
                ranges = self._die_ranges(dwarfinfo, cu, die)
            except Exception:
                ranges = []
            res.append((origin_name, ranges))

        def normalize_ranges(ranges):
            uniq = sorted(set(ranges), key=lambda x: (x[0], x[1]))
            return uniq

        def overlap_offset(inline_range, func_range, base_addr):
            i_start, i_end = inline_range
            f_start, f_end = func_range
            ov_start = max(i_start, f_start)
            ov_end = min(i_end, f_end)
            if ov_start < ov_end:
                return (ov_start - base_addr, ov_end - base_addr)
            return None

        dwarfinfo = self.elf.get_dwarf_info()
        all_functions_ranges = self.read_functions_ranges()
        symbol_table = self.read_symbol_table()

        selected_functions = dict()
        for func_name, func_ranges in all_functions_ranges.items():
            if len(func_ranges) > 0:
                selected_functions[func_name] = func_ranges

        if len(selected_functions) == 0:
            return {}

        result = dict()
        for func_name, func_ranges in selected_functions.items():
            result[func_name] = dict()

        function_meta = []
        for func_name, func_ranges in selected_functions.items():
            symbol_ranges = []
            for entry in symbol_table.get(func_name, []):
                if entry.get('type') != 'STT_FUNC':
                    continue
                start = entry.get('addr', 0)
                size = entry.get('size', 0)
                if start == 0 or size == 0:
                    continue
                symbol_ranges.append((start, start + size))
            if len(symbol_ranges) > 0:
                normalized = normalize_ranges(symbol_ranges)
            else:
                normalized = normalize_ranges(func_ranges)
            function_base = min(map(lambda x: x[0], normalized))
            function_meta.append((func_name, normalized, function_base))

        function_range_meta = []
        for func_name, func_ranges, function_base in function_meta:
            for func_range in func_ranges:
                function_range_meta.append((func_range[0], func_range[1], func_name, function_base))
        function_range_meta.sort(key=lambda x: x[0])
        range_starts = [item[0] for item in function_range_meta]
        prefix_max_ends = []
        max_end_so_far = 0
        for _, end, _, _ in function_range_meta:
            max_end_so_far = max(max_end_so_far, end)
            prefix_max_ends.append(max_end_so_far)

        for CU in dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                if DIE.tag != 'DW_TAG_inlined_subroutine':
                    continue
                if 'DW_AT_abstract_origin' not in DIE.attributes:
                    continue
                try:
                    origin_DIE = DIE.get_DIE_from_attribute('DW_AT_abstract_origin')
                except Exception:
                    continue
                origin_name = self._get_die_name(origin_DIE)
                if origin_name is None:
                    continue
                try:
                    inline_ranges = self._die_ranges(dwarfinfo, CU, DIE)
                except Exception:
                    inline_ranges = []
                if len(inline_ranges) == 0:
                    continue

                for inline_range in inline_ranges:
                    i_start, i_end = inline_range
                    left_idx = bisect_right(prefix_max_ends, i_start)
                    right_idx = bisect_left(range_starts, i_end)

                    for idx in range(left_idx, right_idx):
                        f_start, f_end, func_name, function_base = function_range_meta[idx]
                        offset = overlap_offset(inline_range, (f_start, f_end), function_base)
                        if offset is None:
                            continue
                        if origin_name not in result[func_name]:
                            result[func_name][origin_name] = []
                        result[func_name][origin_name].append(offset)

        cleaned_result = dict()
        for func_name in result:
            if len(result[func_name]) == 0:
                continue
            cleaned_result[func_name] = dict()
            for inline_name, inline_offsets in result[func_name].items():
                cleaned_result[func_name][inline_name] = normalize_ranges(inline_offsets)

        return cleaned_result

    # Return ({filename: {line: line_num, col: col_num, pc: pc, is_stmt: is_stmt, basic_block: basic_block, end_sequence: end_sequence, prologue_end: prologue_end}})
    def read_dwarf(self):
        res = {}
        dwarfinfo = self.elf.get_dwarf_info()
        for CU in dwarfinfo.iter_CUs():
            top_DIE = CU.get_top_DIE()
            comp_dir = None
            if 'DW_AT_comp_dir' in top_DIE.attributes:
                comp_dir = top_DIE.attributes['DW_AT_comp_dir'].value
            line_program = dwarfinfo.line_program_for_CU(CU)
            if line_program is None:
                continue
            lp_entries = line_program.get_entries()
            for lpe in lp_entries:
                if not lpe.state:
                    continue
                filename = lpe_filename(line_program, lpe.state.file, comp_dir)
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
                res[filename].append({
                    'line': line_num,
                    'col': col_num,
                    'pc': pc,
                    'is_stmt': is_stmt,
                    'basic_block': basic_block,
                    'end_sequence': end_sequence,
                    'prologue_end': prologue_end
                })
        return res

    # Return {symbol_name: {'addr': address, 'instr': {addr: (hex_code, instr)}}}
    def read_textdump(self, objdump_opts=''):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            if os.system(f'{self.objdump} {objdump_opts} --visualize-jumps -d {self.elf_path} > {tmp.name}') != 0:
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
                            hex_code = int("".join(filter(lambda x: x in '0123456789abcdef', instr_tuple[1])), 16)
                            control_flow_dir = "".join(filter(lambda x: x in '-|+>X,\'', instr_tuple[1]))
                            rest = "\t".join(instr_tuple[2:])
                            symbols[current_symbol]['instr'][addr] = (hex_code, rest, control_flow_dir[-1] if len(control_flow_dir) > 0 else None)
            return symbols

    def is_control_flow_instr(self, instr):
        assert False, "Not implemented"

    def is_control_flow_end(self, instr):
        assert False, "Not implemented"

    # Return ({  symbol_name: { addr: address, bb: {bbstart: {addr: (hex_code, instr)}, ... }, ... }  }, {trans_dst: [trans_src]})
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
            insn_class = dict() # {bb_addr: {insn_class: count, ... }, ...}
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
                instr_class = self.get_insn_class_by_instr(cur_instr[addr])
                if instr_class:
                    if cur_bb not in insn_class:
                        insn_class[cur_bb] = dict()
                    for each_class in instr_class:
                        if each_class not in insn_class[cur_bb]:
                            insn_class[cur_bb][each_class] = 0
                        insn_class[cur_bb][each_class] += 1
                if addr in trans_out:
                    if len(cur_instr) > 0:
                        bb[cur_bb] = cur_instr
                    cur_instr = OrderedDict()
                    cur_bb = None
            if len(cur_instr) > 0:
                bb[cur_bb] = cur_instr
            res[sym] = {'addr': textdump[sym]['addr'], 'bb': bb, 'insn_class': insn_class}
        return (res, trans_edge)

    def get_insn_class_by_instr(self, instr):
        # Optional feature, return None if not implemented
        return None

    def get_insn_class_level_dict(self):
        # Optional feature, return None if not implemented
        return None
