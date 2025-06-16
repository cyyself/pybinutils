#!/usr/bin/env python3

from arch.arch import arch_tools, insn_db_path
from elftools.elf.elffile import ELFFile
import tempfile
import os
import json
import sys

xlate_isa_type = {
    "3DNOW": ["3dnow"],
    "3DNOW_PREFETCH": ["prfchw"],
    "ADOX_ADCX": ["adx"],
    "AES": ["aes"],
    "AMD": None,
    "AMD_INVLPGB": None,
    "AMX_TILE": {
        "AMX_AVX512": ["amx-avx512"],
        "AMX_BF16": ["amx-bf16"],
        "AMX_COMPLEX": ["amx-complex"],
        "AMX_FP16": ["amx-fp16"],
        "AMX_FP8": ["amx-fp8"],
        "AMX_INT8": ["amx-int8"],
        "AMX_MOVRS": ["amx-movrs"],
        "AMX_TF32": ["amx-tf32"],
        "AMX_TILE": ["amx-tile"],
        "AMX_TRANSPOSE": ["amx-transpose"],
        "AMX_TRANSPOSE_BF16": ["amx-transpose"],
        "AMX_TRANSPOSE_COMPLEX": ["amx-transpose", "amx-complex"],
        "AMX_TRANSPOSE_FP16": ["amx-transpose", "amx-fp16"],
        "AMX_TRANSPOSE_MOVRS": ["amx-transpose", "amx-movrs"],
        "AMX_TRANSPOSE_TF32": ["amx-transpose", "amx-tf32"]
    },
    "APXEVEX": {
        "APX_F": ["apxf"],
        "APX_F_ADX": ["apxf", "adx"],
        "APX_F_AMX": ["apxf", "amx-tile"],
        "APX_F_AMX_MOVRS": ["apxf", "amx-movrs"],
        "APX_F_AMX_TRANSPOSE": ["apxf", "amx-transpose"],
        "APX_F_AMX_TRANSPOSE_MOVRS": ["apxf", "amx-transpose", "amx-movrs"],
        "APX_F_BMI1": ["apxf", "bmi"],
        "APX_F_BMI2": ["apxf", "bmi2"],
        "APX_F_CET": ["apxf", "shstk"],
        "APX_F_CMPCCXADD": ["apxf", "cmpccxadd"],
        "APX_F_ENQCMD": ["apxf", "enqcmd"],
        "APX_F_INVPCID": None,
        "APX_F_KOPB": ["apxf"],
        "APX_F_KOPD": ["apxf"],
        "APX_F_KOPQ": ["apxf"],
        "APX_F_KOPW": ["apxf"],
        "APX_F_LZCNT": ["apxf", "lzcnt"],
        "APX_F_MOVBE": ["apxf", "movbe"],
        "APX_F_MOVDIR64B": ["apxf", "movdir64b"],
        "APX_F_MOVDIRI": ["apxf", "movdiri"],
        "APX_F_MOVRS": ["apxf", "movrs"],
        "APX_F_MSR_IMM": None,
        "APX_F_POPCNT": ["apxf", "popcnt"],
        "APX_F_RAO_INT": ["apxf", "raoint"],
        "APX_F_USER_MSR": ["apxf", "usermsr"],
        "APX_F_VMX": None
    },
    "APXLEGACY": ["apxf"],
    "AVX": ["avx"],
    "AVX2": ["avx2"],
    "AVX2GATHER": ["avx2"],
    "AVX512EVEX": {
        "AVX10_2_BF16_128": ["avx10.2"],
        "AVX10_2_BF16_256": ["avx10.2"],
        "AVX10_2_BF16_512": ["avx10.2"],
        "AVX10_2_BF16_SCALAR": ["avx10.2"],
        "AVX10_MOVRS_128": ["avx10.2", "movrs"],
        "AVX10_MOVRS_256": ["avx10.2", "movrs"],
        "AVX10_MOVRS_512": ["avx10.2", "movrs"],
        "AVX512BW_128": ["avx512bw"],
        "AVX512BW_128N": ["avx512bw"],
        "AVX512BW_256": ["avx512bw"],
        "AVX512BW_512": ["avx512bw"],
        "AVX512CD_128": ["avx512cd"],
        "AVX512CD_256": ["avx512cd"],
        "AVX512CD_512": ["avx512cd"],
        "AVX512DQ_128": ["avx512dq"],
        "AVX512DQ_128N": ["avx512dq"],
        "AVX512DQ_256": ["avx512dq"],
        "AVX512DQ_512": ["avx512dq"],
        "AVX512DQ_SCALAR": ["avx512dq"],
        "AVX512ER_512": None,
        "AVX512ER_SCALAR": None,
        "AVX512F_128": ["avx512f"],
        "AVX512F_128N": ["avx512f"],
        "AVX512F_256": ["avx512f"],
        "AVX512F_512": ["avx512f"],
        "AVX512F_SCALAR": ["avx512f"],
        "AVX512PF_512": None,
        "AVX512_4FMAPS_512": None,
        "AVX512_4FMAPS_SCALAR": None,
        "AVX512_4VNNIW_512": None,
        "AVX512_BF16_128": ["avx512bf16"],
        "AVX512_BF16_256": ["avx512bf16"],
        "AVX512_BF16_512": ["avx512bf16"],
        "AVX512_BITALG_128": ["avx512bitalg"],
        "AVX512_BITALG_256": ["avx512bitalg"],
        "AVX512_BITALG_512": ["avx512bitalg"],
        "AVX512_COM_EF_SCALAR": ["avx10.2"],
        "AVX512_FP16_128": ["avx512fp16"],
        "AVX512_FP16_128N": ["avx512fp16"],
        "AVX512_FP16_256": ["avx512fp16"],
        "AVX512_FP16_512": ["avx512fp16"],
        "AVX512_FP16_CONVERT_128": ["avx10.2"],
        "AVX512_FP16_CONVERT_256": ["avx10.2"],
        "AVX512_FP16_CONVERT_512": ["avx10.2"],
        "AVX512_FP16_SCALAR": ["avx512fp16"],
        "AVX512_FP8_CONVERT_128": ["avx10.2"],
        "AVX512_FP8_CONVERT_256": ["avx10.2"],
        "AVX512_FP8_CONVERT_512": ["avx10.2"],
        "AVX512_GFNI_128": ["avx512f", "gfni"],
        "AVX512_GFNI_256": ["avx512f", "gfni"],
        "AVX512_GFNI_512": ["avx512f", "gfni"],
        "AVX512_IFMA_128": ["avx512ifma"],
        "AVX512_IFMA_256": ["avx512ifma"],
        "AVX512_IFMA_512": ["avx512ifma"],
        "AVX512_MEDIAX_128": ["avx10.2"],
        "AVX512_MEDIAX_256": ["avx10.2"],
        "AVX512_MEDIAX_512": ["avx10.2"],
        "AVX512_MINMAX_128": ["avx10.2"],
        "AVX512_MINMAX_256": ["avx10.2"],
        "AVX512_MINMAX_512": ["avx10.2"],
        "AVX512_MINMAX_SCALAR": ["avx10.2"],
        "AVX512_MOVZXC_128": ["avx10.2"],
        "AVX512_SAT_CVT_128": ["avx10.2"],
        "AVX512_SAT_CVT_256": ["avx10.2"],
        "AVX512_SAT_CVT_512": ["avx10.2"],
        "AVX512_SAT_CVT_DS_128": ["avx10.2"],
        "AVX512_SAT_CVT_DS_256": ["avx10.2"],
        "AVX512_SAT_CVT_DS_512": ["avx10.2"],
        "AVX512_SAT_CVT_DS_SCALAR": ["avx10.2"],
        "AVX512_VAES_128": ["avx512f", "vaes"],
        "AVX512_VAES_256": ["avx512f", "vaes"],
        "AVX512_VAES_512": ["avx512f", "vaes"],
        "AVX512_VBMI2_128": ["avx512vbmi2"],
        "AVX512_VBMI2_256": ["avx512vbmi2"],
        "AVX512_VBMI2_512": ["avx512vbmi2"],
        "AVX512_VBMI_128": ["avx512vbmi"],
        "AVX512_VBMI_256": ["avx512vbmi"],
        "AVX512_VBMI_512": ["avx512vbmi"],
        "AVX512_VNNI_128": ["avx512vnni"],
        "AVX512_VNNI_256": ["avx512vnni"],
        "AVX512_VNNI_512": ["avx512vnni"],
        "AVX512_VNNI_FP16_128": ["avx10.2"],
        "AVX512_VNNI_FP16_256": ["avx10.2"],
        "AVX512_VNNI_FP16_512": ["avx10.2"],
        "AVX512_VNNI_INT16_128": ["avx10.2"],
        "AVX512_VNNI_INT16_256": ["avx10.2"],
        "AVX512_VNNI_INT16_512": ["avx10.2"],
        "AVX512_VNNI_INT8_128": ["avx10.2"],
        "AVX512_VNNI_INT8_256": ["avx10.2"],
        "AVX512_VNNI_INT8_512": ["avx10.2"],
        "AVX512_VP2INTERSECT_128": ["avx512vp2intersect"],
        "AVX512_VP2INTERSECT_256": ["avx512vp2intersect"],
        "AVX512_VP2INTERSECT_512": ["avx512vp2intersect"],
        "AVX512_VPCLMULQDQ_128": ["avx512f", "vpclmulqdq"],
        "AVX512_VPCLMULQDQ_256": ["avx512f", "vpclmulqdq"],
        "AVX512_VPCLMULQDQ_512": ["avx512f", "vpclmulqdq"],
        "AVX512_VPOPCNTDQ_128": ["avx512vpopcntdq"],
        "AVX512_VPOPCNTDQ_256": ["avx512vpopcntdq"],
        "AVX512_VPOPCNTDQ_512": ["avx512vpopcntdq"],
        "SM4_128": ["sm4"],
        "SM4_256": ["sm4"],
        "SM4_512": ["sm4"]
    },
    "AVX512VEX": {
        "AVX512BW_KOPD": ["avx512bw"],
        "AVX512BW_KOPQ": ["avx512bw"],
        "AVX512DQ_KOPB": ["avx512dq"],
        "AVX512DQ_KOPW": ["avx512dq"],
        "AVX512F_KOPW": ["avx512f"]
    },
    "AVXAES": ["vaes"],
    "AVX_IFMA": ["avxifma"],
    "AVX_NE_CONVERT": ["avxneconvert"],
    "AVX_VNNI": ["avxvnni"],
    "AVX_VNNI_INT16": ["avxvnniint16"],
    "AVX_VNNI_INT8": ["avxvnniint8"],
    "BASE": None,
    "BMI1": ["bmi"],
    "BMI2": ["bmi2"],
    "CET": ["shstk"],
    "CLDEMOTE": ["cldemote"],
    "CLFLUSHOPT": ["clflushopt"],
    "CLFSH": None,
    "CLWB": ["clwb"],
    "CLZERO": ["clzero"],
    "CMPCCXADD": "cmpccxadd",
    "ENQCMD": ["enqcmd"],
    "F16C": ["f16c"],
    "FMA": ["fma"],
    "FMA4": ["fma4"],
    "FRED": None,
    "GFNI": ["gfni"],
    "HRESET": ["hreset"],
    "ICACHE_PREFETCH": ["prefetchi"],
    "KEYLOCKER": "kl",
    "KEYLOCKER_WIDE": "widekl",
    "LKGS": None,
    "LONGMODE": {
        "CMPXCHG16B": ["cmpxchg16b"],
        "LONGMODE": None
    },
    "LZCNT": ["lzcnt"],
    "MCOMMIT": None,
    "MMX": ["mmx"],
    "MONITOR": ["mwait"],
    "MONITORX": ["mwaitx"],
    "MOVBE": ["movbe"],
    "MOVDIR": {
        "MOVDIR64B": ["movdir64b"],
        "MOVDIRI": ["movdiri"]
    },
    "MOVRS": ["movrs"],
    "MPX": None,
    "MSRLIST": None,
    "MSR_IMM": None,
    "PAUSE": ["sse2"],
    "PBNDKB": None,
    "PCLMULQDQ": ["pclmul"],
    "PCONFIG": ["pconfig"],
    "PKU": ["pku"],
    "PREFETCHWT1": ["prefetchwt1"],
    "PTWRITE": ["ptwrite"],
    "RAO_INT": ["raoint"],
    "RDPID": ["rdpid"],
    "RDPRU": None,
    "RDRAND": ["rdrnd"],
    "RDSEED": ["rdseed"],
    "RDTSCP": None,
    "RDWRFSGS": None,
    "RTM": ["rtm"],
    "SERIALIZE": ["serialize"],
    "SGX": ["sgx"],
    "SGX_ENCLV": ["sgx"],
    "SHA": ["sha"],
    "SHA512": ["sha512"],
    "SM3": ["sm3"],
    "SM4": ["sm4"],
    "SMAP": None,
    "SMX": None,
    "SNP": None,
    "SSE": ["sse"],
    "SSE2": ["sse2"],
    "SSE3": ["sse3"],
    "SSE4": ["sse4"],
    "SSE4a": ["sse4a"],
    "SSSE3": ["ssse3"],
    "SVM": None,
    "TBM": ["tbm"],
    "TDX": None,
    "TSX_LDTRK": ["tsxldtrk"],
    "UINTR":  ["uintr"],
    "USER_MSR": ["usermsr"],
    "VAES": ["vaes"],
    "VIA_PADLOCK_AES": None,
    "VIA_PADLOCK_MONTMUL": None,
    "VIA_PADLOCK_RNG": None,
    "VIA_PADLOCK_SHA": None,
    "VMFUNC": None,
    "VPCLMULQDQ": ["vpclmulqdq"],
    "VTX": None,
    "WAITPKG": ["waitpkg"],
    "WBNOINVD": ["wbnoinvd"],
    "WRMSRNS": None,
    "X87": None,
    "XOP": ["xop"],
    "XSAVE": ["xsave"],
    "XSAVEC": ["xsavec"],
    "XSAVEOPT": ["xsaveopt"],
    "XSAVES": ["xsaves"]
}

def translate_isa_type(extension, isa_set):
    next_key = xlate_isa_type[extension]
    if next_key is None:
        return []
    elif isinstance(next_key, list):
        return next_key
    next_key = next_key[isa_set]
    if next_key is None:
        return []
    else:
        return next_key

class x86_64_tools(arch_tools):
    def __init__(self, elf_path, ldflags='-no-pie', ld='x86_64-linux-gnu-ld', objdump='x86_64-linux-gnu-objdump', xed_cmd='xed'):
        self.elf_path = elf_path
        self.objdump = objdump
        self.xed_cmd = xed_cmd
        self.openfiles = []
        self.tmpfiles = []
        f = open(self.elf_path, 'rb')
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
        self.xed_result = None
    
    def __init_xed(self):
        self.xed_result = dict()
        with tempfile.NamedTemporaryFile() as tf:
            if os.system(f'{self.xed_cmd} -64 -isa-set -i {self.elf_path} > {tf.name} 2>/dev/null') != 0:
                raise Exception('Failed to disassemble ELF file')
            with open(tf.name, 'r') as xf:
                xed_lines = xf.readlines()
                for line in xed_lines:
                    if line.startswith('XDIS '):
                        cur_line = line.split(': ')
                        pc = int(cur_line[0][5:], 16)
                        instr_info = cur_line[1].strip().split()
                        iclass = instr_info[0]
                        extension = instr_info[1]
                        isa_set = instr_info[2]
                        instr_hex = instr_info[3]
                        instr = int(instr_hex, 16)
                        isa = translate_isa_type(extension, isa_set)
                        self.xed_result[instr] = isa

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

    def get_insn_class_by_instr(self, instr):
        if self.xed_result is None:
            self.__init_xed()
        return self.xed_result.get(instr[0], None)
