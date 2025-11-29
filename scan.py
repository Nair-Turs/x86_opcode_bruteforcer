# x86opcode/scan.py

import itertools
import json
import re
from collections import defaultdict

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

"""All found opcodes are saved in two JSON files:
    ALL_opcodes.json - all found opcodes with corresponding mnemonics
    SAME_opcodes.json - different opcodes for the same mnemonics"""

SAME_JSON = "SAME_opcodes.json"
ALL_JSON = "ALL_opcodes.json"

# Normalization function for disassembly text
_ws_re = re.compile(r"\s+")  # Used to collapse multiple whitespace into single one
_safe_re = re.compile(r"[^0-9a-zA-Z._-]")  # Used to remove whitespaces


# Function to prepare data obtained from Capstone into the format easy to work with
def normalize_ins_text(mnemonic: str, op_str: str) -> str:
    """Produce canonical instruction text for comparison"""
    if op_str:
        text = f"{mnemonic}{op_str}"
    else:
        text = mnemonic
    text = text.strip().lower()
    text = _ws_re.sub(" ", text)  # collapse whitespace
    return text


# Using Capstone to get all opcode-mnemonic pairs
def disasm_full(blob: bytes):
    """Return disasm text for blob if Capstore decodes and consumes all bytes."""
    try:
        ins = next(md.disasm(blob, 0), None)
        if ins is None:
            return None
        if ins.size != len(blob):
            return None
        return normalize_ins_text(ins.mnemonic, ins.op_str)
    except Exception:
        return None


# Function to scan 1 and 2-byte sequences. Return mapping opcode_hex -> disasm_text.
def scan_1_2_bytes():
    """Scan 1 and 2-byte sequences. Return mapping opcode_hex -> disasm_text."""
    mapping = {}
    # 1-byte
    for b in range(0x00, 0x100):
        blob = bytes([b])
        txt = disasm_full(blob)
        if txt:
            mapping[blob.hex()] = txt
    # 2-byte
    for hi, lo in itertools.product(range(0x00, 0x100), range(0x00, 0x100)):
        blob = bytes([hi, lo])
        txt = disasm_full(blob)
        if txt:
            mapping[blob.hex()] = txt
    return mapping


# Function to group opcodes by disassembly text. Only opcodes with same mnemonic and operands returned.
def group_by_text(mapping: dict):
    """Group opcodes by disassembly text."""
    groups = defaultdict(list)
    for opcode_hex, text in mapping.items():
        groups[text].append(opcode_hex)
    # filter groups with more than one opcode
    multi = {txt: sorted(v) for txt, v in groups.items() if len(v) > 1}
    return multi


def export_results(groups: dict, mapping: dict):
    """Export results to JSON files: SAME_opcodes.json and ALL_opcodes.json"""
    with open(SAME_JSON, "w") as f:
        json.dump(groups, f, indent=2, sort_keys=True)
    with open(ALL_JSON, "w") as f:
        json.dump(mapping, f, indent=2, sort_keys=True)


def main():
    print("[*] Starting scan...")
    mapping = scan_1_2_bytes()
    print(f"[*] Valid disassemblies found: {len(mapping)}")
    groups = group_by_text(mapping)
    print(f"[*] Groups with more than one opcode: {len(groups)}")
    export_results(groups, mapping)
    print(f"[*] Results exported to JSON files: {SAME_JSON}, {ALL_JSON}")
    print("[*] Done!")
    print("[*] Example groups: (first 20):")
    for i, (text, opcodes) in enumerate(sorted(groups.items())):
        if i >= 20:
            break
        print(
            f"   {text:40s} -> {', '.join(opcodes[:10])}{'...' if len(opcodes) > 10 else ''}"
        )

    # If all opcodes needed, uncomment the following lines:
    # print("[*] All opcode groups:")
    # for instr, opcs in sorted(groups.items()):
    #     print(instr)
    #     for opc in opcs:
    #         print("   ", opc)
    #     print()


if __name__ == "__main__":
    main()
