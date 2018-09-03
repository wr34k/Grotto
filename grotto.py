#!/usr/bin/env python3

import sys
sys.dont_write_bytecode=True

from ELF.ELF import ELF
from ELF.ELFEnum import *

from argparse import ArgumentParser

prettyHex = lambda x: (hex(x) if isinstance(x, int) else ' '.join(hex(i) for i in x))

def get_args():
    p = ArgumentParser()
    p.add_argument("-b", "--binary", help="Binary to search", required=True)
    p.add_argument("-l", "--length", help="Minimum length of the codecave", default=64, type=int)
    return p.parse_args()

def get_caves(args, elf):
    in_cave     = False
    start_offset= 0x0
    size        = 0x0
    caves       = []

    for byte in range(len(elf.elf_file)):
        if elf.elf_file[byte] == 0x00:
            if not in_cave:
                in_cave=True
                start_offset = byte
                size += 0x1
            else:
                size += 0x1

        elif in_cave:
            in_cave = False
            if size >= args.length:
                caves += [(start_offset, size)]
            start_offset = size = 0x0

    return caves

def print_caves(caves, elf):
    idx=0
    for (start_offset,size) in caves:
        phid        = elf.get_prog_hdr_id_from_offset(start_offset)
        secid       = elf.get_section_id_from_offset(start_offset)

        cave_str = "="*50 + "\n"
        cave_str +=  f"{idx}> Start: {prettyHex(start_offset)}, End: {prettyHex(start_offset+size)}, Size: {prettyHex(size)} ({size})\n"
        if phid is not None:
            cave_str += f"\tProgram header> Type: {ProgramHeaderEnum.Type(elf.program_headers[phid].p_type).name}, Start: {prettyHex(elf.program_headers[phid].p_offset)}, End: {prettyHex(elf.program_headers[phid].p_offset + elf.program_headers[phid].p_filesz)}, Size: {prettyHex(elf.program_headers[phid].p_filesz)} ({elf.program_headers[phid].p_filesz}), Flags: {elf.program_headers[phid].prettyFlags()}\n"
        else:
            cave_str += "\tNot in any program header\n"
        if secid is not None:
            cave_str += f"\tSection header> Name: {elf.section_headers[secid].sh_name_str}, Start: {prettyHex(elf.section_headers[secid].sh_offset)}, End: {prettyHex(elf.section_headers[secid].sh_offset + elf.section_headers[secid].sh_size)}, Size: {prettyHex(elf.section_headers[secid].sh_size)} ({elf.section_headers[secid].sh_size}), Flags: {elf.section_headers[secid].prettyFlags()}"
        else:
            cave_str += "\t Not in any section header"

        print(cave_str)
        idx +=1

def main():
    args=get_args()
    with open(args.binary, "rb") as f:
        elf = ELF(f.read())

    print(f"Looking for caves in {args.binary} having min length of {args.length} bytes...")

    caves = get_caves(args, elf)
    print_caves(caves, elf)

    return

if __name__=='__main__':
    main()
