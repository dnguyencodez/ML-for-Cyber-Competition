import re
import lief
import math
import hashlib
import pprint

"""
NOTES:
- maybe add rich header raw data later on (describes program's compile location)
"""

class AttributeExtractor():
    def __init__(self, pe_bytes) -> None:
        self.pe_bytes = pe_bytes
        # use below when processing HTTP requests
        self.pe = lief.PE.parse(list(pe_bytes))
        self.attributes = {}

    # compute import hash (imphash) to identify similar malware
    # def get_imphash(self):
    #     return self.pe.get_imphash()

    # extract entropy
    def extract_entropy(self):
        if not self.pe_bytes:
            return 0
        entropy=0
        for x in range(256):
            p_x = float(self.pe_bytes.count(bytes(x)))/len(self.pe_bytes)
            if p_x>0:
                entropy += - p_x*math.log(p_x, 2)
        return entropy
    
    # extract DLLs and corresponding API calls
    def extract_dlls_and_api_calls(self):
        self.attributes["DLLs_and_APIs"] = {}

        for imported_lib in self.pe.imports:
            lib_name = imported_lib.name
            api_functions = [entry.name for entry in imported_lib.entries if not entry.is_ordinal]
            self.attributes["DLLs_and_APIs"][lib_name] = api_functions

    # extract PE header fields (file header, and optional header)
    def extract_header_fields(self):

        # extract DOS header fields
        dos_header = self.pe.dos_header
        self.attributes["e_magic"] = dos_header.magic
        self.attributes["Checksum_DOS"] = dos_header.checksum
        self.attributes["oem_id"] = dos_header.oem_id
        self.attributes["oem_info"] = dos_header.oem_info
        # look more into dos header later

        # extracting PE file header fields
        file_header = self.pe.header
        self.attributes["Machine"] = file_header.machine
        self.attributes["NumberOfSections"] = file_header.numberof_sections
        self.attributes["TimeDateStamp"] = file_header.time_date_stamps
        self.attributes["PointerToSymbolTable"] = file_header.pointerto_symbol_table
        self.attributes["NumberOfSymbols"] = file_header.numberof_symbols
        self.attributes["SizeOfOptionalHeader"] = file_header.sizeof_optional_header
        self.attributes["Characteristics"] = " ".join([str(c).replace("HEADER_CHARACTERISTICS.","") for c in file_header.characteristics_list])

        # extract optional header fields
        optional_header = self.pe.optional_header
        self.attributes.update({
            "Magic": optional_header.magic,
            "MajorLinkerVersion": optional_header.major_linker_version,
            "MinorLinkerVersion": optional_header.minor_linker_version,
            "SizeOfCode": optional_header.sizeof_code,
            "SizeOfInitializedData": optional_header.sizeof_initialized_data,
            "SizeOfUninitializedData": optional_header.sizeof_uninitialized_data,
            "AddressOfEntryPoint": optional_header.addressof_entrypoint,
            "BaseOfCode": optional_header.baseof_code,
            "ImageBase": optional_header.imagebase,
            "SectionAlignment": optional_header.section_alignment,
            "FileAlignment": optional_header.file_alignment,
            "MajorOperatingSystemVersion": optional_header.major_operating_system_version,
            "MinorOperatingSystemVersion": optional_header.minor_operating_system_version,
            "MajorImageVersion": optional_header.major_image_version,
            "MinorImageVersion": optional_header.minor_image_version,
            "MajorSubsystemVersion": optional_header.major_subsystem_version,
            "MinorSubsystemVersion": optional_header.minor_subsystem_version,
            "Win32VersionValue": optional_header.win32_version_value,
            "SizeOfImage": optional_header.sizeof_image,
            "SizeOfHeaders": optional_header.sizeof_headers,
            "CheckSum": optional_header.checksum,
            "Subsystem": optional_header.subsystem,
            "DllCharacteristics": " ".join([str(d).replace("DLL_CHARACTERISTICS.", "") for d in optional_header.dll_characteristics_lists]),
            "SizeOfStackReserve": optional_header.sizeof_stack_reserve,
            "SizeOfStackCommit": optional_header.sizeof_stack_commit,
            "SizeOfHeapReserve": optional_header.sizeof_heap_reserve,
            "SizeOfHeapCommit": optional_header.sizeof_heap_commit,
            "LoaderFlags": optional_header.loader_flags,
            "NumberOfRvaAndSizes": optional_header.numberof_rva_and_size
        })


    # extract PE sections fields
    def extract_sections_fields(self):
        self.attributes["Sections"] = {}
        sections = ['.text', '.data', '.rdata', '.bss', '.idata', '.edata', '.rsrc', '.reloc', '.tls']

        for s in sections:
            currSection = self.pe.get_section(s)

            if not currSection:
                continue
            
            self.attributes["Sections"][s] = {
                # "Name": currSection.name,
                "Misc_VirtualSize": currSection.virtual_size,
                "VirtualAddress": currSection.virtual_address,
                "SizeOfRawData": currSection.size,
                "PointerToRawData": currSection.pointerto_raw_data,
                "PointerToRelocations": currSection.pointerto_relocation,
                "PointerToLineNumbers": currSection.pointerto_line_numbers,
                "NumberOfRelocations": currSection.numberof_relocations,
                "NumberofLineNumbers": currSection.numberof_line_numbers,
                "Characteristics": " ".join([str(c).replace("SECTION_CHARACTERISTICS.", "") for c in currSection.characteristics_lists]),
                
                # the following help detect obfuscation and packing
                "Hashes": hashlib.md5(currSection.content).hexdigest(),
                "Entropy": currSection.entropy
            }




# Testing attribute extractor
if __name__ == '__main__':
    pe_file_path = '../DikeDataset/files/malware/0a266ad12d079323f2170811f5195fb51893d5bcbc915e758dc10c0f876d5fb5.exe'

    with open(pe_file_path, "rb") as file:
        pe_bytes = file.read()

    test_attribute_extractor = AttributeExtractor(pe_bytes)

    test_attribute_extractor.extract_dlls_and_api_calls()
    test_attribute_extractor.extract_header_fields()
    test_attribute_extractor.extract_sections_fields()
    # imphash = test_attribute_extractor.get_imphash()

    pprint.pprint(test_attribute_extractor.attributes)

    # print(test_attribute_extractor.pe.has_imports)
    # print(dll_list)

