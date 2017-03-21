/*
The MIT License (MIT)

Copyright (c) 2013 Andrew Ruef

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef _NT_HEADERS
#define _NT_HEADERS
#include <cstdint>

#define _offset(t, f) ((std::uint32_t)(ptrdiff_t)&(((t*)0)->f))

//need to pack these structure definitions

//some constant definitions
namespace peparse {
const std::uint16_t MZ_MAGIC = 0x5A4D;
const std::uint32_t NT_MAGIC = 0x00004550;
const std::uint16_t NUM_DIR_ENTRIES = 16;
const std::uint16_t NT_OPTIONAL_32_MAGIC = 0x10B;
const std::uint16_t NT_OPTIONAL_64_MAGIC = 0x20B;
const std::uint16_t NT_SHORT_NAME_LEN = 8;
const std::uint16_t SYMTAB_RECORD_LEN = 18;
const std::uint16_t DIR_EXPORT = 0;
const std::uint16_t DIR_IMPORT = 1;
const std::uint16_t DIR_RESOURCE = 2;
const std::uint16_t DIR_EXCEPTION = 3;
const std::uint16_t DIR_SECURITY = 4;
const std::uint16_t DIR_BASERELOC = 5;
const std::uint16_t DIR_DEBUG = 6;
const std::uint16_t DIR_ARCHITECTURE = 7;
const std::uint16_t DIR_GLOBALPTR = 8;
const std::uint16_t DIR_TLS = 9;
const std::uint16_t DIR_LOAD_CONFIG = 10;
const std::uint16_t DIR_BOUND_IMPORT = 11;
const std::uint16_t DIR_IAT = 12;
const std::uint16_t DIR_DELAY_IMPORT = 13;
const std::uint16_t DIR_COM_DESCRIPTOR = 14;

const std::uint32_t IMAGE_SCN_TYPE_NO_PAD = 0x00000008;
const std::uint32_t IMAGE_SCN_CNT_CODE = 0x00000020;
const std::uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040; 
const std::uint32_t IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
const std::uint32_t IMAGE_SCN_LNK_OTHER = 0x00000100;
const std::uint32_t IMAGE_SCN_LNK_INFO = 0x00000200;
const std::uint32_t IMAGE_SCN_LNK_REMOVE = 0x00000800;
const std::uint32_t IMAGE_SCN_LNK_COMDAT = 0x00001000;
const std::uint32_t IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000;
const std::uint32_t IMAGE_SCN_GPREL = 0x00008000;
const std::uint32_t IMAGE_SCN_MEM_FARDATA = 0x00008000;
const std::uint32_t IMAGE_SCN_MEM_PURGEABLE = 0x00020000;
const std::uint32_t IMAGE_SCN_MEM_16BIT = 0x00020000;
const std::uint32_t IMAGE_SCN_MEM_LOCKED = 0x00040000;
const std::uint32_t IMAGE_SCN_MEM_PRELOAD = 0x00080000;
const std::uint32_t IMAGE_SCN_ALIGN_1BYTES = 0x00100000;
const std::uint32_t IMAGE_SCN_ALIGN_2BYTES = 0x00200000;
const std::uint32_t IMAGE_SCN_ALIGN_4BYTES = 0x00300000;
const std::uint32_t IMAGE_SCN_ALIGN_8BYTES = 0x00400000;
const std::uint32_t IMAGE_SCN_ALIGN_16BYTES = 0x00500000;
const std::uint32_t IMAGE_SCN_ALIGN_32BYTES = 0x00600000;
const std::uint32_t IMAGE_SCN_ALIGN_64BYTES = 0x00700000;
const std::uint32_t IMAGE_SCN_ALIGN_128BYTES = 0x00800000;
const std::uint32_t IMAGE_SCN_ALIGN_256BYTES = 0x00900000;
const std::uint32_t IMAGE_SCN_ALIGN_512BYTES = 0x00A00000;
const std::uint32_t IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000;
const std::uint32_t IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000;
const std::uint32_t IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000;
const std::uint32_t IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000;
const std::uint32_t IMAGE_SCN_ALIGN_MASK = 0x00F00000;
const std::uint32_t IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;
const std::uint32_t IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
const std::uint32_t IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
const std::uint32_t IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;
const std::uint32_t IMAGE_SCN_MEM_SHARED = 0x10000000;
const std::uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const std::uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
const std::uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;

// Symbol section number values
const std::int16_t IMAGE_SYM_UNDEFINED = 0;
const std::int16_t IMAGE_SYM_ABSOLUTE = -1;
const std::int16_t IMAGE_SYM_DEBUG = -2;

// Symbol table types
const std::uint16_t IMAGE_SYM_TYPE_NULL = 0;
const std::uint16_t IMAGE_SYM_TYPE_VOID = 1;
const std::uint16_t IMAGE_SYM_TYPE_CHAR = 2;
const std::uint16_t IMAGE_SYM_TYPE_SHORT = 3;
const std::uint16_t IMAGE_SYM_TYPE_INT = 4;
const std::uint16_t IMAGE_SYM_TYPE_LONG = 5;
const std::uint16_t IMAGE_SYM_TYPE_FLOAT = 6;
const std::uint16_t IMAGE_SYM_TYPE_DOUBLE = 7;
const std::uint16_t IMAGE_SYM_TYPE_STRUCT = 8;
const std::uint16_t IMAGE_SYM_TYPE_UNION = 9;
const std::uint16_t IMAGE_SYM_TYPE_ENUM = 10;
const std::uint16_t IMAGE_SYM_TYPE_MOE = 11;
const std::uint16_t IMAGE_SYM_TYPE_BYTE = 12;
const std::uint16_t IMAGE_SYM_TYPE_WORD = 13;
const std::uint16_t IMAGE_SYM_TYPE_UINT = 14;
const std::uint16_t IMAGE_SYM_TYPE_DWORD = 15;
const std::uint16_t IMAGE_SYM_DTYPE_NULL = 0;
const std::uint16_t IMAGE_SYM_DTYPE_POINTER = 1;
const std::uint16_t IMAGE_SYM_DTYPE_FUNCTION = 2;
const std::uint16_t IMAGE_SYM_DTYPE_ARRAY = 3;

// Symbol table storage classes
const std::uint8_t IMAGE_SYM_CLASS_END_OF_FUNCTION = -1;
const std::uint8_t IMAGE_SYM_CLASS_NULL = 0;
const std::uint8_t IMAGE_SYM_CLASS_AUTOMATIC = 1;
const std::uint8_t IMAGE_SYM_CLASS_EXTERNAL = 2;
const std::uint8_t IMAGE_SYM_CLASS_STATIC = 3;
const std::uint8_t IMAGE_SYM_CLASS_REGISTER = 4;
const std::uint8_t IMAGE_SYM_CLASS_EXTERNAL_DEF = 5;
const std::uint8_t IMAGE_SYM_CLASS_LABEL = 6;
const std::uint8_t IMAGE_SYM_CLASS_UNDEFINED_LABEL = 7;
const std::uint8_t IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 8;
const std::uint8_t IMAGE_SYM_CLASS_ARGUMENT = 9;
const std::uint8_t IMAGE_SYM_CLASS_STRUCT_TAG = 10;
const std::uint8_t IMAGE_SYM_CLASS_MEMBER_OF_UNION = 11;
const std::uint8_t IMAGE_SYM_CLASS_UNION_TAG = 12;
const std::uint8_t IMAGE_SYM_CLASS_TYPE_DEFINITION = 13;
const std::uint8_t IMAGE_SYM_CLASS_UNDEFINED_STATIC = 14;
const std::uint8_t IMAGE_SYM_CLASS_ENUM_TAG = 15;
const std::uint8_t IMAGE_SYM_CLASS_MEMBER_OF_ENUM = 16;
const std::uint8_t IMAGE_SYM_CLASS_REGISTER_PARAM = 17;
const std::uint8_t IMAGE_SYM_CLASS_BIT_FIELD = 18;
const std::uint8_t IMAGE_SYM_CLASS_BLOCK = 100;
const std::uint8_t IMAGE_SYM_CLASS_FUNCTION = 101;
const std::uint8_t IMAGE_SYM_CLASS_END_OF_STRUCT = 102;
const std::uint8_t IMAGE_SYM_CLASS_FILE = 103;
const std::uint8_t IMAGE_SYM_CLASS_SECTION = 104;
const std::uint8_t IMAGE_SYM_CLASS_WEAK_EXTERNAL = 105;
const std::uint8_t IMAGE_SYM_CLASS_CLR_TOKEN = 107;

struct dos_header {
    std::uint16_t   e_magic;           
    std::uint16_t   e_cblp;            
    std::uint16_t   e_cp;              
    std::uint16_t   e_crlc;            
    std::uint16_t   e_cparhdr;         
    std::uint16_t   e_minalloc;        
    std::uint16_t   e_maxalloc;        
    std::uint16_t   e_ss;              
    std::uint16_t   e_sp;              
    std::uint16_t   e_csum;            
    std::uint16_t   e_ip;              
    std::uint16_t   e_cs;              
    std::uint16_t   e_lfarlc; 
    std::uint16_t   e_ovno;            
    std::uint16_t   e_res[4];          
    std::uint16_t   e_oemid;           
    std::uint16_t   e_oeminfo; 
    std::uint16_t   e_res2[10];        
    std::uint32_t   e_lfanew;          
};

struct file_header {
    std::uint16_t   Machine;
    std::uint16_t   NumberOfSections;
    std::uint32_t   TimeDateStamp;
    std::uint32_t   PointerToSymbolTable;
    std::uint32_t   NumberOfSymbols;
    std::uint16_t   SizeOfOptionalHeader;
    std::uint16_t   Characteristics;
};

struct data_directory {
  std::uint32_t VirtualAddress;
  std::uint32_t Size;
};

struct optional_header_32 {
  std::uint16_t   Magic;
  std::uint8_t    MajorLinkerVersion;
  std::uint8_t    MinorLinkerVersion;
  std::uint32_t   SizeOfCode;
  std::uint32_t   SizeOfInitializedData;
  std::uint32_t   SizeOfUninitializedData;
  std::uint32_t   AddressOfEntryPoint;
  std::uint32_t   BaseOfCode;
  std::uint32_t   BaseOfData;
  std::uint32_t   ImageBase;
  std::uint32_t   SectionAlignment;
  std::uint32_t   FileAlignment;
  std::uint16_t   MajorOperatingSystemVersion;
  std::uint16_t   MinorOperatingSystemVersion;
  std::uint16_t   MajorImageVersion;
  std::uint16_t   MinorImageVersion;
  std::uint16_t   MajorSubsystemVersion;
  std::uint16_t   MinorSubsystemVersion;
  std::uint32_t   Win32VersionValue;
  std::uint32_t   SizeOfImage;
  std::uint32_t   SizeOfHeaders;
  std::uint32_t   CheckSum;
  std::uint16_t   Subsystem;
  std::uint16_t   DllCharacteristics;
  std::uint32_t   SizeOfStackReserve;
  std::uint32_t   SizeOfStackCommit;
  std::uint32_t   SizeOfHeapReserve;
  std::uint32_t   SizeOfHeapCommit;
  std::uint32_t   LoaderFlags;
  std::uint32_t   NumberOfRvaAndSizes;
  data_directory    DataDirectory[NUM_DIR_ENTRIES];
};

/*
 * This is used for PE32+ binaries. It is similar to optional_header_32
 * except some fields don't exist here (BaseOfData), and others are bigger.
 */
struct optional_header_64 {
  std::uint16_t   Magic;
  std::uint8_t    MajorLinkerVersion;
  std::uint8_t    MinorLinkerVersion;
  std::uint32_t   SizeOfCode;
  std::uint32_t   SizeOfInitializedData;
  std::uint32_t   SizeOfUninitializedData;
  std::uint32_t   AddressOfEntryPoint;
  std::uint32_t   BaseOfCode;
  std::uint64_t   ImageBase;
  std::uint32_t   SectionAlignment;
  std::uint32_t   FileAlignment;
  std::uint16_t   MajorOperatingSystemVersion;
  std::uint16_t   MinorOperatingSystemVersion;
  std::uint16_t   MajorImageVersion;
  std::uint16_t   MinorImageVersion;
  std::uint16_t   MajorSubsystemVersion;
  std::uint16_t   MinorSubsystemVersion;
  std::uint32_t   Win32VersionValue;
  std::uint32_t   SizeOfImage;
  std::uint32_t   SizeOfHeaders;
  std::uint32_t   CheckSum;
  std::uint16_t   Subsystem;
  std::uint16_t   DllCharacteristics;
  std::uint64_t   SizeOfStackReserve;
  std::uint64_t   SizeOfStackCommit;
  std::uint64_t   SizeOfHeapReserve;
  std::uint64_t   SizeOfHeapCommit;
  std::uint32_t   LoaderFlags;
  std::uint32_t   NumberOfRvaAndSizes;
  data_directory    DataDirectory[NUM_DIR_ENTRIES];
};

struct nt_header_32 {
  std::uint32_t     Signature;
  file_header         FileHeader;
  optional_header_32  OptionalHeader;
  optional_header_64  OptionalHeader64;
  std::uint16_t     OptionalMagic;
};

/*
 * This structure is only used to know how far to move the offset
 * when parsing resources. The data is stored in a resource_dir_entry
 * struct but that also has extra information used in the parsing which
 * causes the size to be inaccurate.
 */
struct resource_dir_entry_sz {
  std::uint32_t ID;
  std::uint32_t RVA;
};

struct resource_dir_entry {
  inline resource_dir_entry(void)
      : ID(0),
        RVA(0),
        type(0),
        name(0),
        lang(0) {}

  std::uint32_t ID;
  std::uint32_t RVA;
  std::uint32_t type;
  std::uint32_t name;
  std::uint32_t lang;
  std::string     type_str;
  std::string     name_str;
  std::string     lang_str;
};

struct resource_dir_table {
  std::uint32_t Characteristics;
  std::uint32_t TimeDateStamp;
  std::uint16_t MajorVersion;
  std::uint16_t MinorVersion;
  std::uint16_t NameEntries;
  std::uint16_t IDEntries;
};

struct resource_dat_entry {
  std::uint32_t RVA;
  std::uint32_t size;
  std::uint32_t codepage;
  std::uint32_t reserved;
};

struct image_section_header {
    std::uint8_t    Name[NT_SHORT_NAME_LEN];
    union {
            std::uint32_t   PhysicalAddress;
            std::uint32_t   VirtualSize;
    } Misc;
    std::uint32_t   VirtualAddress;
    std::uint32_t   SizeOfRawData;
    std::uint32_t   PointerToRawData;
    std::uint32_t   PointerToRelocations;
    std::uint32_t   PointerToLinenumbers;
    std::uint16_t   NumberOfRelocations;
    std::uint16_t   NumberOfLinenumbers;
    std::uint32_t   Characteristics;
};

struct import_dir_entry {
  std::uint32_t LookupTableRVA;
  std::uint32_t TimeStamp;
  std::uint32_t ForwarderChain;
  std::uint32_t NameRVA;
  std::uint32_t AddressRVA;
};

struct export_dir_table {
  std::uint32_t ExportFlags;
  std::uint32_t TimeDateStamp;
  std::uint16_t MajorVersion;
  std::uint16_t MinorVersion;
  std::uint32_t NameRVA;
  std::uint32_t OrdinalBase;
  std::uint32_t AddressTableEntries;
  std::uint32_t NumberOfNamePointers;
  std::uint32_t ExportAddressTableRVA;
  std::uint32_t NamePointerRVA;
  std::uint32_t OrdinalTableRVA;
};

enum reloc_type {
  ABSOLUTE = 0,
  HIGH = 1,
  LOW = 2,
  HIGHLOW = 3,
  HIGHADJ = 4,
  MIPS_JMPADDR = 5,
  MIPS_JMPADDR16 = 9,
  IA64_IMM64 = 9,
  DIR64 = 10
};

struct reloc_block {
  std::uint32_t PageRVA;
  std::uint32_t BlockSize;
};
} // namespace peparse

#endif
