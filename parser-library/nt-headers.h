#ifndef _NT_HEADERS
#define _NT_HEADERS
#include <boost/cstdint.hpp>

#define _offset(t, f) ((boost::uint32_t)(ptrdiff_t)&(((t*)0)->f))

//need to pack these structure definitions

//some constant definitions
const boost::uint16_t MZ_MAGIC = 0x5A4D;
const boost::uint16_t NUM_DIR_ENTRIES = 16;

struct dos_header {
    boost::uint16_t   e_magic;           
    boost::uint16_t   e_cblp;            
    boost::uint16_t   e_cp;              
    boost::uint16_t   e_crlc;            
    boost::uint16_t   e_cparhdr;         
    boost::uint16_t   e_minalloc;        
    boost::uint16_t   e_maxalloc;        
    boost::uint16_t   e_ss;              
    boost::uint16_t   e_sp;              
    boost::uint16_t   e_csum;            
    boost::uint16_t   e_ip;              
    boost::uint16_t   e_cs;              
    boost::uint16_t   e_lfarlc; 
    boost::uint16_t   e_ovno;            
    boost::uint16_t   e_res[4];          
    boost::uint16_t   e_oemid;           
    boost::uint16_t   e_oeminfo; 
    boost::uint16_t   e_res2[10];        
    boost::uint32_t   e_lfanew;          
};

struct file_header {
    boost::uint16_t   Machine;
    boost::uint16_t   NumberOfSections;
    boost::uint32_t   TimeDateStamp;
    boost::uint32_t   PointerToSymbolTable;
    boost::uint32_t   NumberOfSymbols;
    boost::uint16_t   SizeOfOptionalHeader;
    boost::uint16_t   Characteristics;
};

struct data_directory {
  boost::uint32_t VirtualAddress;
  boost::uint32_t Size;
};

struct optional_header_32 {
  boost::uint16_t   Magic;
  boost::uint8_t    MajorLinkerVersion;
  boost::uint8_t    MinorLinkerVersion;
  boost::uint32_t   SizeOfCode;
  boost::uint32_t   SizeOfInitializedData;
  boost::uint32_t   SizeOfUninitializedData;
  boost::uint32_t   AddressOfEntryPoint;
  boost::uint32_t   BaseOfCode;
  boost::uint32_t   BaseOfData;
  boost::uint32_t   ImageBase;
  boost::uint32_t   SectionAlignment;
  boost::uint32_t   FileAlignment;
  boost::uint16_t   MajorOperatingSystemVersion;
  boost::uint16_t   MinorOperatingSystemVersion;
  boost::uint16_t   MajorImageVersion;
  boost::uint16_t   MinorImageVersion;
  boost::uint16_t   MajorSubsystemVersion;
  boost::uint16_t   MinorSubsystemVersion;
  boost::uint32_t   Win32VersionValue;
  boost::uint32_t   SizeOfImage;
  boost::uint32_t   SizeOfHeaders;
  boost::uint32_t   CheckSum;
  boost::uint16_t   Subsystem;
  boost::uint16_t   DllCharacteristics;
  boost::uint32_t   SizeOfStackReserve;
  boost::uint32_t   SizeOfStackCommit;
  boost::uint32_t   SizeOfHeapReserve;
  boost::uint32_t   SizeOfHeapCommit;
  boost::uint32_t   LoaderFlags;
  boost::uint32_t   NumberOfRvaAndSizes;
  data_directory    DataDirectory[NUM_DIR_ENTRIES];
};

struct nt_header_32 {
  boost::uint32_t     Signature;
  file_header         FileHeader;
  optional_header_32  OptionalHeader;
};

#endif
