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

#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>
#include <stdexcept>

#include <parser-library/nt-headers.h>
#include <parser-library/parse.h>
#include <parser-library/to_string.h>

namespace peparse {

struct section {
  std::string sectionName;
  std::uint64_t sectionBase;
  bounded_buffer *sectionData;
  image_section_header sec;
};

struct importent {
  VA addr;
  std::string symbolName;
  std::string moduleName;
};

struct exportent {
  VA addr;
  std::string symbolName;
  std::string moduleName;
};

struct reloc {
  VA shiftedAddr;
  reloc_type type;
};

#define SYMBOL_NAME_OFFSET(sn) (static_cast<std::uint32_t>(sn.data >> 32))
#define SYMBOL_TYPE_HI(x) (x.type >> 8)

union symbol_name {
  std::uint8_t shortName[NT_SHORT_NAME_LEN];
  std::uint32_t zeroes;
  std::uint64_t data;
};

struct aux_symbol_f1 {
  std::uint32_t tagIndex;
  std::uint32_t totalSize;
  std::uint32_t pointerToLineNumber;
  std::uint32_t pointerToNextFunction;
};

struct aux_symbol_f2 {
  std::uint16_t lineNumber;
  std::uint32_t pointerToNextFunction;
};

struct aux_symbol_f3 {
  std::uint32_t tagIndex;
  std::uint32_t characteristics;
};

struct aux_symbol_f4 {
  std::uint8_t filename[SYMTAB_RECORD_LEN];
  std::string strFilename;
};

struct aux_symbol_f5 {
  std::uint32_t length;
  std::uint16_t numberOfRelocations;
  std::uint16_t numberOfLineNumbers;
  std::uint32_t checkSum;
  std::uint16_t number;
  std::uint8_t selection;
};

struct symbol {
  std::string strName;
  symbol_name name;
  std::uint32_t value;
  std::int16_t sectionNumber;
  std::uint16_t type;
  std::uint8_t storageClass;
  std::uint8_t numberOfAuxSymbols;
  std::vector<aux_symbol_f1> aux_symbols_f1;
  std::vector<aux_symbol_f2> aux_symbols_f2;
  std::vector<aux_symbol_f3> aux_symbols_f3;
  std::vector<aux_symbol_f4> aux_symbols_f4;
  std::vector<aux_symbol_f5> aux_symbols_f5;
};

struct parsed_pe_internal {
  std::vector<section> secs;
  std::vector<resource> rsrcs;
  std::vector<importent> imports;
  std::vector<reloc> relocs;
  std::vector<exportent> exports;
  std::vector<symbol> symbols;
};

std::uint32_t err = 0;
std::string err_loc;

static const char *pe_err_str[] = {"None",
                                   "Out of memory",
                                   "Invalid header",
                                   "Invalid section",
                                   "Invalid resource",
                                   "Unable to get section for VA",
                                   "Unable to read data",
                                   "Unable to open",
                                   "Unable to stat",
                                   "Bad magic",
                                   "Invalid buffer",
                                   "Invalid address",};

std::uint32_t GetPEErr() {
  return err;
}

std::string GetPEErrString() {
  return pe_err_str[err];
}

std::string GetPEErrLoc() {
  return err_loc;
}

const char *GetSymbolTableStorageClassName(std::uint8_t id) {
  switch (id) {
    case IMAGE_SYM_CLASS_END_OF_FUNCTION:
      return "CLASS_END_OF_FUNCTION";
    case IMAGE_SYM_CLASS_NULL:
      return "CLASS_NULL";
    case IMAGE_SYM_CLASS_AUTOMATIC:
      return "CLASS_AUTOMATIC";
    case IMAGE_SYM_CLASS_EXTERNAL:
      return "CLASS_EXTERNAL";
    case IMAGE_SYM_CLASS_STATIC:
      return "CLASS_STATIC";
    case IMAGE_SYM_CLASS_REGISTER:
      return "CLASS_REGISTER";
    case IMAGE_SYM_CLASS_EXTERNAL_DEF:
      return "CLASS_EXTERNAL_DEF";
    case IMAGE_SYM_CLASS_LABEL:
      return "CLASS_LABEL";
    case IMAGE_SYM_CLASS_UNDEFINED_LABEL:
      return "CLASS_UNDEFINED_LABEL";
    case IMAGE_SYM_CLASS_MEMBER_OF_STRUCT:
      return "CLASS_MEMBER_OF_STRUCT";
    case IMAGE_SYM_CLASS_ARGUMENT:
      return "CLASS_ARGUMENT";
    case IMAGE_SYM_CLASS_STRUCT_TAG:
      return "CLASS_STRUCT_TAG";
    case IMAGE_SYM_CLASS_MEMBER_OF_UNION:
      return "CLASS_MEMBER_OF_UNION";
    case IMAGE_SYM_CLASS_UNION_TAG:
      return "CLASS_UNION_TAG";
    case IMAGE_SYM_CLASS_TYPE_DEFINITION:
      return "CLASS_TYPE_DEFINITION";
    case IMAGE_SYM_CLASS_UNDEFINED_STATIC:
      return "CLASS_UNDEFINED_STATIC";
    case IMAGE_SYM_CLASS_ENUM_TAG:
      return "CLASS_ENUM_TAG";
    case IMAGE_SYM_CLASS_MEMBER_OF_ENUM:
      return "CLASS_MEMBER_OF_ENUM";
    case IMAGE_SYM_CLASS_REGISTER_PARAM:
      return "CLASS_REGISTER_PARAM";
    case IMAGE_SYM_CLASS_BIT_FIELD:
      return "CLASS_BIT_FIELD";
    case IMAGE_SYM_CLASS_BLOCK:
      return "CLASS_BLOCK";
    case IMAGE_SYM_CLASS_FUNCTION:
      return "CLASS_FUNCTION";
    case IMAGE_SYM_CLASS_END_OF_STRUCT:
      return "CLASS_END_OF_STRUCT";
    case IMAGE_SYM_CLASS_FILE:
      return "CLASS_FILE";
    case IMAGE_SYM_CLASS_SECTION:
      return "CLASS_SECTION";
    case IMAGE_SYM_CLASS_WEAK_EXTERNAL:
      return "CLASS_WEAK_EXTERNAL";
    case IMAGE_SYM_CLASS_CLR_TOKEN:
      return "CLASS_CLR_TOKEN";
    default:
      return nullptr;
  }
}

static bool
readCString(const bounded_buffer &buffer, std::uint32_t off, std::string &result) {
  if (off < buffer.bufLen) {
    std::uint8_t *p = buffer.buf;
    std::uint32_t n = buffer.bufLen;
    std::uint8_t *b = p + off;
    std::uint8_t *x = std::find(b, p + n, 0);

    if (x == p + n) {
      return false;
    }

    result.insert(result.end(), b, x);
    return true;
  }
  return false;
}

bool getSecForVA(const std::vector<section> &secs, VA v, section &sec) {
  for (section s : secs) {
    std::uint64_t low = s.sectionBase;
    std::uint64_t high = low + s.sec.Misc.VirtualSize;

    if (v >= low && v < high) {
      sec = s;
      return true;
    }
  }

  return false;
}

void IterRsrc(parsed_pe *pe, iterRsrc cb, void *cbd) {
  parsed_pe_internal *pint = pe->internal;

  for (resource r : pint->rsrcs) {
    if (cb(cbd, r) != 0) {
      break;
    }
  }

  return;
}

bool parse_resource_id(bounded_buffer *data, std::uint32_t id, std::string &result) {
  std::uint8_t c;
  std::uint16_t len;

  if (!readWord(data, id, len)) {
    return false;
  }
  id += 2;
  for (std::uint32_t i = 0; i < len * 2U; i++) {
    if (!readByte(data, id + i, c)) {
      return false;
    }
    result.push_back(static_cast<char>(c));
  }
  return true;
}

bool parse_resource_table(bounded_buffer *sectionData,
                          std::uint32_t o,
                          std::uint32_t virtaddr,
                          std::uint32_t depth,
                          resource_dir_entry *dirent,
                          std::vector<resource> &rsrcs) {
  resource_dir_table rdt;

  if (sectionData == nullptr) {
    return false;
  }

  READ_DWORD(sectionData, o, rdt, Characteristics);
  READ_DWORD(sectionData, o, rdt, TimeDateStamp);
  READ_WORD(sectionData, o, rdt, MajorVersion);
  READ_WORD(sectionData, o, rdt, MinorVersion);
  READ_WORD(sectionData, o, rdt, NameEntries);
  READ_WORD(sectionData, o, rdt, IDEntries);

  o += sizeof(resource_dir_table);

  if (rdt.NameEntries == 0u && rdt.IDEntries == 0u) {
    return true; // This is not a hard error. It does happen.
  }

  for (std::uint32_t i = 0;
       i < static_cast<std::uint32_t>(rdt.NameEntries + rdt.IDEntries);
       i++) {
    resource_dir_entry *rde = dirent;
    if (dirent == nullptr) {
      rde = new resource_dir_entry;
    }

    if (!readDword(sectionData, o + _offset(__typeof__(*rde), ID), rde->ID)) {
      PE_ERR(PEERR_READ);
      if (dirent == nullptr) {
        delete rde;
      }
      return false;
    }

    if (!readDword(sectionData, o + _offset(__typeof__(*rde), RVA), rde->RVA)) {
      PE_ERR(PEERR_READ);
      if (dirent == nullptr) {
        delete rde;
      }
      return false;
    }

    o += sizeof(resource_dir_entry_sz);

    if (depth == 0) {
      rde->type = rde->ID;
      if (i < rdt.NameEntries) {
        if (!parse_resource_id(
                sectionData, rde->ID & 0x0FFFFFFF, rde->type_str)) {
          if (dirent == nullptr) {
            delete rde;
          }
          return false;
        }
      }
    } else if (depth == 1) {
      rde->name = rde->ID;
      if (i < rdt.NameEntries) {
        if (!parse_resource_id(
                sectionData, rde->ID & 0x0FFFFFFF, rde->name_str)) {
          if (dirent == nullptr) {
            delete rde;
          }
          return false;
        }
      }
    } else if (depth == 2) {
      rde->lang = rde->ID;
      if (i < rdt.NameEntries) {
        if (!parse_resource_id(
                sectionData, rde->ID & 0x0FFFFFFF, rde->lang_str)) {
          if (dirent == nullptr) {
            delete rde;
          }
          return false;
        }
      }
    } else {
      /* .rsrc can accomodate up to 2**31 levels, but Windows only uses 3 by convention.
       * As such, any depth above 3 indicates potentially unchecked recusion.
       * See: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-rsrc-section
       */

      PE_ERR(PEERR_RESC);
      return false;
    }

    // High bit 0 = RVA to RDT.
    // High bit 1 = RVA to RDE.
    if (rde->RVA & 0x80000000) {
      if (!parse_resource_table(sectionData,
                                rde->RVA & 0x0FFFFFFF,
                                virtaddr,
                                depth + 1,
                                rde,
                                rsrcs)) {
        if (dirent == nullptr) {
          delete rde;
        }
        return false;
      }
    } else {
      resource_dat_entry rdat;

      /*
       * This one is using rde->RVA as an offset.
       *
       * This is because we don't want to set o because we have to keep the
       * original value when we are done parsing this resource data entry.
       * We could store the original o value and reset it when we are done,
       * but meh.
       */

      if (!readDword(sectionData,
                     rde->RVA + _offset(__typeof__(rdat), RVA),
                     rdat.RVA)) {
        PE_ERR(PEERR_READ);
        if (dirent == nullptr) {
          delete rde;
        }
        return false;
      }

      if (!readDword(sectionData,
                     rde->RVA + _offset(__typeof__(rdat), size),
                     rdat.size)) {
        PE_ERR(PEERR_READ);
        if (dirent == nullptr) {
          delete rde;
        }
        return false;
      }

      if (!readDword(sectionData,
                     rde->RVA + _offset(__typeof__(rdat), codepage),
                     rdat.codepage)) {
        PE_ERR(PEERR_READ);
        if (dirent == nullptr) {
          delete rde;
        }
        return false;
      }

      if (!readDword(sectionData,
                     rde->RVA + _offset(__typeof__(rdat), reserved),
                     rdat.reserved)) {
        PE_ERR(PEERR_READ);
        if (dirent == nullptr) {
          delete rde;
        }
        return false;
      }

      resource rsrc;
      rsrc.type_str = rde->type_str;
      rsrc.name_str = rde->name_str;
      rsrc.lang_str = rde->lang_str;
      rsrc.type = rde->type;
      rsrc.name = rde->name;
      rsrc.lang = rde->lang;
      rsrc.codepage = rdat.codepage;
      rsrc.RVA = rdat.RVA;
      rsrc.size = rdat.size;

      // The start address is (RVA - section virtual address).
      uint32_t start = rdat.RVA - virtaddr;
      /*
       * Some binaries (particularly packed) will have invalid addresses here.
       * If those happen, return a zero length buffer.
       * If the start is valid, try to get the data and if that fails return
       * a zero length buffer.
       */
      if (start > rdat.RVA) {
        rsrc.buf = splitBuffer(sectionData, 0, 0);
      } else {
        rsrc.buf = splitBuffer(sectionData, start, start + rdat.size);
        if (rsrc.buf == nullptr) {
          rsrc.buf = splitBuffer(sectionData, 0, 0);
        }
      }

      /* If we can't get even a zero length buffer, something is very wrong. */
      if (rsrc.buf == nullptr) {
        if (dirent == nullptr) {
          delete rde;
        }
        return false;
      }

      rsrcs.push_back(rsrc);
    }

    if (depth == 0) {
      rde->type_str.clear();
    } else if (depth == 1) {
      rde->name_str.clear();
    } else if (depth == 2) {
      rde->lang_str.clear();
    }

    if (dirent == nullptr) {
      delete rde;
    }
  }

  return true;
}

bool getResources(bounded_buffer *b,
                  bounded_buffer *fileBegin,
                  const std::vector<section> secs,
                  std::vector<resource> &rsrcs) {
  static_cast<void>(fileBegin);

  if (b == nullptr)
    return false;

  for (section s : secs) {
    if (s.sectionName != ".rsrc") {
      continue;
    }

    if (!parse_resource_table(
            s.sectionData, 0, s.sec.VirtualAddress, 0, nullptr, rsrcs)) {
      return false;
    }

    break; // Because there should only be one .rsrc
  }

  return true;
}

bool getSections(bounded_buffer *b,
                 bounded_buffer *fileBegin,
                 nt_header_32 &nthdr,
                 std::vector<section> &secs) {
  if (b == nullptr) {
    return false;
  }

  // get each of the sections...
  for (std::uint32_t i = 0; i < nthdr.FileHeader.NumberOfSections; i++) {
    image_section_header curSec;

    std::uint32_t o = i * sizeof(image_section_header);
    for (std::uint32_t k = 0; k < NT_SHORT_NAME_LEN; k++) {
      if (!readByte(b, o + k, curSec.Name[k])) {
        return false;
      }
    }

    READ_DWORD(b, o, curSec, Misc.VirtualSize);
    READ_DWORD(b, o, curSec, VirtualAddress);
    READ_DWORD(b, o, curSec, SizeOfRawData);
    READ_DWORD(b, o, curSec, PointerToRawData);
    READ_DWORD(b, o, curSec, PointerToRelocations);
    READ_DWORD(b, o, curSec, PointerToLinenumbers);
    READ_WORD(b, o, curSec, NumberOfRelocations);
    READ_WORD(b, o, curSec, NumberOfLinenumbers);
    READ_DWORD(b, o, curSec, Characteristics);

    // now we have the section header information, so fill in a section
    // object appropriately
    section thisSec;
    for (std::uint32_t charIndex = 0; charIndex < NT_SHORT_NAME_LEN; charIndex++) {
      std::uint8_t c = curSec.Name[charIndex];
      if (c == 0) {
        break;
      }

      thisSec.sectionName.push_back(static_cast<char>(c));
    }

    if (nthdr.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      thisSec.sectionBase =
          nthdr.OptionalHeader.ImageBase + curSec.VirtualAddress;
    } else if (nthdr.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
      thisSec.sectionBase =
          nthdr.OptionalHeader64.ImageBase + curSec.VirtualAddress;
    } else {
      PE_ERR(PEERR_MAGIC);
    }

    thisSec.sec = curSec;
    std::uint32_t lowOff = curSec.PointerToRawData;
    std::uint32_t highOff = lowOff + curSec.SizeOfRawData;
    thisSec.sectionData = splitBuffer(fileBegin, lowOff, highOff);

    secs.push_back(thisSec);
  }

  return true;
}

bool readOptionalHeader(bounded_buffer *b, optional_header_32 &header) {
  READ_WORD(b, 0, header, Magic);

  READ_BYTE(b, 0, header, MajorLinkerVersion);
  READ_BYTE(b, 0, header, MinorLinkerVersion);
  READ_DWORD(b, 0, header, SizeOfCode);
  READ_DWORD(b, 0, header, SizeOfInitializedData);
  READ_DWORD(b, 0, header, SizeOfUninitializedData);
  READ_DWORD(b, 0, header, AddressOfEntryPoint);
  READ_DWORD(b, 0, header, BaseOfCode);
  READ_DWORD(b, 0, header, BaseOfData);
  READ_DWORD(b, 0, header, ImageBase);
  READ_DWORD(b, 0, header, SectionAlignment);
  READ_DWORD(b, 0, header, FileAlignment);
  READ_WORD(b, 0, header, MajorOperatingSystemVersion);
  READ_WORD(b, 0, header, MinorOperatingSystemVersion);
  READ_WORD(b, 0, header, MajorImageVersion);
  READ_WORD(b, 0, header, MinorImageVersion);
  READ_WORD(b, 0, header, MajorSubsystemVersion);
  READ_WORD(b, 0, header, MinorSubsystemVersion);
  READ_DWORD(b, 0, header, Win32VersionValue);
  READ_DWORD(b, 0, header, SizeOfImage);
  READ_DWORD(b, 0, header, SizeOfHeaders);
  READ_DWORD(b, 0, header, CheckSum);
  READ_WORD(b, 0, header, Subsystem);
  READ_WORD(b, 0, header, DllCharacteristics);
  READ_DWORD(b, 0, header, SizeOfStackReserve);
  READ_DWORD(b, 0, header, SizeOfStackCommit);
  READ_DWORD(b, 0, header, SizeOfHeapReserve);
  READ_DWORD(b, 0, header, SizeOfHeapCommit);
  READ_DWORD(b, 0, header, LoaderFlags);
  READ_DWORD(b, 0, header, NumberOfRvaAndSizes);

  if (header.NumberOfRvaAndSizes > NUM_DIR_ENTRIES) {
    header.NumberOfRvaAndSizes = NUM_DIR_ENTRIES;
  }

  for (std::uint32_t i = 0; i < header.NumberOfRvaAndSizes; i++) {
    std::uint32_t c = (i * sizeof(data_directory));
    c += _offset(optional_header_32, DataDirectory[0]);
    std::uint32_t o;

    o = c + _offset(data_directory, VirtualAddress);
    if (!readDword(b, o, header.DataDirectory[i].VirtualAddress)) {
      return false;
    }

    o = c + _offset(data_directory, Size);
    if (!readDword(b, o, header.DataDirectory[i].Size)) {
      return false;
    }
  }

  return true;
}

bool readOptionalHeader64(bounded_buffer *b, optional_header_64 &header) {
  READ_WORD(b, 0, header, Magic);

  READ_BYTE(b, 0, header, MajorLinkerVersion);
  READ_BYTE(b, 0, header, MinorLinkerVersion);
  READ_DWORD(b, 0, header, SizeOfCode);
  READ_DWORD(b, 0, header, SizeOfInitializedData);
  READ_DWORD(b, 0, header, SizeOfUninitializedData);
  READ_DWORD(b, 0, header, AddressOfEntryPoint);
  READ_DWORD(b, 0, header, BaseOfCode);
  READ_QWORD(b, 0, header, ImageBase);
  READ_DWORD(b, 0, header, SectionAlignment);
  READ_DWORD(b, 0, header, FileAlignment);
  READ_WORD(b, 0, header, MajorOperatingSystemVersion);
  READ_WORD(b, 0, header, MinorOperatingSystemVersion);
  READ_WORD(b, 0, header, MajorImageVersion);
  READ_WORD(b, 0, header, MinorImageVersion);
  READ_WORD(b, 0, header, MajorSubsystemVersion);
  READ_WORD(b, 0, header, MinorSubsystemVersion);
  READ_DWORD(b, 0, header, Win32VersionValue);
  READ_DWORD(b, 0, header, SizeOfImage);
  READ_DWORD(b, 0, header, SizeOfHeaders);
  READ_DWORD(b, 0, header, CheckSum);
  READ_WORD(b, 0, header, Subsystem);
  READ_WORD(b, 0, header, DllCharacteristics);
  READ_QWORD(b, 0, header, SizeOfStackReserve);
  READ_QWORD(b, 0, header, SizeOfStackCommit);
  READ_QWORD(b, 0, header, SizeOfHeapReserve);
  READ_QWORD(b, 0, header, SizeOfHeapCommit);
  READ_DWORD(b, 0, header, LoaderFlags);
  READ_DWORD(b, 0, header, NumberOfRvaAndSizes);

  if (header.NumberOfRvaAndSizes > NUM_DIR_ENTRIES) {
    header.NumberOfRvaAndSizes = NUM_DIR_ENTRIES;
  }

  for (std::uint32_t i = 0; i < header.NumberOfRvaAndSizes; i++) {
    std::uint32_t c = (i * sizeof(data_directory));
    c += _offset(optional_header_64, DataDirectory[0]);
    std::uint32_t o;

    o = c + _offset(data_directory, VirtualAddress);
    if (!readDword(b, o, header.DataDirectory[i].VirtualAddress)) {
      return false;
    }

    o = c + _offset(data_directory, Size);
    if (!readDword(b, o, header.DataDirectory[i].Size)) {
      return false;
    }
  }

  return true;
}

bool readFileHeader(bounded_buffer *b, file_header &header) {
  READ_WORD(b, 0, header, Machine);
  READ_WORD(b, 0, header, NumberOfSections);
  READ_DWORD(b, 0, header, TimeDateStamp);
  READ_DWORD(b, 0, header, PointerToSymbolTable);
  READ_DWORD(b, 0, header, NumberOfSymbols);
  READ_WORD(b, 0, header, SizeOfOptionalHeader);
  READ_WORD(b, 0, header, Characteristics);

  return true;
}

bool readNtHeader(bounded_buffer *b, nt_header_32 &header) {
  if (b == nullptr) {
    return false;
  }

  std::uint32_t pe_magic;
  std::uint32_t curOffset = 0;
  if (!readDword(b, curOffset, pe_magic) || pe_magic != NT_MAGIC) {
    PE_ERR(PEERR_READ);
    return false;
  }

  header.Signature = pe_magic;
  bounded_buffer *fhb =
      splitBuffer(b, _offset(nt_header_32, FileHeader), b->bufLen);

  if (fhb == nullptr) {
    PE_ERR(PEERR_MEM);
    return false;
  }

  if (!readFileHeader(fhb, header.FileHeader)) {
    deleteBuffer(fhb);
    return false;
  }

  if (TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_ARM, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_M32R, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_POWERPC, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_R4000, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_WCEMIPSV2, IMAGE_FILE_BYTES_REVERSED_HI)) {
    b->swapBytes = true;
  }

  /*
   * The buffer is split using the OptionalHeader offset, even if it turns
   * out to be a PE32+. The start of the buffer is at the same spot in the
   * buffer regardless.
   */
  bounded_buffer *ohb =
      splitBuffer(b, _offset(nt_header_32, OptionalHeader), b->bufLen);

  if (ohb == nullptr) {
    deleteBuffer(fhb);
    PE_ERR(PEERR_MEM);
    return false;
  }

  /*
   * Read the Magic to determine if it is 32 or 64.
   */
  if (!readWord(ohb, 0, header.OptionalMagic)) {
    PE_ERR(PEERR_READ);
    if (ohb != nullptr) {
      deleteBuffer(ohb);
    }
    deleteBuffer(fhb);
    return false;
  }
  if (header.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
    if (!readOptionalHeader(ohb, header.OptionalHeader)) {
      deleteBuffer(ohb);
      deleteBuffer(fhb);
      return false;
    }
  } else if (header.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
    if (!readOptionalHeader64(ohb, header.OptionalHeader64)) {
      deleteBuffer(ohb);
      deleteBuffer(fhb);
      return false;
    }
  } else {
    PE_ERR(PEERR_MAGIC);
    deleteBuffer(ohb);
    deleteBuffer(fhb);
    return false;
  }

  deleteBuffer(ohb);
  deleteBuffer(fhb);

  return true;
}

bool getHeader(bounded_buffer *file, pe_header &p, bounded_buffer *&rem) {
  if (file == nullptr) {
    return false;
  }

  // start by reading MZ
  std::uint16_t tmp = 0;
  std::uint32_t curOffset = 0;
  if (!readWord(file, curOffset, tmp)) {
    PE_ERR(PEERR_READ);
    return false;
  }
  if (tmp != MZ_MAGIC) {
    PE_ERR(PEERR_MAGIC);
    return false;
  }

  // read the offset to the NT headers
  std::uint32_t offset;
  if (!readDword(file, _offset(dos_header, e_lfanew), offset)) {
    PE_ERR(PEERR_READ);
    return false;
  }
  curOffset += offset;

  // now, we can read out the fields of the NT headers
  bounded_buffer *ntBuf = splitBuffer(file, curOffset, file->bufLen);

  if (!readNtHeader(ntBuf, p.nt)) {
    // err is set by readNtHeader
    if (ntBuf != nullptr) {
      deleteBuffer(ntBuf);
    }
    return false;
  }

  /*
   * Need to determine if this is a PE32 or PE32+ binary and use the
   # correct size.
   */
  std::uint32_t rem_size;
  if (p.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
    // signature + file_header + optional_header_32
    rem_size =
        sizeof(std::uint32_t) + sizeof(file_header) + sizeof(optional_header_32);
  } else if (p.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
    // signature + file_header + optional_header_64
    rem_size =
        sizeof(std::uint32_t) + sizeof(file_header) + sizeof(optional_header_64);
  } else {
    PE_ERR(PEERR_MAGIC);
    deleteBuffer(ntBuf);
    return false;
  }

  // update 'rem' to point to the space after the header
  rem = splitBuffer(ntBuf, rem_size, ntBuf->bufLen);
  deleteBuffer(ntBuf);

  return true;
}

bool getExports(parsed_pe *p) {
  data_directory exportDir;
  if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
    exportDir = p->peHeader.nt.OptionalHeader.DataDirectory[DIR_EXPORT];
  } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
    exportDir = p->peHeader.nt.OptionalHeader64.DataDirectory[DIR_EXPORT];
  } else {
    return false;
  }

  if (exportDir.Size != 0) {
    section s;
    VA addr;
    if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      addr = exportDir.VirtualAddress + p->peHeader.nt.OptionalHeader.ImageBase;
    } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
      addr =
          exportDir.VirtualAddress + p->peHeader.nt.OptionalHeader64.ImageBase;
    } else {
      return false;
    }

    if (!getSecForVA(p->internal->secs, addr, s)) {
      return false;
    }

    auto rvaofft = static_cast<std::uint32_t>(addr - s.sectionBase);

    // get the name of this module
    std::uint32_t nameRva;
    if (!readDword(s.sectionData,
                   rvaofft + _offset(export_dir_table, NameRVA),
                   nameRva)) {
      return false;
    }

    VA nameVA;
    if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      nameVA = nameRva + p->peHeader.nt.OptionalHeader.ImageBase;
    } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
      nameVA = nameRva + p->peHeader.nt.OptionalHeader64.ImageBase;
    } else {
      return false;
    }

    section nameSec;
    if (!getSecForVA(p->internal->secs, nameVA, nameSec)) {
      return false;
    }

    auto nameOff = static_cast<std::uint32_t>(nameVA - nameSec.sectionBase);
    std::string modName;
    if (!readCString(*nameSec.sectionData, nameOff, modName)) {
      return false;
    }

    // now, get all the named export symbols
    std::uint32_t numNames;
    if (!readDword(s.sectionData,
                   rvaofft + _offset(export_dir_table, NumberOfNamePointers),
                   numNames)) {
      return false;
    }

    if (numNames > 0) {
      // get the names section
      std::uint32_t namesRVA;
      if (!readDword(s.sectionData,
                     rvaofft + _offset(export_dir_table, NamePointerRVA),
                     namesRVA)) {
        return false;
      }

      VA namesVA;
      if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
        namesVA = namesRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
        namesVA = namesRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
      } else {
        return false;
      }

      section namesSec;
      if (!getSecForVA(p->internal->secs, namesVA, namesSec)) {
        return false;
      }

      auto namesOff =
          static_cast<std::uint32_t>(namesVA - namesSec.sectionBase);

      // get the EAT section
      std::uint32_t eatRVA;
      if (!readDword(s.sectionData,
                     rvaofft + _offset(export_dir_table, ExportAddressTableRVA),
                     eatRVA)) {
        return false;
      }

      VA eatVA;
      if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
        eatVA = eatRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
        eatVA = eatRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
      } else {
        return false;
      }

      section eatSec;
      if (!getSecForVA(p->internal->secs, eatVA, eatSec)) {
        return false;
      }

      auto eatOff = static_cast<std::uint32_t>(eatVA - eatSec.sectionBase);

      // get the ordinal base
      std::uint32_t ordinalBase;
      if (!readDword(s.sectionData,
                     rvaofft + _offset(export_dir_table, OrdinalBase),
                     ordinalBase)) {
        return false;
      }

      // get the ordinal table
      std::uint32_t ordinalTableRVA;
      if (!readDword(s.sectionData,
                     rvaofft + _offset(export_dir_table, OrdinalTableRVA),
                     ordinalTableRVA)) {
        return false;
      }

      VA ordinalTableVA;
      if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
        ordinalTableVA =
            ordinalTableRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
        ordinalTableVA =
            ordinalTableRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
      } else {
        return false;
      }

      section ordinalTableSec;
      if (!getSecForVA(p->internal->secs, ordinalTableVA, ordinalTableSec)) {
        return false;
      }

      auto ordinalOff = static_cast<std::uint32_t>(ordinalTableVA -
                                                   ordinalTableSec.sectionBase);

      for (std::uint32_t i = 0; i < numNames; i++) {
        std::uint32_t curNameRVA;
        if (!readDword(namesSec.sectionData,
                       namesOff + (i * sizeof(std::uint32_t)),
                       curNameRVA)) {
          return false;
        }

        VA curNameVA;
        if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
          curNameVA = curNameRVA + p->peHeader.nt.OptionalHeader.ImageBase;
        } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
          curNameVA = curNameRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
        } else {
          return false;
        }

        section curNameSec;

        if (!getSecForVA(p->internal->secs, curNameVA, curNameSec)) {
          return false;
        }

        auto curNameOff =
            static_cast<std::uint32_t>(curNameVA - curNameSec.sectionBase);
        std::string symName;
        std::uint8_t d;

        do {
          if (!readByte(curNameSec.sectionData, curNameOff, d)) {
            return false;
          }

          if (d == 0) {
            break;
          }

          symName.push_back(static_cast<char>(d));
          curNameOff++;
        } while (true);

        // now, for this i, look it up in the ExportOrdinalTable
        std::uint16_t ordinal;
        if (!readWord(ordinalTableSec.sectionData,
                      ordinalOff + (i * sizeof(std::uint16_t)),
                      ordinal)) {
          return false;
        }

        //::uint32_t  eatIdx = ordinal - ordinalBase;
        std::uint32_t eatIdx = (ordinal * sizeof(std::uint32_t));

        std::uint32_t symRVA;
        if (!readDword(eatSec.sectionData, eatOff + eatIdx, symRVA)) {
          return false;
        }

        bool isForwarded =
            ((symRVA >= exportDir.VirtualAddress) &&
             (symRVA < exportDir.VirtualAddress + exportDir.Size));

        if (!isForwarded) {
          VA symVA;
          if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
            symVA = symRVA + p->peHeader.nt.OptionalHeader.ImageBase;
          } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
            symVA = symRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
          } else {
            return false;
          }

          exportent a;

          a.addr = symVA;
          a.symbolName = symName;
          a.moduleName = modName;
          p->internal->exports.push_back(a);
        }
      }
    }
  }

  return true;
}

bool getRelocations(parsed_pe *p) {
  data_directory relocDir;
  if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
    relocDir = p->peHeader.nt.OptionalHeader.DataDirectory[DIR_BASERELOC];
  } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
    relocDir = p->peHeader.nt.OptionalHeader64.DataDirectory[DIR_BASERELOC];
  } else {
    return false;
  }

  if (relocDir.Size != 0) {
    section d;
    VA vaAddr;
    if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      vaAddr =
          relocDir.VirtualAddress + p->peHeader.nt.OptionalHeader.ImageBase;
    } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
      vaAddr =
          relocDir.VirtualAddress + p->peHeader.nt.OptionalHeader64.ImageBase;
    } else {
      return false;
    }

    if (!getSecForVA(p->internal->secs, vaAddr, d)) {
      return false;
    }

    auto rvaofft = static_cast<std::uint32_t>(vaAddr - d.sectionBase);

    while (rvaofft < relocDir.Size) {
      std::uint32_t pageRva;
      std::uint32_t blockSize;

      if (!readDword(d.sectionData,
                     rvaofft + _offset(reloc_block, PageRVA),
                     pageRva)) {
        return false;
      }

      if (!readDword(d.sectionData,
                     rvaofft + _offset(reloc_block, BlockSize),
                     blockSize)) {
        return false;
      }

      // BlockSize - The total number of bytes in the base relocation block,
      // including the Page RVA and Block Size fields and the Type/Offset fields
      // that follow. Therefore we should subtract 8 bytes from BlockSize to
      // exclude the Page RVA and Block Size fields.
      std::uint32_t entryCount = (blockSize - 8) / sizeof(std::uint16_t);

      // Skip the Page RVA and Block Size fields
      rvaofft += sizeof(reloc_block);

      // Iterate over all of the block Type/Offset entries
      while (entryCount != 0) {
        std::uint16_t entry;
        std::uint8_t type;
        std::uint16_t offset;

        if (!readWord(d.sectionData, rvaofft, entry)) {
          return false;
        }

        // Mask out the type and assign
        type = entry >> 12;
        // Mask out the offset and assign
        offset = entry & ~0xf000;

        // Produce the VA of the relocation
        VA relocVA;
        if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
          relocVA = pageRva + offset + p->peHeader.nt.OptionalHeader.ImageBase;
        } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
          relocVA =
              pageRva + offset + p->peHeader.nt.OptionalHeader64.ImageBase;
        } else {
          return false;
        }

        // Store in our list
        reloc r;

        r.shiftedAddr = relocVA;
        r.type = static_cast<reloc_type>(type);
        p->internal->relocs.push_back(r);

        entryCount--;
        rvaofft += sizeof(std::uint16_t);
      }
    }
  }

  return true;
}

bool getImports(parsed_pe *p) {
  data_directory importDir;
  if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
    importDir = p->peHeader.nt.OptionalHeader.DataDirectory[DIR_IMPORT];
  } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
    importDir = p->peHeader.nt.OptionalHeader64.DataDirectory[DIR_IMPORT];
  } else {
    return false;
  }

  if (importDir.Size != 0) {
    // get section for the RVA in importDir
    section c;
    VA addr;
    if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      addr = importDir.VirtualAddress + p->peHeader.nt.OptionalHeader.ImageBase;
    } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
      addr =
          importDir.VirtualAddress + p->peHeader.nt.OptionalHeader64.ImageBase;
    } else {
      return false;
    }

    if (!getSecForVA(p->internal->secs, addr, c)) {
      return false;
    }

    // get import directory from this section
    auto offt = static_cast<std::uint32_t>(addr - c.sectionBase);

    import_dir_entry emptyEnt;
    memset(&emptyEnt, 0, sizeof(import_dir_entry));

    do {
      // read each directory entry out
      import_dir_entry curEnt = emptyEnt;

      READ_DWORD(c.sectionData, offt, curEnt, LookupTableRVA);
      READ_DWORD(c.sectionData, offt, curEnt, TimeStamp);
      READ_DWORD(c.sectionData, offt, curEnt, ForwarderChain);
      READ_DWORD(c.sectionData, offt, curEnt, NameRVA);
      READ_DWORD(c.sectionData, offt, curEnt, AddressRVA);

      // are all the fields in curEnt null? then we break
      if (curEnt.LookupTableRVA == 0 && curEnt.NameRVA == 0 &&
          curEnt.AddressRVA == 0) {
        break;
      }

      // then, try and get the name of this particular module...
      VA name;
      if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
        name = curEnt.NameRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
        name = curEnt.NameRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
      } else {
        return false;
      }

      section nameSec;
      if (!getSecForVA(p->internal->secs, name, nameSec)) {
        return false;
      }

      auto nameOff = static_cast<std::uint32_t>(name - nameSec.sectionBase);
      std::string modName;
      if (!readCString(*nameSec.sectionData, nameOff, modName)) {
        return false;
      }

      // clang-format off
      std::transform(
        modName.begin(),
        modName.end(),
        modName.begin(),

        [](char chr) -> char {
          return static_cast<char>(::toupper(chr));
        }
      );
      // clang-format on

      // then, try and get all of the sub-symbols
      VA lookupVA = 0;
      if (curEnt.LookupTableRVA != 0) {
        if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
          lookupVA =
              curEnt.LookupTableRVA + p->peHeader.nt.OptionalHeader.ImageBase;
        } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
          lookupVA =
              curEnt.LookupTableRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
        } else {
          return false;
        }
      } else if (curEnt.AddressRVA != 0) {
        if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
          lookupVA =
              curEnt.AddressRVA + p->peHeader.nt.OptionalHeader.ImageBase;
        } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
          lookupVA =
              curEnt.AddressRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
        } else {
          return false;
        }
      }

      section lookupSec;
      if (lookupVA == 0 ||
          !getSecForVA(p->internal->secs, lookupVA, lookupSec)) {
        return false;
      }

      auto lookupOff =
          static_cast<std::uint32_t>(lookupVA - lookupSec.sectionBase);
      std::uint32_t offInTable = 0;
      do {
        VA valVA = 0;
        std::uint8_t ord = 0;
        std::uint16_t oval = 0;
        std::uint32_t val32 = 0;
        std::uint64_t val64 = 0;
        if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
          if (!readDword(lookupSec.sectionData, lookupOff, val32)) {
            return false;
          }
          if (val32 == 0) {
            break;
          }
          ord = (val32 >> 31);
          oval = (val32 & ~0xFFFF0000);
          valVA = val32 + p->peHeader.nt.OptionalHeader.ImageBase;
        } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
          if (!readQword(lookupSec.sectionData, lookupOff, val64)) {
            return false;
          }
          if (val64 == 0) {
            break;
          }
          ord = (val64 >> 63);
          oval = (val64 & ~0xFFFF0000);
          valVA = val64 + p->peHeader.nt.OptionalHeader64.ImageBase;
        } else {
          return false;
        }

        if (ord == 0) {
          // import by name
          std::string symName;
          section symNameSec;

          if (!getSecForVA(p->internal->secs, valVA, symNameSec)) {
            return false;
          }

          std::uint32_t nameOffset =
              static_cast<std::uint32_t>(valVA - symNameSec.sectionBase) +
              sizeof(std::uint16_t);
          do {
            std::uint8_t chr;
            if (!readByte(symNameSec.sectionData, nameOffset, chr)) {
              return false;
            }

            if (chr == 0) {
              break;
            }

            symName.push_back(static_cast<char>(chr));
            nameOffset++;
          } while (true);

          // okay now we know the pair... add it
          importent ent;

          if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
            ent.addr = offInTable + curEnt.AddressRVA +
                       p->peHeader.nt.OptionalHeader.ImageBase;
          } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
            ent.addr = offInTable + curEnt.AddressRVA +
                       p->peHeader.nt.OptionalHeader64.ImageBase;
          } else {
            return false;
          }

          ent.symbolName = symName;
          ent.moduleName = modName;
          p->internal->imports.push_back(ent);
        } else {
          std::string symName =
              "ORDINAL_" + modName + "_" + to_string<std::uint32_t>(oval, std::dec);

          importent ent;

          if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
            ent.addr = offInTable + curEnt.AddressRVA +
                       p->peHeader.nt.OptionalHeader.ImageBase;
          } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
            ent.addr = offInTable + curEnt.AddressRVA +
                       p->peHeader.nt.OptionalHeader64.ImageBase;
          } else {
            return false;
          }

          ent.symbolName = symName;
          ent.moduleName = modName;

          p->internal->imports.push_back(ent);
        }

        if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
          lookupOff += sizeof(std::uint32_t);
          offInTable += sizeof(std::uint32_t);
        } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
          lookupOff += sizeof(std::uint64_t);
          offInTable += sizeof(std::uint64_t);
        } else {
          return false;
        }
      } while (true);

      offt += sizeof(import_dir_entry);
    } while (true);
  }

  return true;
}

bool getSymbolTable(parsed_pe *p) {
  if (p->peHeader.nt.FileHeader.PointerToSymbolTable == 0) {
    return true;
  }

  std::uint32_t strTableOffset =
      p->peHeader.nt.FileHeader.PointerToSymbolTable +
      (p->peHeader.nt.FileHeader.NumberOfSymbols * SYMTAB_RECORD_LEN);

  std::uint32_t offset = p->peHeader.nt.FileHeader.PointerToSymbolTable;

  for (std::uint32_t i = 0; i < p->peHeader.nt.FileHeader.NumberOfSymbols; i++) {
    symbol sym;

    // Read name
    if (!readQword(p->fileBuffer, offset, sym.name.data)) {
      PE_ERR(PEERR_MAGIC);
      return false;
    }

    if (sym.name.zeroes == 0) {
      // The symbol name is greater than 8 bytes so it is stored in the string
      // table. In this case instead of name, an offset of the string in the
      // string table is provided.

      uint32_t strOffset = strTableOffset + SYMBOL_NAME_OFFSET(sym.name);
      uint8_t ch;
      for (;;) {
        if (!readByte(p->fileBuffer, strOffset, ch)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }
        if (ch == 0u) {
          break;
        }
        sym.strName.push_back(static_cast<char>(ch));
        strOffset += sizeof(std::uint8_t);
      }
    } else {
      for (std::uint8_t n = 0; n < NT_SHORT_NAME_LEN && sym.name.shortName[n] != 0;
           n++) {
        sym.strName.push_back(static_cast<char>(sym.name.shortName[n]));
      }
    }

    offset += sizeof(std::uint64_t);

    // Read value
    if (!readDword(p->fileBuffer, offset, sym.value)) {
      PE_ERR(PEERR_MAGIC);
      return false;
    }

    offset += sizeof(std::uint32_t);

    // Read section number
    uint16_t secNum;
    if (!readWord(p->fileBuffer, offset, secNum)) {
      PE_ERR(PEERR_MAGIC);
      return false;
    }
    sym.sectionNumber = static_cast<std::int16_t>(secNum);

    offset += sizeof(std::uint16_t);

    // Read type
    if (!readWord(p->fileBuffer, offset, sym.type)) {
      PE_ERR(PEERR_MAGIC);
      return false;
    }

    offset += sizeof(std::uint16_t);

    // Read storage class
    if (!readByte(p->fileBuffer, offset, sym.storageClass)) {
      PE_ERR(PEERR_MAGIC);
      return false;
    }

    offset += sizeof(std::uint8_t);

    // Read number of auxiliary symbols
    if (!readByte(p->fileBuffer, offset, sym.numberOfAuxSymbols)) {
      PE_ERR(PEERR_MAGIC);
      return false;
    }

    // Set offset to next symbol
    offset += sizeof(std::uint8_t);

    // Save the symbol
    p->internal->symbols.push_back(sym);

    if (sym.numberOfAuxSymbols == 0) {
      continue;
    }

    // Read auxiliary symbol records
    auto nextSymbolOffset =
        offset + (static_cast<std::uint32_t>(sym.numberOfAuxSymbols) *
                  static_cast<std::uint32_t>(SYMTAB_RECORD_LEN));

    i += sym.numberOfAuxSymbols;

    if (sym.storageClass == IMAGE_SYM_CLASS_EXTERNAL &&
        SYMBOL_TYPE_HI(sym) == 0x20 && sym.sectionNumber > 0) {
      // Auxiliary Format 1: Function Definitions

      for (std::uint8_t n = 0; n < sym.numberOfAuxSymbols; n++) {
        aux_symbol_f1 asym;

        // Read tag index
        if (!readDword(p->fileBuffer, offset, asym.tagIndex)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint32_t);

        // Read total size
        if (!readDword(p->fileBuffer, offset, asym.totalSize)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint32_t);

        // Read pointer to line number
        if (!readDword(p->fileBuffer, offset, asym.pointerToLineNumber)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint32_t);

        // Read pointer to next function
        if (!readDword(p->fileBuffer, offset, asym.pointerToNextFunction)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        // Skip the processed 4 bytes + unused 2 bytes
        offset += sizeof(std::uint8_t) * 6;

        // Save the record
        sym.aux_symbols_f1.push_back(asym);
      }

    } else if (sym.storageClass == IMAGE_SYM_CLASS_FUNCTION) {
      // Auxiliary Format 2: .bf and .ef Symbols

      for (std::uint8_t n = 0; n < sym.numberOfAuxSymbols; n++) {
        aux_symbol_f2 asym;
        // Skip unused 4 bytes
        offset += sizeof(std::uint32_t);

        // Read line number
        if (!readWord(p->fileBuffer, offset, asym.lineNumber)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint16_t);

        // Skip unused 6 bytes
        offset += sizeof(std::uint8_t) * 6;

        // Read pointer to next function
        if (!readDword(p->fileBuffer, offset, asym.pointerToNextFunction)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        // Skip the processed 4 bytes + unused 2 bytes
        offset += sizeof(std::uint8_t) * 6;

        // Save the record
        sym.aux_symbols_f2.push_back(asym);
      }

    } else if (sym.storageClass == IMAGE_SYM_CLASS_EXTERNAL &&
               sym.sectionNumber == IMAGE_SYM_UNDEFINED && sym.value == 0) {
      // Auxiliary Format 3: Weak Externals

      for (std::uint8_t n = 0; n < sym.numberOfAuxSymbols; n++) {
        aux_symbol_f3 asym;

        // Read line number
        if (!readDword(p->fileBuffer, offset, asym.tagIndex)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        // Read characteristics
        if (!readDword(p->fileBuffer, offset, asym.characteristics)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        // Skip unused 10 bytes
        offset += sizeof(std::uint8_t) * 10;

        // Save the record
        sym.aux_symbols_f3.push_back(asym);
      }

    } else if (sym.storageClass == IMAGE_SYM_CLASS_FILE) {
      // Auxiliary Format 4: Files

      for (std::uint8_t n = 0; n < sym.numberOfAuxSymbols; n++) {
        aux_symbol_f4 asym;

        // Read filename
        bool terminatorFound = false;

        for (std::uint16_t j = 0; j < SYMTAB_RECORD_LEN; j++) {
          // Save the raw field
          if (!readByte(p->fileBuffer, offset, asym.filename[j])) {
            PE_ERR(PEERR_MAGIC);
            return false;
          }

          offset += sizeof(std::uint8_t);

          if (asym.filename[j] == 0) {
            terminatorFound = true;
          }

          if (!terminatorFound) {
            asym.strFilename.push_back(static_cast<char>(asym.filename[j]));
          }
        }

        // Save the record
        sym.aux_symbols_f4.push_back(asym);
      }

    } else if (sym.storageClass == IMAGE_SYM_CLASS_STATIC) {
      // Auxiliary Format 5: Section Definitions

      for (std::uint8_t n = 0; n < sym.numberOfAuxSymbols; n++) {
        aux_symbol_f5 asym;

        // Read length
        if (!readDword(p->fileBuffer, offset, asym.length)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint32_t);

        // Read number of relocations
        if (!readWord(p->fileBuffer, offset, asym.numberOfRelocations)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint16_t);

        // Read number of line numbers
        if (!readWord(p->fileBuffer, offset, asym.numberOfLineNumbers)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint16_t);

        // Read checksum
        if (!readDword(p->fileBuffer, offset, asym.checkSum)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint32_t);

        // Read number
        if (!readWord(p->fileBuffer, offset, asym.number)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint16_t);

        // Read selection
        if (!readByte(p->fileBuffer, offset, asym.selection)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint8_t);

        // Skip unused 3 bytes
        offset += sizeof(std::uint8_t) * 3;

        // Save the record
        sym.aux_symbols_f5.push_back(asym);
      }

    } else {
      std::ios::fmtflags originalStreamFlags(std::cerr.flags());

      auto storageClassName = GetSymbolTableStorageClassName(sym.storageClass);
      if (storageClassName == nullptr) {
        std::cerr << "Warning: Skipping auxiliary symbol of type 0x" << std::hex
                  << static_cast<std::uint32_t>(sym.storageClass)
                  << " at offset 0x" << std::hex << offset << "\n";
      } else {
        std::cerr << "Warning: Skipping auxiliary symbol of type "
                  << storageClassName << " at offset 0x" << std::hex << offset
                  << "\n";
      }

      std::cerr.flags(originalStreamFlags);
      offset = nextSymbolOffset;
    }

    if (offset != nextSymbolOffset) {
      std::ios::fmtflags originalStreamFlags(std::cerr.flags());

      std::cerr << "Warning: Invalid internal offset (current: 0x" << std::hex
                << offset << ", expected: 0x" << std::hex << nextSymbolOffset
                << ")\n";

      std::cerr.flags(originalStreamFlags);
      offset = nextSymbolOffset;
    }
  }

  return true;
}

parsed_pe *ParsePEFromFile(const char *filePath) {
  // First, create a new parsed_pe structure
  // We pass std::nothrow parameter to new so in case of failure it returns
  // nullptr instead of throwing exception std::bad_alloc.
  parsed_pe *p = new (std::nothrow) parsed_pe();

  if (p == nullptr) {
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  // Make a new buffer object to hold just our file data
  p->fileBuffer = readFileToFileBuffer(filePath);

  if (p->fileBuffer == nullptr) {
    delete p;
    // err is set by readFileToFileBuffer
    return nullptr;
  }

  p->internal = new (std::nothrow) parsed_pe_internal();

  if (p->internal == nullptr) {
    deleteBuffer(p->fileBuffer);
    delete p;
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  // get header information
  bounded_buffer *remaining = nullptr;
  if (!getHeader(p->fileBuffer, p->peHeader, remaining)) {
    deleteBuffer(p->fileBuffer);
    delete p;
    // err is set by getHeader
    return nullptr;
  }

  bounded_buffer *file = p->fileBuffer;
  if (!getSections(remaining, file, p->peHeader.nt, p->internal->secs)) {
    deleteBuffer(remaining);
    deleteBuffer(p->fileBuffer);
    delete p;
    PE_ERR(PEERR_SECT);
    return nullptr;
  }

  if (!getResources(remaining, file, p->internal->secs, p->internal->rsrcs)) {
    deleteBuffer(remaining);
    deleteBuffer(p->fileBuffer);
    delete p;
    PE_ERR(PEERR_RESC);
    return nullptr;
  }

  // Get exports
  if (!getExports(p)) {
    deleteBuffer(remaining);
    deleteBuffer(p->fileBuffer);
    delete p;
    PE_ERR(PEERR_MAGIC);
    return nullptr;
  }

  // Get relocations, if exist
  if (!getRelocations(p)) {
    deleteBuffer(remaining);
    deleteBuffer(p->fileBuffer);
    delete p;
    PE_ERR(PEERR_MAGIC);
    return nullptr;
  }

  // Get imports
  if (!getImports(p)) {
    deleteBuffer(remaining);
    deleteBuffer(p->fileBuffer);
    delete p;
    return nullptr;
  }

  // Get symbol table
  if (!getSymbolTable(p)) {
    deleteBuffer(remaining);
    deleteBuffer(p->fileBuffer);
    delete p;
    return nullptr;
  }

  deleteBuffer(remaining);

  return p;
}

void DestructParsedPE(parsed_pe *p) {
  if (p == nullptr) {
    return;
  }

  deleteBuffer(p->fileBuffer);

  for (section s : p->internal->secs) {
    if (s.sectionData != nullptr) {
      deleteBuffer(s.sectionData);
    }
  }
  for (resource r : p->internal->rsrcs) {
    if (r.buf != nullptr) {
      deleteBuffer(r.buf);
    }
  }

  delete p->internal;
  delete p;
  return;
}

// iterate over the imports by VA and string
void IterImpVAString(parsed_pe *pe, iterVAStr cb, void *cbd) {
  std::vector<importent> &l = pe->internal->imports;

  for (importent i : l) {
    if (cb(cbd, i.addr, i.moduleName, i.symbolName) != 0) {
      break;
    }
  }

  return;
}

// iterate over relocations in the PE file
void IterRelocs(parsed_pe *pe, iterReloc cb, void *cbd) {
  std::vector<reloc> &l = pe->internal->relocs;

  for (reloc r : l) {
    if (cb(cbd, r.shiftedAddr, r.type) != 0) {
      break;
    }
  }

  return;
}

// Iterate over symbols (symbol table) in the PE file
void IterSymbols(parsed_pe *pe, iterSymbol cb, void *cbd) {
  std::vector<symbol> &l = pe->internal->symbols;

  for (symbol s : l) {
    if (cb(cbd,
           s.strName,
           s.value,
           s.sectionNumber,
           s.type,
           s.storageClass,
           s.numberOfAuxSymbols) != 0) {
      break;
    }
  }

  return;
}

// iterate over the exports by VA
void IterExpVA(parsed_pe *pe, iterExp cb, void *cbd) {
  std::vector<exportent> &l = pe->internal->exports;

  for (exportent i : l) {
    if (cb(cbd, i.addr, i.moduleName, i.symbolName) != 0) {
      break;
    }
  }

  return;
}

// iterate over sections
void IterSec(parsed_pe *pe, iterSec cb, void *cbd) {
  parsed_pe_internal *pint = pe->internal;

  for (section s : pint->secs) {
    if (cb(cbd, s.sectionBase, s.sectionName, s.sec, s.sectionData) != 0) {
      break;
    }
  }

  return;
}

bool ReadByteAtVA(parsed_pe *pe, VA v, std::uint8_t &b) {
  // find this VA in a section
  section s;

  if (!getSecForVA(pe->internal->secs, v, s)) {
    PE_ERR(PEERR_SECTVA);
    return false;
  }

  auto off = static_cast<std::uint32_t>(v - s.sectionBase);
  return readByte(s.sectionData, off, b);
}

bool GetEntryPoint(parsed_pe *pe, VA &v) {

  if (pe != nullptr) {
    nt_header_32 *nthdr = &pe->peHeader.nt;

    if (nthdr->OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      v = nthdr->OptionalHeader.AddressOfEntryPoint +
          nthdr->OptionalHeader.ImageBase;
    } else if (nthdr->OptionalMagic == NT_OPTIONAL_64_MAGIC) {
      v = nthdr->OptionalHeader64.AddressOfEntryPoint +
          nthdr->OptionalHeader64.ImageBase;
    } else {
      PE_ERR(PEERR_MAGIC);
      return false;
    }

    return true;
  }

  return false;
}

const char *GetMachineAsString(parsed_pe *pe) {
  if (pe == nullptr)
    return nullptr;

  switch (pe->peHeader.nt.FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_I386:
      return "x86";
    case IMAGE_FILE_MACHINE_ARMNT:
      return "ARM Thumb-2 Little-Endian";
    case IMAGE_FILE_MACHINE_IA64:
      return "Intel IA64";
    case IMAGE_FILE_MACHINE_AMD64:
      return "x64";
    case IMAGE_FILE_MACHINE_ARM64:
      return "ARM64";
    case IMAGE_FILE_MACHINE_CEE:
      return "CLR Pure MSIL";
    default:
      return nullptr;
  }
}

const char *GetSubsystemAsString(parsed_pe *pe) {
  if (pe == nullptr)
    return nullptr;

  std::uint16_t subsystem;
  if (pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC)
    subsystem = pe->peHeader.nt.OptionalHeader.Subsystem;
  else if (pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC)
    subsystem = pe->peHeader.nt.OptionalHeader64.Subsystem;
  else
    return nullptr;

  switch (subsystem) {
    case IMAGE_SUBSYSTEM_UNKNOWN:
      return "UNKNOWN";
    case IMAGE_SUBSYSTEM_NATIVE:
      return "NATIVE";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
      return "WINDOWS_GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
      return "WINDOWS_CUI";
    case IMAGE_SUBSYSTEM_OS2_CUI:
      return "OS2_CUI";
    case IMAGE_SUBSYSTEM_POSIX_CUI:
      return "POSIX_CUI";
    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
      return "NATIVE_WINDOWS";
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
      return "WINDOWS_CE_GUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
      return "EFI_APPLICATION";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
      return "EFI_BOOT_SERVICE_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
      return "EFI_RUNTIME_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_ROM:
      return "EFI_ROM";
    case IMAGE_SUBSYSTEM_XBOX:
      return "XBOX";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
      return "WINDOWS_BOOT_APPLICATION";
    case IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG:
      return "XBOX_CODE_CATALOG";
    default:
      return nullptr;
  }
}

} // namespace peparse
