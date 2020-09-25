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

#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <pe-parse/parse.h>

#include "vendor/argh.h"

using namespace peparse;

int printExps(void *N,
              const VA &funcAddr,
              const std::string &mod,
              const std::string &func) {
  static_cast<void>(N);

  auto address = static_cast<std::uint32_t>(funcAddr);

  std::cout << "EXP: ";
  std::cout << mod;
  std::cout << "!";
  std::cout << func;
  std::cout << ": 0x";
  std::cout << std::hex << address;
  std::cout << "\n";
  return 0;
}

int printImports(void *N,
                 const VA &impAddr,
                 const std::string &modName,
                 const std::string &symName) {
  static_cast<void>(N);

  auto address = static_cast<std::uint32_t>(impAddr);

  std::cout << "0x" << std::hex << address << " " << modName << "!" << symName;
  std::cout << "\n";
  return 0;
}

int printRelocs(void *N, const VA &relocAddr, const reloc_type &type) {
  static_cast<void>(N);

  std::cout << "TYPE: ";
  switch (type) {
    case RELOC_ABSOLUTE:
      std::cout << "ABSOLUTE";
      break;
    case RELOC_HIGH:
      std::cout << "HIGH";
      break;
    case RELOC_LOW:
      std::cout << "LOW";
      break;
    case RELOC_HIGHLOW:
      std::cout << "HIGHLOW";
      break;
    case RELOC_HIGHADJ:
      std::cout << "HIGHADJ";
      break;
    case RELOC_MIPS_JMPADDR:
      std::cout << "MIPS_JMPADDR";
      break;
    case RELOC_MIPS_JMPADDR16:
      std::cout << "MIPS_JMPADD16";
      break;
    case RELOC_DIR64:
      std::cout << "DIR64";
      break;
    default:
      std::cout << "UNKNOWN";
      break;
  }

  std::cout << " VA: 0x" << std::hex << relocAddr << "\n";

  return 0;
}

int printSymbols(void *N,
                 const std::string &strName,
                 const uint32_t &value,
                 const int16_t &sectionNumber,
                 const uint16_t &type,
                 const uint8_t &storageClass,
                 const uint8_t &numberOfAuxSymbols) {
  static_cast<void>(N);

  std::cout << "Symbol Name: " << strName << "\n";
  std::cout << "Symbol Value: 0x" << std::hex << value << "\n";

  std::cout << "Symbol Section Number: ";
  switch (sectionNumber) {
    case IMAGE_SYM_UNDEFINED:
      std::cout << "UNDEFINED";
      break;
    case IMAGE_SYM_ABSOLUTE:
      std::cout << "ABSOLUTE";
      break;
    case IMAGE_SYM_DEBUG:
      std::cout << "DEBUG";
      break;
    default:
      std::cout << sectionNumber;
      break;
  }
  std::cout << "\n";

  std::cout << "Symbol Type: ";
  switch (type) {
    case IMAGE_SYM_TYPE_NULL:
      std::cout << "NULL";
      break;
    case IMAGE_SYM_TYPE_VOID:
      std::cout << "VOID";
      break;
    case IMAGE_SYM_TYPE_CHAR:
      std::cout << "CHAR";
      break;
    case IMAGE_SYM_TYPE_SHORT:
      std::cout << "SHORT";
      break;
    case IMAGE_SYM_TYPE_INT:
      std::cout << "INT";
      break;
    case IMAGE_SYM_TYPE_LONG:
      std::cout << "LONG";
      break;
    case IMAGE_SYM_TYPE_FLOAT:
      std::cout << "FLOAT";
      break;
    case IMAGE_SYM_TYPE_DOUBLE:
      std::cout << "DOUBLE";
      break;
    case IMAGE_SYM_TYPE_STRUCT:
      std::cout << "STRUCT";
      break;
    case IMAGE_SYM_TYPE_UNION:
      std::cout << "UNION";
      break;
    case IMAGE_SYM_TYPE_ENUM:
      std::cout << "ENUM";
      break;
    case IMAGE_SYM_TYPE_MOE:
      std::cout << "IMAGE_SYM_TYPE_MOE";
      break;
    case IMAGE_SYM_TYPE_BYTE:
      std::cout << "BYTE";
      break;
    case IMAGE_SYM_TYPE_WORD:
      std::cout << "WORD";
      break;
    case IMAGE_SYM_TYPE_UINT:
      std::cout << "UINT";
      break;
    case IMAGE_SYM_TYPE_DWORD:
      std::cout << "DWORD";
      break;
    default:
      std::cout << "UNKNOWN";
      break;
  }
  std::cout << "\n";

  std::cout << "Symbol Storage Class: ";
  switch (storageClass) {
    case IMAGE_SYM_CLASS_END_OF_FUNCTION:
      std::cout << "FUNCTION";
      break;
    case IMAGE_SYM_CLASS_NULL:
      std::cout << "NULL";
      break;
    case IMAGE_SYM_CLASS_AUTOMATIC:
      std::cout << "AUTOMATIC";
      break;
    case IMAGE_SYM_CLASS_EXTERNAL:
      std::cout << "EXTERNAL";
      break;
    case IMAGE_SYM_CLASS_STATIC:
      std::cout << "STATIC";
      break;
    case IMAGE_SYM_CLASS_REGISTER:
      std::cout << "REGISTER";
      break;
    case IMAGE_SYM_CLASS_EXTERNAL_DEF:
      std::cout << "EXTERNAL DEF";
      break;
    case IMAGE_SYM_CLASS_LABEL:
      std::cout << "LABEL";
      break;
    case IMAGE_SYM_CLASS_UNDEFINED_LABEL:
      std::cout << "UNDEFINED LABEL";
      break;
    case IMAGE_SYM_CLASS_MEMBER_OF_STRUCT:
      std::cout << "MEMBER OF STRUCT";
      break;
    default:
      std::cout << "UNKNOWN";
      break;
  }
  std::cout << "\n";

  std::cout << "Symbol Number of Aux Symbols: "
            << static_cast<std::uint32_t>(numberOfAuxSymbols) << "\n";

  return 0;
}

int printRich(void *N, const rich_entry &r) {
  static_cast<void>(N);
  std::cout << std::dec;
  std::cout << std::setw(10) << "ProdId:" << std::setw(7) << r.ProductId;
  std::cout << std::setw(10) << "Build:" << std::setw(7) << r.BuildNumber;
  std::cout << std::setw(10) << "Name:" << std::setw(40)
            << GetRichProductName(r.BuildNumber) << " "
            << GetRichObjectType(r.ProductId);
  std::cout << std::setw(10) << "Count:" << std::setw(7) << r.Count << "\n";
  return 0;
}

int printRsrc(void *N, const resource &r) {
  static_cast<void>(N);

  if (r.type_str.length())
    std::cout << "Type (string): " << r.type_str << "\n";
  else
    std::cout << "Type: 0x" << std::hex << r.type << "\n";

  if (r.name_str.length())
    std::cout << "Name (string): " << r.name_str << "\n";
  else
    std::cout << "Name: 0x" << std::hex << r.name << "\n";

  if (r.lang_str.length())
    std::cout << "Lang (string): " << r.lang_str << "\n";
  else
    std::cout << "Lang: 0x" << std::hex << r.lang << "\n";

  std::cout << "Codepage: 0x" << std::hex << r.codepage << "\n";
  std::cout << "RVA: " << std::dec << r.RVA << "\n";
  std::cout << "Size: " << std::dec << r.size << "\n";
  return 0;
}

int printSecs(void *N,
              const VA &secBase,
              const std::string &secName,
              const image_section_header &s,
              const bounded_buffer *data) {
  static_cast<void>(N);
  static_cast<void>(s);

  std::cout << "Sec Name: " << secName << "\n";
  std::cout << "Sec Base: 0x" << std::hex << secBase << "\n";
  if (data)
    std::cout << "Sec Size: " << std::dec << data->bufLen << "\n";
  else
    std::cout << "Sec Size: 0"
              << "\n";
  return 0;
}

#define DUMP_FIELD(x)           \
  std::cout << "" #x << ": 0x"; \
  std::cout << std::hex << static_cast<std::uint64_t>(p->peHeader.x) << "\n";
#define DUMP_DEC_FIELD(x)     \
  std::cout << "" #x << ": "; \
  std::cout << std::dec << static_cast<std::uint64_t>(p->peHeader.x) << "\n";
#define DUMP_BOOL_FIELD(x)    \
  std::cout << "" #x << ": "; \
  std::cout << std::boolalpha << static_cast<bool>(p->peHeader.x) << "\n";

int main(int argc, char *argv[]) {

  argh::parser cmdl(argv);

  if (cmdl[{"-h", "--help"}] || argc <= 1) {
    std::cout << "dump-pe utility from Trail of Bits\n";
    std::cout << "Repository: https://github.com/trailofbits/pe-parse\n\n";
    std::cout << "Usage:\n\tdump-pe /path/to/executable.exe\n";
    return 0;
  } else if (cmdl[{"-v", "--version"}]) {
    std::cout << "dump-pe (pe-parse) version " << PEPARSE_VERSION << "\n";
    return 0;
  }

  parsed_pe *p = ParsePEFromFile(cmdl[1].c_str());

  if (p == nullptr) {
    std::cout << "Error: " << GetPEErr() << " (" << GetPEErrString() << ")"
              << "\n";
    std::cout << "Location: " << GetPEErrLoc() << "\n";
    return 1;
  }

  if (p != NULL) {
    // Print DOS header
    DUMP_FIELD(dos.e_magic);
    DUMP_FIELD(dos.e_cp);
    DUMP_FIELD(dos.e_crlc);
    DUMP_FIELD(dos.e_cparhdr);
    DUMP_FIELD(dos.e_minalloc);
    DUMP_FIELD(dos.e_maxalloc);
    DUMP_FIELD(dos.e_ss);
    DUMP_FIELD(dos.e_sp);
    DUMP_FIELD(dos.e_csum);
    DUMP_FIELD(dos.e_ip);
    DUMP_FIELD(dos.e_cs);
    DUMP_FIELD(dos.e_lfarlc);
    DUMP_FIELD(dos.e_ovno);
    DUMP_FIELD(dos.e_res[0]);
    DUMP_FIELD(dos.e_res[1]);
    DUMP_FIELD(dos.e_res[2]);
    DUMP_FIELD(dos.e_res[3]);
    DUMP_FIELD(dos.e_oemid);
    DUMP_FIELD(dos.e_oeminfo);
    DUMP_FIELD(dos.e_res2[0]);
    DUMP_FIELD(dos.e_res2[1]);
    DUMP_FIELD(dos.e_res2[2]);
    DUMP_FIELD(dos.e_res2[3]);
    DUMP_FIELD(dos.e_res2[4]);
    DUMP_FIELD(dos.e_res2[5]);
    DUMP_FIELD(dos.e_res2[6]);
    DUMP_FIELD(dos.e_res2[7]);
    DUMP_FIELD(dos.e_res2[8]);
    DUMP_FIELD(dos.e_res2[9]);
    DUMP_FIELD(dos.e_lfanew);
    // Print Rich header info
    DUMP_BOOL_FIELD(rich.isPresent);
    if (p->peHeader.rich.isPresent) {
      DUMP_FIELD(rich.DecryptionKey);
      DUMP_FIELD(rich.Checksum);
      DUMP_BOOL_FIELD(rich.isValid);
      IterRich(p, printRich, NULL);
    }
    // print out some things
    DUMP_FIELD(nt.Signature);
    DUMP_FIELD(nt.FileHeader.Machine);
    DUMP_FIELD(nt.FileHeader.NumberOfSections);
    DUMP_DEC_FIELD(nt.FileHeader.TimeDateStamp);
    DUMP_FIELD(nt.FileHeader.PointerToSymbolTable);
    DUMP_DEC_FIELD(nt.FileHeader.NumberOfSymbols);
    DUMP_FIELD(nt.FileHeader.SizeOfOptionalHeader);
    DUMP_FIELD(nt.FileHeader.Characteristics);
    if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      DUMP_FIELD(nt.OptionalHeader.Magic);
      DUMP_DEC_FIELD(nt.OptionalHeader.MajorLinkerVersion);
      DUMP_DEC_FIELD(nt.OptionalHeader.MinorLinkerVersion);
      DUMP_FIELD(nt.OptionalHeader.SizeOfCode);
      DUMP_FIELD(nt.OptionalHeader.SizeOfInitializedData);
      DUMP_FIELD(nt.OptionalHeader.SizeOfUninitializedData);
      DUMP_FIELD(nt.OptionalHeader.AddressOfEntryPoint);
      DUMP_FIELD(nt.OptionalHeader.BaseOfCode);
      DUMP_FIELD(nt.OptionalHeader.BaseOfData);
      DUMP_FIELD(nt.OptionalHeader.ImageBase);
      DUMP_FIELD(nt.OptionalHeader.SectionAlignment);
      DUMP_FIELD(nt.OptionalHeader.FileAlignment);
      DUMP_DEC_FIELD(nt.OptionalHeader.MajorOperatingSystemVersion);
      DUMP_DEC_FIELD(nt.OptionalHeader.MinorOperatingSystemVersion);
      DUMP_DEC_FIELD(nt.OptionalHeader.Win32VersionValue);
      DUMP_FIELD(nt.OptionalHeader.SizeOfImage);
      DUMP_FIELD(nt.OptionalHeader.SizeOfHeaders);
      DUMP_FIELD(nt.OptionalHeader.CheckSum);
      DUMP_FIELD(nt.OptionalHeader.Subsystem);
      DUMP_FIELD(nt.OptionalHeader.DllCharacteristics);
      DUMP_FIELD(nt.OptionalHeader.SizeOfStackReserve);
      DUMP_FIELD(nt.OptionalHeader.SizeOfStackCommit);
      DUMP_FIELD(nt.OptionalHeader.SizeOfHeapReserve);
      DUMP_FIELD(nt.OptionalHeader.SizeOfHeapCommit);
      DUMP_FIELD(nt.OptionalHeader.LoaderFlags);
      DUMP_DEC_FIELD(nt.OptionalHeader.NumberOfRvaAndSizes);
    } else {
      DUMP_FIELD(nt.OptionalHeader64.Magic);
      DUMP_DEC_FIELD(nt.OptionalHeader64.MajorLinkerVersion);
      DUMP_DEC_FIELD(nt.OptionalHeader64.MinorLinkerVersion);
      DUMP_FIELD(nt.OptionalHeader64.SizeOfCode);
      DUMP_FIELD(nt.OptionalHeader64.SizeOfInitializedData);
      DUMP_FIELD(nt.OptionalHeader64.SizeOfUninitializedData);
      DUMP_FIELD(nt.OptionalHeader64.AddressOfEntryPoint);
      DUMP_FIELD(nt.OptionalHeader64.BaseOfCode);
      DUMP_FIELD(nt.OptionalHeader64.ImageBase);
      DUMP_FIELD(nt.OptionalHeader64.SectionAlignment);
      DUMP_FIELD(nt.OptionalHeader64.FileAlignment);
      DUMP_DEC_FIELD(nt.OptionalHeader64.MajorOperatingSystemVersion);
      DUMP_DEC_FIELD(nt.OptionalHeader64.MinorOperatingSystemVersion);
      DUMP_DEC_FIELD(nt.OptionalHeader64.Win32VersionValue);
      DUMP_FIELD(nt.OptionalHeader64.SizeOfImage);
      DUMP_FIELD(nt.OptionalHeader64.SizeOfHeaders);
      DUMP_FIELD(nt.OptionalHeader64.CheckSum);
      DUMP_FIELD(nt.OptionalHeader64.Subsystem);
      DUMP_FIELD(nt.OptionalHeader64.DllCharacteristics);
      DUMP_FIELD(nt.OptionalHeader64.SizeOfStackReserve);
      DUMP_FIELD(nt.OptionalHeader64.SizeOfStackCommit);
      DUMP_FIELD(nt.OptionalHeader64.SizeOfHeapReserve);
      DUMP_FIELD(nt.OptionalHeader64.SizeOfHeapCommit);
      DUMP_FIELD(nt.OptionalHeader64.LoaderFlags);
      DUMP_DEC_FIELD(nt.OptionalHeader64.NumberOfRvaAndSizes);
    }

#undef DUMP_FIELD
#undef DUMP_DEC_FIELD

    std::cout << "Imports: "
              << "\n";
    IterImpVAString(p, printImports, NULL);
    std::cout << "Relocations: "
              << "\n";
    IterRelocs(p, printRelocs, NULL);
    std::cout << "Symbols (symbol table): "
              << "\n";
    IterSymbols(p, printSymbols, NULL);
    std::cout << "Sections: "
              << "\n";
    IterSec(p, printSecs, NULL);
    std::cout << "Exports: "
              << "\n";
    IterExpVA(p, printExps, NULL);

    // read the first 8 bytes from the entry point and print them
    VA entryPoint;
    if (GetEntryPoint(p, entryPoint)) {
      std::cout << "First 8 bytes from entry point (0x";
      std::cout << std::hex << entryPoint << "):"
                << "\n";
      for (std::size_t i = 0; i < 8; i++) {
        std::uint8_t b;
        if (!ReadByteAtVA(p, i + entryPoint, b)) {
          std::cout << " ERR";
        } else {
          std::cout << " 0x" << std::hex << static_cast<int>(b);
        }
      }

      std::cout << "\n";
    }

    std::cout << "Resources: "
              << "\n";
    IterRsrc(p, printRsrc, NULL);

    DestructParsedPE(p);

    return 0;
  }
}
