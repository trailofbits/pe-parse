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

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

#include <parser-library/parse.h>

using namespace peparse;

int printExps(void *N, VA funcAddr, std::string &mod, std::string &func) {
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
                 VA impAddr,
                 const std::string &modName,
                 const std::string &symName) {
  static_cast<void>(N);

  auto address = static_cast<std::uint32_t>(impAddr);

  std::cout << "0x" << std::hex << address << " " << modName << "!" << symName;
  std::cout << "\n";
  return 0;
}

int printRelocs(void *N, VA relocAddr, reloc_type type) {
  static_cast<void>(N);

  std::cout << "TYPE: ";
  switch (type) {
    case ABSOLUTE:
      std::cout << "ABSOLUTE";
      break;
    case HIGH:
      std::cout << "HIGH";
      break;
    case LOW:
      std::cout << "LOW";
      break;
    case HIGHLOW:
      std::cout << "HIGHLOW";
      break;
    case HIGHADJ:
      std::cout << "HIGHADJ";
      break;
    case MIPS_JMPADDR:
      std::cout << "MIPS_JMPADDR";
      break;
    case MIPS_JMPADDR16:
      std::cout << "MIPS_JMPADD16";
      break;
    case DIR64:
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
                 std::string &strName,
                 uint32_t &value,
                 int16_t &sectionNumber,
                 uint16_t &type,
                 uint8_t &storageClass,
                 uint8_t &numberOfAuxSymbols) {
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

int printRsrc(void *N, resource r) {
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
              VA secBase,
              std::string &secName,
              image_section_header s,
              bounded_buffer *data) {
  static_cast<void>(N);
  static_cast<void>(s);

  std::cout << "Sec Name: " << secName << "\n";
  std::cout << "Sec Base: 0x" << std::hex << secBase << "\n";
  if (data)
    std::cout << "Sec Size: " << std::dec << data->bufLen << "\n";
  else
    std::cout << "Sec Size: 0" << "\n";
  return 0;
}

#define DUMP_FIELD(x)                                                   \
  std::cout << "" #x << ": 0x";                                         \
  std::cout << std::hex << static_cast<std::uint64_t>(p->peHeader.nt.x) \
            << "\n";
#define DUMP_DEC_FIELD(x)                                               \
  std::cout << "" #x << ": ";                                           \
  std::cout << std::dec << static_cast<std::uint64_t>(p->peHeader.nt.x) \
            << "\n";

int main(int argc, char *argv[]) {
  if (argc != 2 || (argc == 2 && std::strcmp(argv[1], "--help") == 0)) {
    std::cout << "dump-pe utility from Trail of Bits\n";
    std::cout << "Repository: https://github.com/trailofbits/pe-parse\n\n";
    std::cout << "Usage:\n\tdump-pe /path/to/executable.exe\n";
    return 1;
  }

  parsed_pe *p = ParsePEFromFile(argv[1]);

  if (p != NULL) {
    // print out some things
    DUMP_FIELD(Signature);
    DUMP_FIELD(FileHeader.Machine);
    DUMP_FIELD(FileHeader.NumberOfSections);
    DUMP_DEC_FIELD(FileHeader.TimeDateStamp);
    DUMP_FIELD(FileHeader.PointerToSymbolTable);
    DUMP_DEC_FIELD(FileHeader.NumberOfSymbols);
    DUMP_FIELD(FileHeader.SizeOfOptionalHeader);
    DUMP_FIELD(FileHeader.Characteristics);
    if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      DUMP_FIELD(OptionalHeader.Magic);
      DUMP_DEC_FIELD(OptionalHeader.MajorLinkerVersion);
      DUMP_DEC_FIELD(OptionalHeader.MinorLinkerVersion);
      DUMP_FIELD(OptionalHeader.SizeOfCode);
      DUMP_FIELD(OptionalHeader.SizeOfInitializedData);
      DUMP_FIELD(OptionalHeader.SizeOfUninitializedData);
      DUMP_FIELD(OptionalHeader.AddressOfEntryPoint);
      DUMP_FIELD(OptionalHeader.BaseOfCode);
      DUMP_FIELD(OptionalHeader.BaseOfData);
      DUMP_FIELD(OptionalHeader.ImageBase);
      DUMP_FIELD(OptionalHeader.SectionAlignment);
      DUMP_FIELD(OptionalHeader.FileAlignment);
      DUMP_DEC_FIELD(OptionalHeader.MajorOperatingSystemVersion);
      DUMP_DEC_FIELD(OptionalHeader.MinorOperatingSystemVersion);
      DUMP_DEC_FIELD(OptionalHeader.Win32VersionValue);
      DUMP_FIELD(OptionalHeader.SizeOfImage);
      DUMP_FIELD(OptionalHeader.SizeOfHeaders);
      DUMP_FIELD(OptionalHeader.CheckSum);
      DUMP_FIELD(OptionalHeader.Subsystem);
      DUMP_FIELD(OptionalHeader.DllCharacteristics);
      DUMP_FIELD(OptionalHeader.SizeOfStackReserve);
      DUMP_FIELD(OptionalHeader.SizeOfStackCommit);
      DUMP_FIELD(OptionalHeader.SizeOfHeapReserve);
      DUMP_FIELD(OptionalHeader.SizeOfHeapCommit);
      DUMP_FIELD(OptionalHeader.LoaderFlags);
      DUMP_DEC_FIELD(OptionalHeader.NumberOfRvaAndSizes);
    } else {
      DUMP_FIELD(OptionalHeader64.Magic);
      DUMP_DEC_FIELD(OptionalHeader64.MajorLinkerVersion);
      DUMP_DEC_FIELD(OptionalHeader64.MinorLinkerVersion);
      DUMP_FIELD(OptionalHeader64.SizeOfCode);
      DUMP_FIELD(OptionalHeader64.SizeOfInitializedData);
      DUMP_FIELD(OptionalHeader64.SizeOfUninitializedData);
      DUMP_FIELD(OptionalHeader64.AddressOfEntryPoint);
      DUMP_FIELD(OptionalHeader64.BaseOfCode);
      DUMP_FIELD(OptionalHeader64.ImageBase);
      DUMP_FIELD(OptionalHeader64.SectionAlignment);
      DUMP_FIELD(OptionalHeader64.FileAlignment);
      DUMP_DEC_FIELD(OptionalHeader64.MajorOperatingSystemVersion);
      DUMP_DEC_FIELD(OptionalHeader64.MinorOperatingSystemVersion);
      DUMP_DEC_FIELD(OptionalHeader64.Win32VersionValue);
      DUMP_FIELD(OptionalHeader64.SizeOfImage);
      DUMP_FIELD(OptionalHeader64.SizeOfHeaders);
      DUMP_FIELD(OptionalHeader64.CheckSum);
      DUMP_FIELD(OptionalHeader64.Subsystem);
      DUMP_FIELD(OptionalHeader64.DllCharacteristics);
      DUMP_FIELD(OptionalHeader64.SizeOfStackReserve);
      DUMP_FIELD(OptionalHeader64.SizeOfStackCommit);
      DUMP_FIELD(OptionalHeader64.SizeOfHeapReserve);
      DUMP_FIELD(OptionalHeader64.SizeOfHeapCommit);
      DUMP_FIELD(OptionalHeader64.LoaderFlags);
      DUMP_DEC_FIELD(OptionalHeader64.NumberOfRvaAndSizes);
    }

#undef DUMP_FIELD
#undef DUMP_DEC_FIELD

    std::cout << "Imports: " << "\n";
    IterImpVAString(p, printImports, NULL);
    std::cout << "Relocations: " << "\n";
    IterRelocs(p, printRelocs, NULL);
    std::cout << "Symbols (symbol table): " << "\n";
    IterSymbols(p, printSymbols, NULL);
    std::cout << "Sections: " << "\n";
    IterSec(p, printSecs, NULL);
    std::cout << "Exports: " << "\n";
    IterExpVA(p, printExps, NULL);

    // read the first 8 bytes from the entry point and print them
    VA entryPoint;
    if (GetEntryPoint(p, entryPoint)) {
      std::cout << "First 8 bytes from entry point (0x";

      std::cout << std::hex << entryPoint << "):" << "\n";
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

    std::cout << "Resources: " << "\n";
    IterRsrc(p, printRsrc, NULL);
    DestructParsedPE(p);
  } else {
    std::cout << "Error: " << GetPEErr() << " (" << GetPEErrString() << ")"
              << "\n";
    std::cout << "Location: " << GetPEErrLoc() << "\n";
  }

  return 0;
}
