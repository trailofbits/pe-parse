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

#include <list>
#include "parse.h"
#include "nt-headers.h"

using namespace std;
using namespace boost;

struct section {
  string                sectionName;
  ::uint32_t            sectionBase;
  bounded_buffer        *sectionData;
  image_section_header  sec;
};

struct importent {
  RVA     addr;
  string  symbolName;
  string  moduleName;
};

struct reloc {
  RVA shiftedAddr;
  RVA shiftedTo;
};

struct parsed_pe_internal {
  list<section>   secs;
  list<importent> imports;
};

bool getSecForRVA(list<section> &secs, RVA v, section &sec) {
  for(list<section>::iterator it = secs.begin(), e = secs.end();
      it != e;
      ++it)
  {
    section s = *it;
  
    ::uint32_t  low = s.sectionBase;
    ::uint32_t  high = low + s.sec.Misc.VirtualSize;

    if(v >= low && v < high) {
      sec = s;
      return true;
    }
  }

  return false;
}

bool getSections( bounded_buffer  *b, 
                  bounded_buffer  *fileBegin,
                  nt_header_32    &nthdr, 
                  list<section>   &secs) {
  if(b == NULL) {
    return false;
  }

  //get each of the sections...
  for(::uint32_t i = 0; i < nthdr.FileHeader.NumberOfSections; i++) {
    image_section_header  curSec;
    
    ::uint32_t  o = i*sizeof(image_section_header);
    for(::uint32_t k = 0; k < NT_SHORT_NAME_LEN; k++) {
      readByte(b, o+k, curSec.Name[k]);
    }
#define READ_WORD(x) \
  if(readWord(b, o+_offset(image_section_header, x), curSec.x) == false) { \
    return false; \
  } 
#define READ_DWORD(x) \
  if(readDword(b, o+_offset(image_section_header, x), curSec.x) == false) { \
    return false; \
  } 
 
    READ_DWORD(Misc.VirtualSize);
    READ_DWORD(VirtualAddress);
    READ_DWORD(SizeOfRawData);
    READ_DWORD(PointerToRawData);
    READ_DWORD(PointerToRelocations);
    READ_DWORD(PointerToLinenumbers);
    READ_WORD(NumberOfRelocations);
    READ_WORD(NumberOfLinenumbers);
    READ_DWORD(Characteristics);
#undef READ_WORD
#undef READ_DWORD

    //now we have the section header information, so fill in a section 
    //object appropriately
    section thisSec;
    for(::uint32_t i = 0; i < NT_SHORT_NAME_LEN; i++) {
      ::uint8_t c = curSec.Name[i];
      if(c == 0) {
        break;
      }

      thisSec.sectionName.push_back((char)c);
    }

    thisSec.sectionBase = nthdr.OptionalHeader.ImageBase+curSec.VirtualAddress;
    thisSec.sec = curSec;
    ::uint32_t  lowOff = curSec.PointerToRawData;
    ::uint32_t  highOff = lowOff+curSec.SizeOfRawData;
    thisSec.sectionData = splitBuffer(fileBegin, lowOff, highOff);
    
    secs.push_back(thisSec);
  }

  return true;
}

bool readOptionalHeader(bounded_buffer *b, optional_header_32 &header) {
#define READ_WORD(x) \
  if(readWord(b, _offset(optional_header_32, x), header.x) == false) { \
    return false; \
  } 
#define READ_DWORD(x) \
  if(readDword(b, _offset(optional_header_32, x), header.x) == false) { \
    return false; \
  } 
#define READ_BYTE(x) \
  if(readByte(b, _offset(optional_header_32, x), header.x) == false) { \
    return false; \
  }

  READ_WORD(Magic);

  if(header.Magic != NT_OPTIONAL_32_MAGIC) {
    return false;
  }

  READ_BYTE(MajorLinkerVersion);
  READ_BYTE(MinorLinkerVersion);
  READ_DWORD(SizeOfCode);
  READ_DWORD(SizeOfInitializedData);
  READ_DWORD(SizeOfUninitializedData);
  READ_DWORD(AddressOfEntryPoint);
  READ_DWORD(BaseOfCode);
  READ_DWORD(BaseOfData);
  READ_DWORD(ImageBase);
  READ_DWORD(SectionAlignment);
  READ_DWORD(FileAlignment);
  READ_WORD(MajorOperatingSystemVersion);
  READ_WORD(MinorOperatingSystemVersion);
  READ_WORD(MajorImageVersion);
  READ_WORD(MinorImageVersion);
  READ_WORD(MajorSubsystemVersion);
  READ_WORD(MinorSubsystemVersion);
  READ_DWORD(Win32VersionValue);
  READ_DWORD(SizeOfImage);
  READ_DWORD(SizeOfHeaders);
  READ_DWORD(CheckSum);
  READ_WORD(Subsystem);
  READ_WORD(DllCharacteristics);
  READ_DWORD(SizeOfStackReserve);
  READ_DWORD(SizeOfStackCommit);
  READ_DWORD(SizeOfHeapReserve);
  READ_DWORD(SizeOfHeapCommit);
  READ_DWORD(LoaderFlags);
  READ_DWORD(NumberOfRvaAndSizes);

#undef READ_WORD
#undef READ_DWORD
#undef READ_BYTE

  for(::uint32_t i = 0; i < header.NumberOfRvaAndSizes; i++) {
    ::uint32_t  c = (i*sizeof(data_directory));
    c+= _offset(optional_header_32, DataDirectory[0]);
    ::uint32_t  o; 

    o = c + _offset(data_directory, VirtualAddress);
    if(readDword(b, o, header.DataDirectory[i].VirtualAddress) == false) {
      return false;
    }

    o = c + _offset(data_directory, Size);
    if(readDword(b, o, header.DataDirectory[i].Size) == false) {
      return false;
    }
  }

  return true;
}

bool readFileHeader(bounded_buffer *b, file_header &header) {
#define READ_WORD(x) \
  if(readWord(b, _offset(file_header, x), header.x) == false) { \
    return false; \
  } 
#define READ_DWORD(x) \
  if(readDword(b, _offset(file_header, x), header.x) == false) { \
    return false; \
  } 

  READ_WORD(Machine);
  READ_WORD(NumberOfSections);
  READ_DWORD(TimeDateStamp);
  READ_DWORD(PointerToSymbolTable);
  READ_DWORD(NumberOfSymbols);
  READ_WORD(SizeOfOptionalHeader);
  READ_WORD(Characteristics);

#undef READ_DWORD
#undef READ_WORD
  return true;
}

bool readNtHeader(bounded_buffer *b, nt_header_32 &header) {
  if(b == NULL) {
    return false;
  }

  ::uint32_t  pe_magic;
  ::uint32_t  curOffset =0;
  if(readDword(b, curOffset, pe_magic) == false || pe_magic != NT_MAGIC) {
    return false;
  }

  header.Signature = pe_magic;
  bounded_buffer  *fhb = 
    splitBuffer(b, _offset(nt_header_32, FileHeader), b->bufLen);
  
  if(fhb == NULL) {
    return false;
  }

  if(readFileHeader(fhb, header.FileHeader) == false) {
    deleteBuffer(fhb);
    return false;
  }

  bounded_buffer *ohb = 
    splitBuffer(b, _offset(nt_header_32, OptionalHeader), b->bufLen);

  if(ohb == NULL) {
    deleteBuffer(fhb);
    return false;
  }

  if(readOptionalHeader(ohb, header.OptionalHeader) == false) {
    deleteBuffer(ohb);
    deleteBuffer(fhb);
    return false;
  }

  deleteBuffer(ohb);
  deleteBuffer(fhb);

  return true;
}

bool getHeader(bounded_buffer *file, pe_header &p, bounded_buffer *&rem) {
  if(file == NULL) {
    return false;
  }

  //start by reading MZ
  ::uint16_t  tmp = 0;
  ::uint32_t  curOffset = 0;
  readWord(file, curOffset, tmp);
  if(tmp != MZ_MAGIC) {
    return false;
  }

  //read the offset to the NT headers
  ::uint32_t  offset;
  if(readDword(file, _offset(dos_header, e_lfanew), offset) == false) {
    return false;
  }
  curOffset += offset; 

  //now, we can read out the fields of the NT headers
  bounded_buffer  *ntBuf = splitBuffer(file, curOffset, file->bufLen);
  if(readNtHeader(ntBuf, p.nt) == false) {
    return false;
  }

  //update 'rem' to point to the space after the header
  rem = splitBuffer(ntBuf, sizeof(nt_header_32), ntBuf->bufLen);
  deleteBuffer(ntBuf);

  return true;
}

parsed_pe *ParsePEFromFile(const char *filePath) {
  //first, create a new parsed_pe structure
  parsed_pe *p = new parsed_pe();

  if(p == NULL) {
    return NULL;
  }

  //make a new buffer object to hold just our file data 
  p->fileBuffer = readFileToFileBuffer(filePath);

  if(p->fileBuffer == NULL) {
    delete p;
    return NULL;
  }

  p->internal = new parsed_pe_internal();

  if(p->internal == NULL) {
    deleteBuffer(p->fileBuffer);
    delete p;
    return NULL;
  }

  //get header information
  bounded_buffer  *remaining = NULL;
  if(getHeader(p->fileBuffer, p->peHeader, remaining) == false) {
    deleteBuffer(p->fileBuffer);
    delete p;
    return NULL;
  }

  bounded_buffer  *file = p->fileBuffer;
  if(getSections(remaining, file, p->peHeader.nt, p->internal->secs) == false) {
    deleteBuffer(remaining);
    deleteBuffer(p->fileBuffer);
    delete p;
    return NULL;
  }
  //get exports
  data_directory  exportDir = 
    p->peHeader.nt.OptionalHeader.DataDirectory[DIR_EXPORT];

  //get relocations
  data_directory  relocDir = 
    p->peHeader.nt.OptionalHeader.DataDirectory[DIR_BASERELOC];

  //get imports
  data_directory  importDir = 
    p->peHeader.nt.OptionalHeader.DataDirectory[DIR_IMPORT];
  //get section for the RVA in importDir
  section c;
  ::uint32_t  addr = 
    importDir.VirtualAddress + p->peHeader.nt.OptionalHeader.ImageBase;

  if(getSecForRVA(p->internal->secs, addr, c) == false) {
    deleteBuffer(remaining);
    deleteBuffer(p->fileBuffer);
    delete p;
    return NULL;
  }

  //get import directory from this section
  ::uint32_t  offt = addr - c.sectionBase;
  do {
#define READ_DWORD(x) \
  if(readDword(c.sectionData, offt+_offset(import_dir_entry, x), curEnt.x) == false) { \
    return NULL; \
  }
    //read each directory entry out
    import_dir_entry  curEnt;

    READ_DWORD(LookupTableRVA);
    READ_DWORD(TimeStamp);
    READ_DWORD(ForwarderChain);
    READ_DWORD(NameRVA);
    READ_DWORD(AddressRVA);

    //are all the fields in curEnt null? then we break
    if( curEnt.LookupTableRVA == 0 && 
        curEnt.NameRVA == 0 &&
        curEnt.AddressRVA == 0) {
      break;
    }

    //then, try and get the name of this particular module...
    ::uint32_t  name = curEnt.NameRVA + p->peHeader.nt.OptionalHeader.ImageBase;
    section nameSec;
    if(getSecForRVA(p->internal->secs, name, nameSec) == false) {
      return NULL;
    }

    ::uint32_t  nameOff = name - nameSec.sectionBase;
    string      modName;
    ::uint8_t   c;
    do {
      if(readByte(nameSec.sectionData, nameOff, c) == false) {
        return NULL;
      }
      
      if(c == 0) {
        break;
      }

      modName.push_back(c);
      nameOff++;
    }while(true);

    //then, try and get all of the sub-symbols

    offt += sizeof(import_dir_entry);
  } while(true);

  deleteBuffer(remaining);

#undef READ_DWORD
  return p;
}

void DestructParsedPE(parsed_pe *p) {

  delete p;
  return;
}

//iterate over the imports by RVA and string
void IterImpRVAString(parsed_pe *pe, iterRVAStr cb, void *cbd) {

  return;
}

//iterate over relocations in the PE file
void IterRelocs(parsed_pe *pe, iterReloc cb, void *cbd) {

  return;
}

//iterate over the exports by RVA
void IterExpRVA(parsed_pe *pe, iterRVA cb, void *cbd) {

  return;
}

//iterate over sections
void IterSec(parsed_pe *pe, iterSec cb, void *cbd) {
  parsed_pe_internal  *pint = pe->internal;

  for(list<section>::iterator sit = pint->secs.begin(), e = pint->secs.end();
      sit != e;
      ++sit)
  {
    section s = *sit;
    cb(cbd, s.sectionBase, s.sectionName, s.sectionData);
  }

  return;
}
