#include <list>
#include "parse.h"
#include "nt-headers.h"

using namespace std;
using namespace boost;

struct section {
  string          sectionName;
  RVA             sectionBase;
  bounded_buffer  sectionData;
};

struct reloc {
  RVA shiftedAddr;
  RVA shiftedTo;
};

struct parsed_pe_internal {
  list<section>   secs;
};

list<section> getSections(bounded_buffer *file) {
  list<section> sections;

  return sections;
}

bool readNtHeader(bounded_buffer *b, nt_header_32 &header) {
  if(b == NULL) {
    return false;
  }

  return false;
}

bool getHeader(bounded_buffer *file) {
  pe_header p;

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
  curOffset = _offset(dos_header, e_lfanew)+curOffset;
  if(readDword(file, curOffset, offset) == false) {
    return false;
  }
  curOffset += offset; 

  //now, we can read out the fields of the NT headers
  nt_header_32 nt;
  if(readNtHeader(splitBuffer(file, curOffset, file->bufLen-1), nt) == false) {
    return false;
  }

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

  //now, we need to do some actual PE parsing and file carving.

  //get header information
  if(getHeader(p->fileBuffer) == false) {
    deleteBuffer(p->fileBuffer);
    delete p;
    return NULL;
  }

  //get the raw data of each section
  p->internal->secs = getSections(p->fileBuffer);

  //get exports

  //get relocations

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
    cb(cbd, s.sectionBase, s.sectionName, &s.sectionData);
  }

  return;
}
