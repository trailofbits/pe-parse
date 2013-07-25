#include <fstream>
#include "parse.h"

using namespace boost;
using namespace std;

bool readByte(bounded_buffer *b, ::uint32_t offset, ::uint8_t &out) {
  if(offset >= b->bufLen) {
    return false;
  }

  ::uint8_t *tmp = (b->buf+offset);
  out = *tmp;

  return true;
}

bool readWord(bounded_buffer *b, ::uint32_t offset, ::uint16_t &out) {
  if(offset >= b->bufLen) {
    return false;
  }

  ::uint16_t  *tmp = (::uint16_t *)(b->buf+offset);
  out = *tmp;

  return true;
}

bool readDword(bounded_buffer *b, ::uint32_t offset, ::uint32_t &out) {
  if(offset >= b->bufLen) {
    return false;
  }

  ::uint32_t  *tmp = (::uint32_t *)(b->buf+offset);
  out = *tmp;

  return true;
}


bounded_buffer *readFileToFileBuffer(const char *filePath) {
  //make a buffer object
  bounded_buffer  *p = new bounded_buffer();

  if(p == NULL) {
    return NULL;
  }

  //open the file in binary mode
  ifstream  inFile(filePath, ios::in|ios::binary|ios::ate);

  if(inFile.is_open()) {
    size_t  fileSize = inFile.tellg();

    if(fileSize == 0) {
      delete p;
      return NULL;
    }

    p->buf = (::uint8_t *)malloc(fileSize);

    if(p->buf == NULL) {
      delete p;
      return NULL;
    }

    memset(p->buf, 0, fileSize);
    p->bufLen = fileSize;
    p->copy = false;
    
    inFile.seekg(0, ios::beg);
    inFile.read((char *)p->buf, fileSize);
    inFile.close();
  } else {
    delete p;
    return NULL;
  }

  return p;
}

//split buffer inclusively from from to to by offset
bounded_buffer *splitBuffer(bounded_buffer *b, ::uint32_t from, ::uint32_t to) {
  //safety checks
  if(to < from || to > b->bufLen) {
    return NULL;
  }
  
  //make a new buffer
  bounded_buffer  *newBuff = new bounded_buffer();

  if(newBuff == NULL) {
    return NULL;
  }

  newBuff->copy = true;
  newBuff->buf = b->buf+from;
  newBuff->bufLen = (to-from);

  return newBuff;
}

void deleteBuffer(bounded_buffer *b) {
  if(b->copy == false) {
    free(b->buf);
  }

  delete b;
}

