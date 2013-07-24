#include "parse.h"

using namespace boost;

bool readByte(bounded_buffer *b, ::uint32_t offset, ::uint8_t &out) {
  if(offset >= b->bufLen) {
    return false;
  }

  ::uint8_t *tmp = (b->bufBegin+offset);
  out = *tmp;

  return true;
}

bool readWord(bounded_buffer *b, ::uint32_t offset, ::uint16_t &out) {
  return false;
}

bool readDword(bounded_buffer *b, ::uint32_t offset, ::uint32_t &out) {
  return false;
}

bounded_buffer *readFileToFileBuffer(const char *filePath) {
  return NULL;
}

//split buffer inclusively from from to to by offset
bounded_buffer *splitBuffer(bounded_buffer *b, ::uint32_t from, ::uint32_t to) {
  //safety checks
  
  //make a new buffer
  bounded_buffer  *newBuff = new bounded_buffer();

  if(newBuff == NULL) {
    return NULL;
  }

  ::uint8_t   *curPtr = b->bufBegin;
  ::uint8_t   *newPtr = curPtr+from;

  return newBuff;
}

