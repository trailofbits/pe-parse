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
#include <fstream>

// keep this header above "windows.h" because it contains many types
#include <pe-parse/parse.h>

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN

#include <intrin.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

inline std::uint16_t byteSwapUint16(std::uint16_t val) {
#if defined(_MSC_VER) || defined(_MSC_FULL_VER)
  return _byteswap_ushort(val);
#else
  return __builtin_bswap16(val);
#endif
}

inline std::uint32_t byteSwapUint32(std::uint32_t val) {
#if defined(_MSC_VER) || defined(_MSC_FULL_VER)
  return _byteswap_ulong(val);
#else
  return __builtin_bswap32(val);
#endif
}

inline uint64_t byteSwapUint64(std::uint64_t val) {
#if defined(_MSC_VER) || defined(_MSC_FULL_VER)
  return _byteswap_uint64(val);
#else
  return __builtin_bswap64(val);
#endif
}

} // anonymous namespace

namespace peparse {

extern std::uint32_t err;
extern std::string err_loc;

struct buffer_detail {
#ifdef _WIN32
  HANDLE file;
  HANDLE sec;
#else
  int fd;
#endif
};

bool readByte(bounded_buffer *b, std::uint32_t offset, std::uint8_t &out) {
  if (b == nullptr) {
    PE_ERR(PEERR_BUFFER);
    return false;
  }

  if (offset >= b->bufLen) {
    PE_ERR(PEERR_ADDRESS);
    return false;
  }

  std::uint8_t *tmp = (b->buf + offset);
  out = *tmp;

  return true;
}

bool readWord(bounded_buffer *b, std::uint32_t offset, std::uint16_t &out) {
  if (b == nullptr) {
    PE_ERR(PEERR_BUFFER);
    return false;
  }

  if (static_cast<std::uint64_t>(offset) + 1 >= b->bufLen) {
    PE_ERR(PEERR_ADDRESS);
    return false;
  }

  std::uint16_t tmp;
  memcpy(&tmp, (b->buf + offset), sizeof(std::uint16_t));
  if (b->swapBytes) {
    out = byteSwapUint16(tmp);
  } else {
    out = tmp;
  }

  return true;
}

bool readDword(bounded_buffer *b, std::uint32_t offset, std::uint32_t &out) {
  if (b == nullptr) {
    PE_ERR(PEERR_BUFFER);
    return false;
  }

  if (static_cast<std::uint64_t>(offset) + 3 >= b->bufLen) {
    PE_ERR(PEERR_ADDRESS);
    return false;
  }

  std::uint32_t tmp;
  memcpy(&tmp, (b->buf + offset), sizeof(std::uint32_t));
  if (b->swapBytes) {
    out = byteSwapUint32(tmp);
  } else {
    out = tmp;
  }

  return true;
}

bool readQword(bounded_buffer *b, std::uint32_t offset, std::uint64_t &out) {
  if (b == nullptr) {
    PE_ERR(PEERR_BUFFER);
    return false;
  }

  if (static_cast<std::uint64_t>(offset) + 7 >= b->bufLen) {
    PE_ERR(PEERR_ADDRESS);
    return false;
  }

  std::uint64_t tmp;
  memcpy(&tmp, (b->buf + offset), sizeof(std::uint64_t));
  if (b->swapBytes) {
    out = byteSwapUint64(tmp);
  } else {
    out = tmp;
  }

  return true;
}

bool readChar16(bounded_buffer *b, std::uint32_t offset, char16_t &out) {
  if (b == nullptr) {
    PE_ERR(PEERR_BUFFER);
    return false;
  }

  if (static_cast<std::uint64_t>(offset) + 1 >= b->bufLen) {
    PE_ERR(PEERR_ADDRESS);
    return false;
  }

  char16_t tmp;
  if (b->swapBytes) {
    std::uint8_t tmpBuf[2];
    tmpBuf[0] = *(b->buf + offset + 1);
    tmpBuf[1] = *(b->buf + offset);
    memcpy(&tmp, tmpBuf, sizeof(std::uint16_t));
  } else {
    memcpy(&tmp, (b->buf + offset), sizeof(std::uint16_t));
  }
  out = tmp;

  return true;
}

bounded_buffer *readFileToFileBuffer(const char *filePath) {
#ifdef _WIN32
  HANDLE h = CreateFileA(filePath,
                         GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL,
                         nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    return nullptr;
  }

  DWORD fileSize = GetFileSize(h, nullptr);

  if (fileSize == INVALID_FILE_SIZE) {
    CloseHandle(h);
    return nullptr;
  }

#else
  // only where we have mmap / open / etc
  int fd = open(filePath, O_RDONLY);

  if (fd == -1) {
    PE_ERR(PEERR_OPEN);
    return nullptr;
  }
#endif

  // make a buffer object
  bounded_buffer *p = new (std::nothrow) bounded_buffer();
  if (p == nullptr) {
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  memset(p, 0, sizeof(bounded_buffer));
  buffer_detail *d = new (std::nothrow) buffer_detail();

  if (d == nullptr) {
    delete p;
    PE_ERR(PEERR_MEM);
    return nullptr;
  }
  memset(d, 0, sizeof(buffer_detail));
  p->detail = d;

// only where we have mmap / open / etc
#ifdef _WIN32
  p->detail->file = h;

  HANDLE hMap = CreateFileMapping(h, nullptr, PAGE_READONLY, 0, 0, nullptr);

  if (hMap == nullptr) {
    CloseHandle(h);
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  p->detail->sec = hMap;

  LPVOID ptr = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

  if (ptr == nullptr) {
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  p->buf = reinterpret_cast<std::uint8_t *>(ptr);
  p->bufLen = fileSize;
#else
  p->detail->fd = fd;

  struct stat s;
  memset(&s, 0, sizeof(struct stat));

  if (fstat(fd, &s) != 0) {
    close(fd);
    delete d;
    delete p;
    PE_ERR(PEERR_STAT);
    return nullptr;
  }

  void *maddr = mmap(nullptr,
                     static_cast<std::size_t>(s.st_size),
                     PROT_READ,
                     MAP_SHARED,
                     fd,
                     0);

  if (maddr == MAP_FAILED) {
    close(fd);
    delete d;
    delete p;
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  p->buf = reinterpret_cast<std::uint8_t *>(maddr);
  p->bufLen = static_cast<std::uint32_t>(s.st_size);
#endif
  p->copy = false;
  p->swapBytes = false;

  return p;
}

bounded_buffer *makeBufferFromPointer(std::uint8_t *data, std::uint32_t sz) {
  if (data == nullptr) {
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  bounded_buffer *p = new (std::nothrow) bounded_buffer();

  if (p == nullptr) {
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  p->copy = true;
  p->detail = nullptr;
  p->buf = data;
  p->bufLen = sz;
  p->swapBytes = false;

  return p;
}

// split buffer inclusively from from to to by offset
bounded_buffer *
splitBuffer(bounded_buffer *b, std::uint32_t from, std::uint32_t to) {
  if (b == nullptr) {
    return nullptr;
  }

  // safety checks
  if (to < from || to > b->bufLen) {
    return nullptr;
  }

  // make a new buffer
  auto newBuff = new (std::nothrow) bounded_buffer();
  if (newBuff == nullptr) {
    return nullptr;
  }

  newBuff->copy = true;
  newBuff->buf = b->buf + from;
  newBuff->bufLen = (to - from);

  return newBuff;
}

void deleteBuffer(bounded_buffer *b) {
  if (b == nullptr) {
    return;
  }

  if (!b->copy) {
#ifdef _WIN32
    UnmapViewOfFile(b->buf);
    CloseHandle(b->detail->sec);
    CloseHandle(b->detail->file);
#else
    munmap(b->buf, b->bufLen);
    close(b->detail->fd);
#endif
  }

  delete b->detail;
  delete b;
}

std::uint64_t bufLen(bounded_buffer *b) {
  return b->bufLen;
}
} // namespace peparse
