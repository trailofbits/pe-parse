/*
The MIT License (MIT)

Copyright (c) 2019 Trail of Bits, Inc.

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

#include <pe-parse/to_string.h>
#include <unicode/ustring.h>
#include <unicode/utypes.h>

namespace peparse {
std::string from_utf16(const UCharString &u) {
  if (u.empty()) {
    return std::string();
  }

  const UChar *src = reinterpret_cast<const UChar *>(u.data());
  int32_t srcLength = static_cast<int32_t>(u.size());

  // First pass: determine required buffer size
  UErrorCode status = U_ZERO_ERROR;
  int32_t destLength = 0;
  u_strToUTF8(nullptr, 0, &destLength, src, srcLength, &status);

  if (status != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(status)) {
    return std::string(); // Return empty on error (matches current behavior)
  }

  // Second pass: perform actual conversion
  std::string result(static_cast<std::size_t>(destLength), '\0');
  status = U_ZERO_ERROR;
  u_strToUTF8(&result[0], destLength, nullptr, src, srcLength, &status);

  if (U_FAILURE(status)) {
    return std::string();
  }

  return result;
}
} // namespace peparse
