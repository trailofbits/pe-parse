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

#include <codecvt>
#include <locale>
#include <parser-library/to_string.h>

namespace peparse {
// See
// https://stackoverflow.com/questions/38688417/utf-conversion-functions-in-c11
std::string from_utf16(const UCharString &u) {
#if defined(_MSC_VER)
  // std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>convert;
  // // Doesn't compile with Visual Studio. See
  // https://stackoverflow.com/questions/32055357/visual-studio-c-2015-stdcodecvt-with-char16-t-or-char32-t
  std::wstring_convert<std::codecvt_utf8<std::int16_t>, std::int16_t> convert;
  auto p = reinterpret_cast<const std::int16_t *>(u.data());
  return convert.to_bytes(p, p + u.size());
#else
  // -std=c++11 or -std=c++14
  // Requires GCC 5 or higher
  // Requires Clang ??? or higher (tested on Clang 3.8, 5.0, 6.0)
  std::wstring_convert<std::codecvt_utf8<char16_t>, char16_t> convert;
  return convert.to_bytes(u);
#endif
}
} // namespace peparse
