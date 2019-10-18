#pragma once

#include <sstream>
#include <string>

#ifdef USE_ICU4C
#include <unicode/unistr.h>
typedef std::basic_string<UChar> UCharString;
#else
typedef std::u16string UCharString;
#endif

namespace peparse {
template <class T>
static std::string to_string(T t, std::ios_base &(*f)(std::ios_base &) ) {
  std::ostringstream oss;
  oss << f << t;
  return oss.str();
}

std::string from_utf16(const UCharString &u);
} // namespace peparse
