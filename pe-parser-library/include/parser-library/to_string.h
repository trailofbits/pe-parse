#pragma once

#include <string>
#include <sstream>

namespace peparse {
template <class T>
static std::string to_string(T t, std::ios_base &(*f)(std::ios_base &) ) {
  std::ostringstream oss;
  oss << f << t;
  return oss.str();
}

std::string from_utf16(const std::u16string &u);
} // namespace peparse
