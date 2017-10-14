#pragma once

#include <sstream>

namespace peparse {
template <class T>
static std::string to_string(T t, std::ios_base &(*f)(std::ios_base &) ) {
  std::ostringstream oss;
  oss << f << t;
  return oss.str();
}
} // namespace peparse
