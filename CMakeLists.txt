cmake_minimum_required(VERSION 3.1)
project(pe-parse)

set(MAJOR_VERSION "1")
set(MINOR_VERSION "0")

set(CMAKE_VERBOSE_MAKEFILE True)
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif ()

include(cmake/compilation_flags.cmake)
list(APPEND GLOBAL_CXXFLAGS ${DEFAULT_CXX_FLAGS})

add_subdirectory(pe-parser-library)
add_subdirectory(dump-pe)
