cmake_minimum_required(VERSION 2.8)
project(pe-parse)

set(CMAKE_VERBOSE_MAKEFILE True)
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif ()

include(cmake/compilation_flags.cmake)
list(APPEND PROJECT_CXXFLAGS ${DEFAULT_CXX_FLAGS})

add_subdirectory(parser-library)
add_subdirectory(dump-prog)
