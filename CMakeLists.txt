cmake_minimum_required(VERSION 3.1)
project(pe-parse)

if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Default install directory" FORCE)
endif ()

set(CMAKE_VERBOSE_MAKEFILE True)
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif ()

include(cmake/compilation_flags.cmake)
list(APPEND GLOBAL_CXXFLAGS ${DEFAULT_CXX_FLAGS})

option(BUILD_SHARED_LIBS "Build Shared Libraries" OFF)
option(BUILD_COMMAND_LINE_TOOLS "Build Command Line Tools" ON)

add_subdirectory(pe-parser-library)

if (BUILD_COMMAND_LINE_TOOLS)
  add_subdirectory(dump-pe)
endif ()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Build Shared: ${BUILD_SHARED_LIBS}")
message(STATUS "Build Command Line Tools: ${BUILD_COMMAND_LINE_TOOLS}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
