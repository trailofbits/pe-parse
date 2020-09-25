cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(pe-parse)

# NOTE(ww): CMake has bad defaults for install prefixes.
# Instead of fussing over them, install everything to the build directory by default
# and let the user set CMAKE_INSTALL_PREFIX explicitly for their own needs.
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}" CACHE PATH "Default install directory" FORCE)
endif ()

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif ()

include(cmake/compilation_flags.cmake)
list(APPEND GLOBAL_CXXFLAGS ${DEFAULT_CXX_FLAGS})

option(BUILD_SHARED_LIBS "Build Shared Libraries" ON)
option(BUILD_COMMAND_LINE_TOOLS "Build Command Line Tools" ON)
option(PEPARSE_LIBRARY_WARNINGS "Log pe-parse library warnings to stderr" OFF)


if (MSVC)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif ()

file(READ "${PROJECT_SOURCE_DIR}/VERSION" PEPARSE_VERSION)
string(STRIP "${PEPARSE_VERSION}" PEPARSE_VERSION)
add_compile_definitions(PEPARSE_VERSION="${PEPARSE_VERSION}")

add_subdirectory(pe-parser-library)

if (BUILD_COMMAND_LINE_TOOLS)
  add_subdirectory(dump-pe)
endif ()

# `peparse_format` target.
file(
    GLOB_RECURSE
    PEPARSE_ALL_SOURCES
        pe-parser-library/*.cpp
        pe-parser-library/*.h
        pepy/*.cpp
        pepy/*.h
        dump-pe/*.cpp
        examples/*.cpp
        examples/*.h
)
add_custom_target(
  peparse_format
  COMMAND clang-format -i -style=file ${PEPARSE_ALL_SOURCES}
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  COMMENT "Auto-format the codebase with clang-format"
  VERBATIM
)

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Build Shared: ${BUILD_SHARED_LIBS} ${BUILD_SHARED_LIBS_MESSAGE}")
message(STATUS "Build Command Line Tools: ${BUILD_COMMAND_LINE_TOOLS}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
