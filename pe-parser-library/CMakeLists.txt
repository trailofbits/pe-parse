cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(pe-parser-library)

message(STATUS "VERSION file: ${PROJECT_SOURCE_DIR}/../VERSION")

file(READ "${PROJECT_SOURCE_DIR}/../VERSION" PEPARSE_VERSION)
string(STRIP "${PEPARSE_VERSION}" PEPARSE_VERSION)
add_compile_definitions(PEPARSE_VERSION="${PEPARSE_VERSION}")

# List all files explicitly; this will make IDEs happy (i.e. QtCreator, CLion, ...)
list(APPEND PEPARSERLIB_SOURCEFILES
  include/parser-library/parse.h
  include/parser-library/nt-headers.h
  include/parser-library/to_string.h

  src/buffer.cpp
  src/parse.cpp
)

# NOTE(ww): On Windows we use the Win32 API's built-in UTF16 conversion
# routines; on other platforms we use codecvt. codecvt is nominally deprecated
# in C++17 and onwards, but will probably be available for quite some time.
# Previous versions of pe-parse used ICU when available, but this caused
# DLL hell on Windows and wasn't worth the additional dependency.
if(MSVC)
  list(APPEND PEPARSERLIB_SOURCEFILES src/unicode_winapi.cpp)
else()
  list(APPEND PEPARSERLIB_SOURCEFILES src/unicode_codecvt.cpp)
endif()

add_library(${PROJECT_NAME} ${PEPARSERLIB_SOURCEFILES})

target_include_directories(
  ${PROJECT_NAME}
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_compile_options(${PROJECT_NAME} PRIVATE ${GLOBAL_CXXFLAGS})

install(
  TARGETS ${PROJECT_NAME}
  EXPORT pe-parse-config
  RUNTIME
    DESTINATION "bin"
  LIBRARY
    DESTINATION "lib"
  ARCHIVE
    DESTINATION "lib"
)
export(
  TARGETS ${PROJECT_NAME}
  NAMESPACE pe-parse::
  FILE "${CMAKE_CURRENT_BINARY_DIR}/pe-parse-config.cmake"
)
install(
  EXPORT
  pe-parse-config
  DESTINATION "lib/cmake/pe-parse"
  NAMESPACE pe-parse::
  EXPORT_LINK_INTERFACE_LIBRARIES
)
install(DIRECTORY "include/parser-library" DESTINATION "include")
