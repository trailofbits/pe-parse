cmake_minimum_required(VERSION 3.11 FATAL_ERROR)
project(pe-parser-library)

message(STATUS "VERSION file: ${CMAKE_SOURCE_DIR}/VERSION")

file(READ "${PROJECT_SOURCE_DIR}/../VERSION" PEPARSE_VERSION)
string(STRIP "${PEPARSE_VERSION}" PEPARSE_VERSION)
add_compile_definitions(PEPARSE_VERSION="${PEPARSE_VERSION}")

set(UNICODE_LIBRARY "any" CACHE STRING "Select a unicode library")
set_property(CACHE UNICODE_LIBRARY PROPERTY STRINGS "any" "icu" "codecvt")

# This variable is used twice so setting once at the top here to prevent
# the chance they get out of sync.
# This is the minimum "required" version but there's a good chance early
# versions of ICU support the simple functionality needed by this project.
set(ICU_MINIMUM_REQUIRED 55.0)

# List all files explicitly; this will make IDEs happy (i.e. QtCreator, CLion, ...)
list(APPEND PEPARSERLIB_SOURCEFILES
  include/parser-library/parse.h
  include/parser-library/nt-headers.h
  include/parser-library/to_string.h

  src/buffer.cpp
  src/parse.cpp
)

# Check for codecvt support. Likely the proper way to do this would be to
# use CMake system inspection via methods like "try_compile" to determine
# if the "#include <codecvt>" directive compiles successfully.
if (MSVC)
  if (MSVC_VERSION LESS 1900)
    set(CODECVT_SUPPORTED OFF)
  else ()
    set(CODECVT_SUPPORTED ON)
  endif ()
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS "5.0")
    set(CODECVT_SUPPORTED OFF)
  else ()
    set(CODECVT_SUPPORTED ON)
  endif ()
else ()
  find_path(CODECVT_INCLUDE_DIR NAMES "codecvt")
  if (CODECVT_INCLUDE_DIR)
    set(CODECVT_SUPPORTED OFF)
  else ()
    set(CODECVT_SUPPORTED ON)
  endif ()
endif ()

if(${UNICODE_LIBRARY} MATCHES "icu")
  find_package(ICU ${ICU_MINIMUM_REQUIRED} COMPONENTS uc REQUIRED)
  add_definitions(-DUSE_ICU4C)
  list(APPEND PEPARSERLIB_SOURCEFILES src/unicode_icu.cpp)
elseif(${UNICODE_LIBRARY} MATCHES "codecvt")
  if(NOT CODECVT_SUPPORTED)
    message(SEND_ERROR "codecvt header not found")
  endif()
  list(APPEND PEPARSERLIB_SOURCEFILES src/unicode_codecvt.cpp)
else()
  find_package(ICU ${ICU_MINIMUM_REQUIRED} COMPONENTS uc)
  if(ICU_FOUND)
    add_definitions(-DUSE_ICU4C)
    list(APPEND PEPARSERLIB_SOURCEFILES src/unicode_icu.cpp)
  elseif(CODECVT_SUPPORTED)
    list(APPEND PEPARSERLIB_SOURCEFILES src/unicode_codecvt.cpp)
  else()
    message(SEND_ERROR "unable to find codecvt header or ICU library (hint: try installing libicu-dev)")
  endif(ICU_FOUND)
endif()

add_library(${PROJECT_NAME} ${PEPARSERLIB_SOURCEFILES})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(${PROJECT_NAME} PRIVATE ${GLOBAL_CXXFLAGS})
if(ICU_FOUND)
  target_link_libraries(${PROJECT_NAME} ICU::uc)
endif()

install(TARGETS ${PROJECT_NAME}
  RUNTIME DESTINATION "bin"
  LIBRARY DESTINATION "lib"
  ARCHIVE DESTINATION "lib"
)
install(FILES "cmake/peparse-config.cmake" DESTINATION "lib/cmake/peparse")
install(DIRECTORY "include/parser-library" DESTINATION "include")
