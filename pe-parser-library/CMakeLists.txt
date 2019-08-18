cmake_minimum_required(VERSION 3.7)
project(pe-parser-library)

set(UNICODE_LIBRARY "any" CACHE STRING "Select a unicode library")
set_property(CACHE UNICODE_LIBRARY PROPERTY STRINGS "any" "icu" "codecvt")

# List all files explicitly; this will make IDEs happy (i.e. QtCreator, CLion, ...)
list(APPEND PEPARSERLIB_SOURCEFILES
  include/parser-library/parse.h
  include/parser-library/nt-headers.h
  include/parser-library/to_string.h

  src/buffer.cpp
  src/parse.cpp
)

if(${UNICODE_LIBRARY} MATCHES "icu")
  find_package(ICU 61.0 COMPONENTS uc REQUIRED)
  list(APPEND PEPARSERLIB_SOURCEFILES src/unicode_icu.cpp)
elseif(${UNICODE_LIBRARY} MATCHES "codecvt")
  if(NOT MSVC)
    find_path(CODECVT_INCLUDE_DIR NAMES "codecvt")
    if(${CODECVT_INCLUDE_DIR} MATCHES "CODECVT_INCLUDE_DIR-NOTFOUND")
      message(SEND_ERROR "codecvt header not found")
    endif()
  endif()
  list(APPEND PEPARSERLIB_SOURCEFILES src/unicode_codecvt.cpp)
else()
  find_package(ICU 61.0 COMPONENTS uc)
  if(ICU_FOUND)
    list(APPEND PEPARSERLIB_SOURCEFILES src/unicode_icu.cpp)
  else(ICU_FOUND)
    if(NOT MSVC)
      find_path(CODECVT_INCLUDE_DIR NAMES "codecvt")
      if(${CODECVT_INCLUDE_DIR} MATCHES "CODECVT_INCLUDE_DIR-NOTFOUND")
        message(SEND_ERROR "unable to find ICU library or codecvt header")
      endif()
    endif(NOT MSVC)
    list(APPEND PEPARSERLIB_SOURCEFILES src/unicode_codecvt.cpp)
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
