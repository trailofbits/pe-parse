cmake_minimum_required(VERSION 3.7)
project(pe-parser-library)

# List all files explicitly; this will make IDEs happy (i.e. QtCreator, CLion, ...)
list(APPEND PEPARSERLIB_SOURCEFILES
  include/parser-library/parse.h
  include/parser-library/nt-headers.h
  include/parser-library/to_string.h

  src/buffer.cpp
  src/parse.cpp
)

add_library(${PROJECT_NAME} ${PEPARSERLIB_SOURCEFILES})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(${PROJECT_NAME} PRIVATE ${GLOBAL_CXXFLAGS})

install(TARGETS ${PROJECT_NAME}
  RUNTIME DESTINATION "bin"
  LIBRARY DESTINATION "lib"
  ARCHIVE DESTINATION "lib"
)
install(FILES "cmake/peparse-config.cmake" DESTINATION "lib/cmake/peparse")
install(DIRECTORY "include/parser-library" DESTINATION "include")
