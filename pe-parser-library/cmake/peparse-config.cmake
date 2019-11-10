if(CMAKE_CROSSCOMPILING)
  find_path(PEPARSE_INCLUDE_DIR "parser-library/parse.h")
else()
  find_path(PEPARSE_INCLUDE_DIR $<SHELL_PATH:"parser-library/parse.h">)
endif()
find_library(PEPARSE_LIBRARIES NAMES "libpe-parser-library" "pe-parser-library")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(peparse DEFAULT_MSG PEPARSE_INCLUDE_DIR PEPARSE_LIBRARIES)
