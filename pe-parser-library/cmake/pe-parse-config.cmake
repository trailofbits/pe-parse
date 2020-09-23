find_path(PEPARSE_INCLUDE_DIR "pe-parse/parse.h")
find_library(PEPARSE_LIBRARIES NAMES "libpe-parse" "pe-parse")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(pe-parse DEFAULT_MSG PEPARSE_INCLUDE_DIR PEPARSE_LIBRARIES)
