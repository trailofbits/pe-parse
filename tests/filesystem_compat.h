// This header is for C++17 filesystem compatibility for different versions of
// compilers and c++ standard libraries header placement

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
#error "no filesystem support"
#endif
