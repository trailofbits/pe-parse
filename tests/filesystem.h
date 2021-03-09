#if !defined(__has_include)
// Assume experimental if compiler doesn't have __has_include
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#elif __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
#error "no filesystem support"
#endif
