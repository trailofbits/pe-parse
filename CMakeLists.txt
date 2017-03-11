cmake_minimum_required (VERSION 2.8)

project (pe-parse)

set(CMAKE_CXX_FLAGS "-std=c++11")

find_package(Threads REQUIRED)

add_subdirectory(parser-library)
add_subdirectory(dump-prog)
