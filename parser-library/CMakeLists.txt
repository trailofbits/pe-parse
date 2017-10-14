cmake_minimum_required(VERSION 3.1)
project(pe-parser-library)

add_library(${PROJECT_NAME} buffer.cpp parse.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(${PROJECT_NAME} PRIVATE ${GLOBAL_CXXFLAGS})
