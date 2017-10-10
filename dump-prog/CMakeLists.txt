cmake_minimum_required(VERSION 2.8)
project(dump-prog)

add_executable(${PROJECT_NAME} dump.cpp)
target_link_libraries(${PROJECT_NAME} pe-parser-library)
target_compile_options(${PROJECT_NAME} PRIVATE ${PROJECT_CXXFLAGS})
