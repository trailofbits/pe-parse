cmake_minimum_required(VERSION 3.1)
project(dump-prog)

add_executable(${PROJECT_NAME} dump.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE pe-parser-library)
target_compile_options(${PROJECT_NAME} PRIVATE ${GLOBAL_CXXFLAGS})
