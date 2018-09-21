cmake_minimum_required(VERSION 3.7)
project(dump-pe)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE pe-parser-library)
target_compile_options(${PROJECT_NAME} PRIVATE ${GLOBAL_CXXFLAGS})

install(TARGETS ${PROJECT_NAME} DESTINATION "bin")
