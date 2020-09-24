cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(dump-pe)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE pe-parse)
target_compile_options(${PROJECT_NAME} PRIVATE ${GLOBAL_CXXFLAGS})

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION "bin")
