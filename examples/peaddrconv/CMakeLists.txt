cmake_minimum_required(VERSION 3.1)
project(peaddrconv)

find_package(peparse REQUIRED)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} ${PEPARSE_LIBRARIES})
target_include_directories(${PROJECT_NAME} PRIVATE ${PEPARSE_INCLUDE_DIRS})

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
