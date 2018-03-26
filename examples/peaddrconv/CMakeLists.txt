cmake_minimum_required(VERSION 3.1)
project(peaddrconv)

if (MSVC)
  list(APPEND PEADDRCONV_CXXFLAGS /W4 /analyze)

  if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    list(APPEND PEADDRCONV_CXXFLAGS /Zi)
  endif ()

  if (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    list(APPEND PEADDRCONV_CXXFLAGS /WX)
  endif ()

else ()
  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_CXX_EXTENSIONS OFF)

  list(APPEND PEADDRCONV_CXXFLAGS
    -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization
    -Wformat=2 -Winit-self -Wlong-long -Wmissing-declarations -Wmissing-include-dirs -Wcomment
    -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion
    -Wsign-promo -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wunused -Wuninitialized
    -Wno-missing-declarations
  )

  if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    list(APPEND PEADDRCONV_CXXFLAGS -gdwarf-2 -g3)
  endif ()
endif ()

find_package(peparse REQUIRED)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} ${PEPARSE_LIBRARIES})
target_include_directories(${PROJECT_NAME} PRIVATE ${PEPARSE_INCLUDE_DIRS})
target_compile_options(${PROJECT_NAME} PRIVATE ${PEADDRCONV_CXXFLAGS})

install(TARGETS ${PROJECT_NAME} DESTINATION "bin")
