include(CTest)

# Path for corkami dataset
set(CORKAMI_SUBMODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/assets/corkami-poc-dataset")
set(CORKAMI_PE_PATH "${CORKAMI_SUBMODULE_PATH}/PE/bin")

if (NOT EXISTS "${CORKAMI_PE_PATH}")
  message(WARNING "Could not find Corkami dataset for testing.\nUse 'git submodule update --init'")
endif()

# To reconfigure and rebuild when submodule status changes
# See https://gitlab.kitware.com/cmake/cmake/-/issues/18755 to read why using
# (potentially non-existant) CORKAMI_PE_PATH doesn't work
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CORKAMI_SUBMODULE_PATH}")

if (NOT USE_EXTERNAL_CATCH2)
  include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/catch.cmake.in")
else()
  find_package(Catch2 REQUIRED)
endif()

add_executable(tests
  test_main.cpp
  simple_test.cpp
  corkami_test.cpp
  pr_153_test.cpp

  filesystem_compat.h
  )
target_compile_definitions(tests PRIVATE ASSETS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/assets")
target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(tests PRIVATE std::filesystem ${PROJECT_NAME} Catch2::Catch2)
# ASAN on Windows messes with exception handlers, and Catch2 doesn't account
# for this. A workaround is to disable SEH on Windows with ASAN
# https://github.com/catchorg/Catch2/issues/898#issuecomment-841733322
if (WIN32 AND PEPARSE_USE_SANITIZER STREQUAL "Address")
  target_compile_definitions(tests PUBLIC CATCH_CONFIG_NO_WINDOWS_SEH)
endif()

if (EXISTS "${CORKAMI_PE_PATH}")
  target_compile_definitions(tests PRIVATE CORKAMI_PE_PATH="${CORKAMI_PE_PATH}")
endif()

if (WIN32 AND BUILD_SHARED_LIBS)
  # Workaround for shared lib loading in Windows.
  # Need to copy all dependent DLLs to the same directory
  add_custom_command (TARGET tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:${PROJECT_NAME}> $<TARGET_FILE_DIR:tests>
    )
endif()

include(Catch)
catch_discover_tests(tests)
