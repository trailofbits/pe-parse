# Enable C/C++ sanitizers in your CMake project by `include`ing this file
# somewhere in your CMakeLists.txt.
#
# Example:
#
#   include("cmake/sanitizers.cmake")
#   process_sanitizer(MY_PROJECT)
#
# Example CMake configuration usage for `MY_PROJECT`:
#
#   cmake -Bbuild-asan-ubsan -H. -DMY_PROJECT_USE_SANITIZER=Address,Undefined
#
# where "MY_PROJECT" can by any arbitrary text that will be prepended to some
# expected CMake variables--see below.
#
# This file expects the following variables to be set during CMake
# configuration, where the prefix is set by the caller of `process_sanitizer`:
#
#   - *_USE_SANITIZER
#     - A string value that is one of the following:
#       - Address
#       - HWAddress
#       - Memory
#       - MemoryWithOrigins
#       - Undefined
#       - Thread
#       - DataFlow
#       - Leak
#       - Address,Undefined
#
#   - *_OPTIMIZE_SANITIZED_BUILDS
#     - A boolean value to set whether a higher optimization is used in debug
#       builds
#
#   - *_BLACKLIST_FILE
#     - A filepath to a sanitizer blacklist file.


function(append value)
  foreach(variable ${ARGN})
    set(${variable}
        "${${variable}} ${value}"
        PARENT_SCOPE)
  endforeach(variable)
endfunction()


macro(append_common_sanitizer_flags prefix)
  if (NOT MSVC)
    # Append -fno-omit-frame-pointer and turn on debug info to get better
    # stack traces.
    append("-fno-omit-frame-pointer" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    append("-fno-optimize-sibling-calls" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    append("-gline-tables-only" CMAKE_C_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELEASE
                                CMAKE_C_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_MINSIZE_REL)
    # Use -O1 even in debug mode, otherwise sanitizers slowdown is too large.
    if (${prefix}_OPTIMIZE_SANITIZED_BUILDS)
      message(STATUS "Optimizing sanitized Debug build")
      append("-O1" CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG)
    endif()
  else()
    # Keep frame pointers around.
    append("/Oy-" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    # Always ask the linker to produce symbols with asan.
    append("/Zi" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    # Workaround for incompatible (warning-producing) default CMake flag
    # https://docs.microsoft.com/en-us/cpp/sanitizers/asan-known-issues
    # https://gitlab.kitware.com/cmake/cmake/-/issues/19084
    string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
    append("/debug" CMAKE_EXE_LINKER_FLAGS CMAKE_MODULE_LINKER_FLAGS CMAKE_SHARED_LINKER_FLAGS)
  endif()
endmacro()


# Main logic
macro(process_sanitizer prefix)

  # Add options for the project to use sanitizers
  set(${prefix}_USE_SANITIZER "false" CACHE STRING "Enable building with sanitizer support.")
  set_property(CACHE ${prefix}_USE_SANITIZER PROPERTY STRINGS Address HWAddress Memory MemoryWithOrigins Undefined Thread DataFlow Leak "Address,Undefined")
  if (UNIX)
    option(${prefix}_OPTIMIZE_SANITIZED_BUILDS "Optimize builds that use sanitization" false)
    option(${prefix}_BLACKLIST_FILE "Path to blacklist file for sanitizers" "")
    option(${prefix}_USE_SANITIZE_COVERAGE "Set for libFuzzer-required instrumentation, no linking." false)
  endif()

  if (${prefix}_USE_SANITIZER)
    if(UNIX)

      if(${prefix}_USE_SANITIZER STREQUAL "Address")
        message(STATUS "Building with Address sanitizer")
        append_common_sanitizer_flags(${prefix})
        append("-fsanitize=address" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)

      elseif(${prefix}_USE_SANITIZER STREQUAL "HWAddress")
        message(STATUS "Building with Address sanitizer")
        append_common_sanitizer_flags(${prefix})
        append("-fsanitize=hwaddress" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)

      elseif(${prefix}_USE_SANITIZER MATCHES "Memory(WithOrigins)?")
        append_common_sanitizer_flags(${prefix})
        append("-fsanitize=memory" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
        if(${prefix}_USE_SANITIZER STREQUAL "MemoryWithOrigins")
          message(STATUS "Building with MemoryWithOrigins sanitizer")
          append("-fsanitize-memory-track-origins" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
        else()
          message(STATUS "Building with Memory sanitizer")
        endif()

      elseif(${prefix}_USE_SANITIZER STREQUAL "Undefined")
        message(STATUS "Building with Undefined sanitizer")
        append_common_sanitizer_flags(${prefix})
        append("-fsanitize=undefined" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
        # Execution error on undefined detection. Could be optional to add this
        append("-fno-sanitize-recover=all" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)

      elseif(${prefix}_USE_SANITIZER STREQUAL "Thread")
        message(STATUS "Building with Thread sanitizer")
        append_common_sanitizer_flags(${prefix})
        append("-fsanitize=thread" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)

      elseif(${prefix}_USE_SANITIZER STREQUAL "DataFlow")
        message(STATUS "Building with DataFlow sanitizer")
        append("-fsanitize=dataflow" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)

      elseif(${prefix}_USE_SANITIZER STREQUAL "Leak")
        message(STATUS "Building with Leak sanitizer")
        append_common_sanitizer_flags(${prefix})
        append("-fsanitize=leak" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)

      elseif(${prefix}_USE_SANITIZER STREQUAL "Address,Undefined"
          OR ${prefix}_USE_SANITIZER STREQUAL "Undefined,Address")
        message(STATUS "Building with Address, Undefined sanitizers")
        append_common_sanitizer_flags(${prefix})
        append("-fsanitize=address,undefined" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
        # Execution error on undefined detection. Could be optional to add this
        append("-fno-sanitize-recover=all" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)

      else()
        message(
          FATAL_ERROR "Unsupported value of ${prefix}_USE_SANITIZER: '${${prefix}_USE_SANITIZER}'")
      endif()
    elseif(MSVC)
      if(${prefix}_USE_SANITIZER STREQUAL "Address")
        message(STATUS "Building with Address sanitizer")
        append_common_sanitizer_flags(${prefix})
        append("/fsanitize=address" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
      else()
        message(FATAL_ERROR "This sanitizer is not yet supported in the MSVC environment: '${${prefix}_USE_SANITIZER}'")
      endif()
    else()
      message(FATAL_ERROR "${prefix}_USE_SANITIZER is not supported on this platform.")
    endif()

    # If specified, use a blacklist file
    if (EXISTS "${${prefix}_BLACKLIST_FILE}")
      message(STATUS "Using sanitizer blacklist file: ${${prefix}_BLACKLIST_FILE}")
      append("-fsanitize-blacklist=${${prefix}_BLACKLIST_FILE}" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    endif()

    # Set a once non-default option for more detection
    if (${prefix}_USE_SANITIZER MATCHES "(Undefined,)?Address(,Undefined)?")
      if (UNIX)
        append("-fsanitize-address-use-after-scope" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
      endif()
    endif()

    # Set for libFuzzer-required instrumentation, no linking.
    if (${prefix}_USE_SANITIZE_COVERAGE)
      message(STATUS "Setting up sanitizer for coverage support with 'fuzzer-no-link'")
      append("-fsanitize=fuzzer-no-link" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    endif()
  endif()
endmacro()
