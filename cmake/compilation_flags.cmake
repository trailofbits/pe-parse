
if (WIN32)
  set(CMAKE_CXX_STANDARD 14)

  list(APPEND DEFAULT_CXX_FLAGS /W4)

  if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    list(APPEND DEFAULT_CXX_FLAGS /Zi)
  endif ()

  if (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    list(APPEND DEFAULT_CXX_FLAGS /WX)
  endif ()

else ()
  set(CMAKE_CXX_STANDARD 14)

  list(APPEND DEFAULT_CXX_FLAGS
    -fPIC

    -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization
    -Wformat=2 -Winit-self -Wlong-long -Wmissing-declarations -Wmissing-include-dirs -Wcomment
    -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion
    -Wsign-promo -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wunused
  )

  if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    list(APPEND PROJECT_CXXFLAGS -gdwarf-2 -g3)
  endif ()

  if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "This is a debug build; enabling -Weverything...")

    list(APPEND PROJECT_CXXFLAGS
      -Weverything -Wno-c++98-compat -Wno-missing-prototypes
      -Wno-missing-variable-declarations -Wno-global-constructors
      -Wno-exit-time-destructors -Wno-padded -Wno-error
    )
  endif ()
endif ()