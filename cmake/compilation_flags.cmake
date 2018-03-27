if (MSVC)
  list(APPEND DEFAULT_CXX_FLAGS /W4 /analyze)

  if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    list(APPEND DEFAULT_CXX_FLAGS /Zi)
  endif ()

  if (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    list(APPEND DEFAULT_CXX_FLAGS /WX)
  endif ()

else ()
  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_CXX_EXTENSIONS OFF)

  if (NOT MINGW)
    list(APPEND DEFAULT_CXX_FLAGS -fPIC)
  endif ()

  list(APPEND DEFAULT_CXX_FLAGS

    -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization
    -Wformat=2 -Winit-self -Wlong-long -Wmissing-declarations -Wmissing-include-dirs -Wcomment
    -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion
    -Wsign-promo -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wunused -Wuninitialized
    -Wno-missing-declarations -Wno-strict-overflow
  )

  if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
  list(APPEND DEFAULT_CXX_FLAGS -gdwarf-2 -g3)
  endif ()

  if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "This is a debug build; enabling -Weverything...")

    list(APPEND DEFAULT_CXX_FLAGS
      -Weverything -Wno-c++98-compat -Wno-missing-prototypes
      -Wno-missing-variable-declarations -Wno-global-constructors
      -Wno-exit-time-destructors -Wno-padded -Wno-error
    )
  endif ()
endif ()
