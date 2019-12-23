pe-parse
=========================================

[![Build Status](https://img.shields.io/github/workflow/status/trailofbits/pe-parse/CI/master)](https://github.com/trailofbits/pe-parse/actions?query=workflow%3ACI)

pe-parse is a principled, lightweight parser for windows portable executable files. It was created to assist in compiled program analysis, potentially of programs of unknown origins. This means that it should be resistant to malformed or maliciously crafted PE files, and it should support questions that analysis software would ask of an executable program container. For example, listing relocations, describing imports and exports, and supporting byte reads from virtual addresses as well as file offsets.

pe-parse supports these use cases via a minimal API that provides methods for
 * Opening and closing a PE file
 * Iterating over the imported functions
 * Iterating over the relocations
 * Iterating over the exported functions
 * Iterating over sections
 * Iterating over resources
 * Reading bytes from specified virtual addresses
 * Retrieving the program entry point

The interface is defined in `parser-library/parse.h`. The program in `dump-prog/dump.cpp` is an example of using the parser-library API to dump information about a PE file.

Internally, the parser-library uses a bounded buffer abstraction to access information stored in the PE file. This should help in constructing a sane parser that allows for detection of the use of bogus values in the PE that would result in out of bounds accesses of the input buffer. Once data is read from the file it is sanitized and placed in C++ STL containers of internal types.

Dependencies
========
### CMake
  * Debian/Ubuntu: `sudo apt-get install cmake`
  * RedHat/Fedora: `sudo yum install cmake`
  * OSX: `brew install cmake`
  * Windows: Download the installer from the [CMake page](https://cmake.org/download/)

Building
========
### Generic instructions
```
git clone https://github.com/trailofbits/pe-parse.git
cd pe-parse

mkdir build
cd build

cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release

# optional
cmake --build . --config Release --target install
```

PE files that have a Resource section with strings for the Type are encoded in UTF-16, but that `std::string` expects UTF-8. Some cross-platform solution
is desired. You can let cmake choose one it finds in your build environment or you can choose one from the following options yourself and specify it with
the `-DUNICODE_LIBRARY` argument when generating the project files with cmake:
* `icu` (preferred) - "[ICU](http://site.icu-project.org/) is a mature, widely used set of C/C++ and Java libraries providing Unicode and Globalization support for software applications"
* `codecvt` - A C++ library header file ([now deprecated](http://open-std.org/JTC1/SC22/WG21/docs/papers/2017/p0618r0.html)) supported by some C++ runtimes

### Notes about Windows

If you are building on Windows with Visual Studio, the generator option can be used to select the compiler version and the output architecture:

```
# Compile 64-bit binaries with Visual Studio 2017
cmake -G "Visual Studio 15 2017 Win64" -DCMAKE_BUILD_TYPE=Release ..

# Compile 32-bit binaries with Visual Studio 2017
cmake -G "Visual Studio 15 2017" -DCMAKE_BUILD_TYPE=Release ..
```

Visual Studio 2015 or higher is required to use codecvt, but you also have the option of using [ICU](http://site.icu-project.org/). The easiest way to
get started with ICU in Windows is with [vcpkg](https://vcpkg.readthedocs.io/): `vcpkg install icu`. Then add the
`-DCMAKE_TOOLCHAIN_FILE=C:\src\vcpkg\scripts\buildsystems\vcpkg.cmake` argument when generating the project files with cmake to add the appropriate
library and include directories to the project.

Using the library
=======
Once the library is installed, linking to it is easy! Add the following lines in your CMake project:

```
find_package(peparse REQUIRED)

target_link_libraries(your_target_name ${PEPARSE_LIBRARIES})
target_include_directories(your_target_name PRIVATE ${PEPARSE_INCLUDE_DIRS})
```

You can see a full example in the examples/peaddrconv folder.

Authors
=======
pe-parse was designed and implemented by Andrew Ruef (andrew@trailofbits.com), with significant contributions from [Wesley Shields](https://github.com/wxsBSD).
