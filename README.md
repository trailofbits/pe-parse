pe-parse
========

[![Build Status](https://img.shields.io/github/workflow/status/trailofbits/pe-parse/CI/master)](https://github.com/trailofbits/pe-parse/actions?query=workflow%3ACI)
[![LGTM Total alerts](https://img.shields.io/lgtm/alerts/g/trailofbits/pe-parse.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/trailofbits/pe-parse/alerts/)

pe-parse is a principled, lightweight parser for Windows portable executable files.
It was created to assist in compiled program analysis, potentially of programs of unknown origins.
This means that it should be resistant to malformed or maliciously crafted PE files, and it should
support questions that analysis software would ask of an executable program container.
For example, listing relocations, describing imports and exports, and supporting byte reads from
virtual addresses as well as file offsets.

pe-parse supports these use cases via a minimal API that provides methods for
 * Opening and closing a PE file
 * Iterating over the imported functions
 * Iterating over the relocations
 * Iterating over the exported functions
 * Iterating over sections
 * Iterating over resources
 * Reading bytes from specified virtual addresses
 * Retrieving the program entry point

The interface is defined in `parser-library/parse.h`.

The program in `dump-prog/dump.cpp` is an example of using the parser-library API to dump
information about a PE file.

Internally, the parser-library uses a bounded buffer abstraction to access information stored in
the PE file. This should help in constructing a sane parser that allows for detection of the use
of bogus values in the PE that would result in out of bounds accesses of the input buffer.
Once data is read from the file it is sanitized and placed in C++ STL containers of internal types.

pe-parse includes Python bindings via `pepy`, which can be installed via `pip`:

```bash
$ pip3 install pepy
```

More information about `pepy` can be found in its [README](./pepy/README.md).

## Dependencies

### CMake
  * Debian/Ubuntu: `sudo apt-get install cmake`
  * RedHat/Fedora: `sudo yum install cmake`
  * OSX: `brew install cmake`
  * Windows: Download the installer from the [CMake page](https://cmake.org/download/)

## Building

### Generic instructions

```
git clone https://github.com/trailofbits/pe-parse.git
cd pe-parse

mkdir build
cd build

cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .

# optional
cmake --build . --target install
```

### Windows-specific

VS 2017 and VS 2019 are supported.

```
# Compile 64-bit binaries with Visual Studio 2017
cmake -G "Visual Studio 15 2017 Win64" ..

# Or, with VS 2019, use the -A flag for architecture
cmake -G "Visual Studio 16 2019" -A Win64 ..

# Pass the build type at build time
cmake --build . --config Release
```

## Using the library

Once the library is installed, linking to it is easy! Add the following lines in your CMake project:

```
find_package(pe-parse REQUIRED)

target_link_libraries(your_target_name PRIVATE pe-parse::pe-parser-library)
```

You can see a full example in the [examples/peaddrconv](examples/peaddrconv) folder.

## Authors

pe-parse was designed and implemented by Andrew Ruef (andrew@trailofbits.com), with significant
contributions from [Wesley Shields](https://github.com/wxsBSD).
