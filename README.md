pe-parse
=========================================

[![Build Status](https://travis-ci.org/trailofbits/pe-parse.svg?branch=master)](https://travis-ci.org/trailofbits/pe-parse)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/3671/badge.svg)](https://scan.coverity.com/projects/3671)

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

Building
========
pe-parse is built using `cmake` and has no major dependencies.

1. Install cmake:
  * Debian/Ubuntu: `sudo apt-get install cmake`
  * RedHat/Fedora: `sudo yum install cmake`
  * OSX: `brew install cmake`
2. `cmake .`
3. `make`

Authors
=======
pe-parse was designed and implemented by Andrew Ruef (andrew@trailofbits.com), with significant contributions from [Wesley Shields](https://github.com/wxsBSD).
