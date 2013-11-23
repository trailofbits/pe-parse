pe-parse
=========================================
pe-parse is a principled, lightweight parser for windows portable executable files. It was created to assist in compiled program analysis, potentially of programs of unknown origins. This means that it should be resistent to malformed or maliciously crafted PE files, and it should support questions that analysis software would ask of an executable program container. For example, listing relocations, describing imports and exports, and supporting byte reads from virtual addresses as well as file offsets. 

pe-parse supports these use cases via a minimal API that provides methods for
 * Opening and closing a PE file
 * Iterating over the imported functions
 * Iterating over the relocations
 * Iterating over the exported functions
 * Iterating over sections
 * Reading bytes from specified virtual addresses
 * Retrieving the program entry point

The interface is defined in `parser-library/parse.h`. The program in `dump-prog/dump.cpp` is an example of using the parser-library API to dump information about a PE file. 

Internally, the parser-library uses a bounded buffer abstraction to access information stored in the PE file. This should help in constructing a sane parser that allows for detection of the use of bogus values in the PE that would result in out of bounds accesses of the input buffer. Once data is read from the file it is sanitized and placed in C++ STL containers of internal types.

Building
========
pe-parse is built using cmake and depends on boost. Once your platforms CMake knows how to find boost, build pe-parse through `cmake . && make`

Authors
=======
pe-parse was designed and implemented by Andrew Ruef (andrew@trailofbits.com)
