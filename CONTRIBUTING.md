Contributing to pe-parse
========================

Hello, and welcome to the contributing guidelines for pe-parse!

For general building instructions, see the [README](README.md).

For licensing information, see the [LICENSE](LICENSE.txt) file. pe-parse includes a CLA; you will be
automatically prompted to sign it during your first PR.

## General contribution guidelines

* Your changes should be valid C++11
* Your changes should work across all major compiler vendors (GCC, Clang, MSVC) and all
major operating systems (Linux, macOS, Windows)
* Your changes should be auto-formatted with `clang-format -style=file`
* Your changes should not introduce *mandatory* third-party dependencies

## Adding features

Feature additions to either the parsing library or `dump-pe` are welcome!

Check out the following issue labels for some contribution ideas:

* [Enhancements](https://github.com/trailofbits/pe-parse/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)
* [Hacktoberfest](https://github.com/trailofbits/pe-parse/issues?q=is%3Aissue+is%3Aopen+label%3Ahacktoberfest)
