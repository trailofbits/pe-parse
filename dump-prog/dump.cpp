/*
The MIT License (MIT)

Copyright (c) 2013 Andrew Ruef

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <iostream>
#include <sstream>
#include "parse.h"

using namespace std;
using namespace boost;

template <class T>
static
string to_string(T t, ios_base & (*f)(ios_base&)) {
    ostringstream oss;
    oss << f << t;
    return oss.str();
}

void printImports(void *N, RVA  impAddr, string &impName) {

  return;
}

void printRelocs(void *N, RVA relocAddr) {

  return;
}

int main(int argc, char *argv[]) {
  if(argc == 2) {
    parsed_pe *p = ParsePEFromFile(argv[1]);

    if(p != NULL) {
      //print out some things
#define DUMP_FIELD(x) \
      cout << "" #x << ": "; \
      cout << to_string<uint32_t>(p->peHeader.x, hex) << endl;

      DUMP_FIELD(nt.Signature);
      DUMP_FIELD(nt.FileHeader.Machine);
      DUMP_FIELD(nt.FileHeader.NumberOfSections);
      DUMP_FIELD(nt.FileHeader.TimeDateStamp);
      DUMP_FIELD(nt.FileHeader.PointerToSymbolTable);
      DUMP_FIELD(nt.FileHeader.NumberOfSymbols);
      DUMP_FIELD(nt.FileHeader.SizeOfOptionalHeader);
      DUMP_FIELD(nt.FileHeader.Characteristics);
     
#undef DUMP_FIELD

      IterImpRVAString(p, printImports, NULL);
      IterRelocs(p, printRelocs, NULL);

      DestructParsedPE(p);
    }
  }
  return 0;
}
