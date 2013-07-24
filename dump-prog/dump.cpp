#include <iostream>
#include "parse.h"

using namespace std;

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
      IterImpRVAString(p, printImports, NULL);
      IterRelocs(p, printRelocs, NULL);

      DestructParsedPE(p);
    }
  }
  return 0;
}
