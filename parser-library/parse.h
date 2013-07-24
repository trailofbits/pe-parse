/* DO WHATEVER YOU WANT */

#ifndef _PARSE_H
#define _PARSE_H
#include <string>
#include <boost/cstdint.hpp>

typedef boost::uint32_t RVA;

typedef struct _parsed_pe {
  std::string originalFilePath;
} parsed_pe;

//get a PE parse context from a file 
parsed_pe *ParsePEFromFile(const char *filePath);

//destruct a PE context
void DestructParsedPE(parsed_pe *pe);

//iterate over the imports by RVA and string 
typedef void (*iterRVAStr)(void *, RVA, std::string &);
void IterImpRVAString(parsed_pe *pe, iterRVAStr cb, void *cbd);

//iterate over relocations in the PE file
typedef void (*iterReloc)(void *, RVA);
void IterRelocs(parsed_pe *pe, iterReloc cb, void *cbd);

//iterate over the exports by RVA
typedef void (*iterRVA)(void *, RVA);
void IterExpRVA(parsed_pe *pe, iterRVA cb, void *cbd);

#endif
