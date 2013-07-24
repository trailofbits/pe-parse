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

void DestructParsedPE(parsed_pe *pe);

#endif
