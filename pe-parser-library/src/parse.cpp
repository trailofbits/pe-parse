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

#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

#include <pe-parse/nt-headers.h>
#include <pe-parse/parse.h>
#include <pe-parse/to_string.h>

namespace peparse {

struct section {
  std::string sectionName;
  std::uint64_t sectionBase;
  bounded_buffer *sectionData;
  image_section_header sec;
};

struct importent {
  VA addr;
  std::string symbolName;
  std::string moduleName;
};

struct exportent {
  VA addr;
  std::string symbolName;
  std::string moduleName;
};

struct reloc {
  VA shiftedAddr;
  reloc_type type;
};

#define SYMBOL_NAME_OFFSET(sn) (static_cast<std::uint32_t>(sn.data >> 32))
#define SYMBOL_TYPE_HI(x) (x.type >> 8)

union symbol_name {
  std::uint8_t shortName[NT_SHORT_NAME_LEN];
  std::uint32_t zeroes;
  std::uint64_t data;
};

struct aux_symbol_f1 {
  std::uint32_t tagIndex;
  std::uint32_t totalSize;
  std::uint32_t pointerToLineNumber;
  std::uint32_t pointerToNextFunction;
};

struct aux_symbol_f2 {
  std::uint16_t lineNumber;
  std::uint32_t pointerToNextFunction;
};

struct aux_symbol_f3 {
  std::uint32_t tagIndex;
  std::uint32_t characteristics;
};

struct aux_symbol_f4 {
  std::uint8_t filename[SYMTAB_RECORD_LEN];
  std::string strFilename;
};

struct aux_symbol_f5 {
  std::uint32_t length;
  std::uint16_t numberOfRelocations;
  std::uint16_t numberOfLineNumbers;
  std::uint32_t checkSum;
  std::uint16_t number;
  std::uint8_t selection;
};

struct symbol {
  std::string strName;
  symbol_name name;
  std::uint32_t value;
  std::int16_t sectionNumber;
  std::uint16_t type;
  std::uint8_t storageClass;
  std::uint8_t numberOfAuxSymbols;
  std::vector<aux_symbol_f1> aux_symbols_f1;
  std::vector<aux_symbol_f2> aux_symbols_f2;
  std::vector<aux_symbol_f3> aux_symbols_f3;
  std::vector<aux_symbol_f4> aux_symbols_f4;
  std::vector<aux_symbol_f5> aux_symbols_f5;
};

struct parsed_pe_internal {
  std::vector<section> secs;
  std::vector<resource> rsrcs;
  std::vector<importent> imports;
  std::vector<reloc> relocs;
  std::vector<exportent> exports;
  std::vector<symbol> symbols;
};

// String representation of Rich header object types
static const std::string kProdId_C = "[ C ]";
static const std::string kProdId_CPP = "[C++]";
static const std::string kProdId_RES = "[RES]";
static const std::string kProdId_IMP = "[IMP]";
static const std::string kProdId_EXP = "[EXP]";
static const std::string kProdId_ASM = "[ASM]";
static const std::string kProdId_LNK = "[LNK]";
static const std::string kProdId_UNK = "[ ? ]";

// Mapping of Rich header Product ID to object type string
// Source: https://github.com/dishather/richprint/blob/master/comp_id.txt
static const std::map<std::uint16_t, std::string> ProductIdMap = {
    {std::make_pair(static_cast<std::uint16_t>(0x0000), kProdId_UNK)},
    {std::make_pair(static_cast<std::uint16_t>(0x0002), kProdId_IMP)},
    {std::make_pair(static_cast<std::uint16_t>(0x0004), kProdId_LNK)},
    {std::make_pair(static_cast<std::uint16_t>(0x0006), kProdId_RES)},
    {std::make_pair(static_cast<std::uint16_t>(0x000A), kProdId_C)},
    {std::make_pair(static_cast<std::uint16_t>(0x000B), kProdId_CPP)},
    {std::make_pair(static_cast<std::uint16_t>(0x000F), kProdId_ASM)},
    {std::make_pair(static_cast<std::uint16_t>(0x0015), kProdId_C)},
    {std::make_pair(static_cast<std::uint16_t>(0x0016), kProdId_CPP)},
    {std::make_pair(static_cast<std::uint16_t>(0x0019), kProdId_IMP)},
    {std::make_pair(static_cast<std::uint16_t>(0x001C), kProdId_C)},
    {std::make_pair(static_cast<std::uint16_t>(0x001D), kProdId_CPP)},
    {std::make_pair(static_cast<std::uint16_t>(0x003D), kProdId_LNK)},
    {std::make_pair(static_cast<std::uint16_t>(0x003F), kProdId_EXP)},
    {std::make_pair(static_cast<std::uint16_t>(0x0040), kProdId_ASM)},
    {std::make_pair(static_cast<std::uint16_t>(0x0045), kProdId_RES)},
    {std::make_pair(static_cast<std::uint16_t>(0x005A), kProdId_LNK)},
    {std::make_pair(static_cast<std::uint16_t>(0x005C), kProdId_EXP)},
    {std::make_pair(static_cast<std::uint16_t>(0x005D), kProdId_IMP)},
    {std::make_pair(static_cast<std::uint16_t>(0x005E), kProdId_RES)},
    {std::make_pair(static_cast<std::uint16_t>(0x005F), kProdId_C)},
    {std::make_pair(static_cast<std::uint16_t>(0x0060), kProdId_CPP)},
    {std::make_pair(static_cast<std::uint16_t>(0x006D), kProdId_C)},
    {std::make_pair(static_cast<std::uint16_t>(0x006E), kProdId_CPP)},
    {std::make_pair(static_cast<std::uint16_t>(0x0078), kProdId_LNK)},
    {std::make_pair(static_cast<std::uint16_t>(0x007A), kProdId_EXP)},
    {std::make_pair(static_cast<std::uint16_t>(0x007B), kProdId_IMP)},
    {std::make_pair(static_cast<std::uint16_t>(0x007C), kProdId_RES)},
    {std::make_pair(static_cast<std::uint16_t>(0x007D), kProdId_ASM)},
    {std::make_pair(static_cast<std::uint16_t>(0x0083), kProdId_C)},
    {std::make_pair(static_cast<std::uint16_t>(0x0084), kProdId_CPP)},
    {std::make_pair(static_cast<std::uint16_t>(0x0091), kProdId_LNK)},
    {std::make_pair(static_cast<std::uint16_t>(0x0092), kProdId_EXP)},
    {std::make_pair(static_cast<std::uint16_t>(0x0093), kProdId_IMP)},
    {std::make_pair(static_cast<std::uint16_t>(0x0094), kProdId_RES)},
    {std::make_pair(static_cast<std::uint16_t>(0x0095), kProdId_ASM)},
    {std::make_pair(static_cast<std::uint16_t>(0x009A), kProdId_RES)},
    {std::make_pair(static_cast<std::uint16_t>(0x009B), kProdId_EXP)},
    {std::make_pair(static_cast<std::uint16_t>(0x009C), kProdId_IMP)},
    {std::make_pair(static_cast<std::uint16_t>(0x009D), kProdId_LNK)},
    {std::make_pair(static_cast<std::uint16_t>(0x009E), kProdId_ASM)},
    {std::make_pair(static_cast<std::uint16_t>(0x00AA), kProdId_C)},
    {std::make_pair(static_cast<std::uint16_t>(0x00AB), kProdId_CPP)},
    {std::make_pair(static_cast<std::uint16_t>(0x00C9), kProdId_RES)},
    {std::make_pair(static_cast<std::uint16_t>(0x00CA), kProdId_EXP)},
    {std::make_pair(static_cast<std::uint16_t>(0x00CB), kProdId_IMP)},
    {std::make_pair(static_cast<std::uint16_t>(0x00CC), kProdId_LNK)},
    {std::make_pair(static_cast<std::uint16_t>(0x00CD), kProdId_ASM)},
    {std::make_pair(static_cast<std::uint16_t>(0x00CE), kProdId_C)},
    {std::make_pair(static_cast<std::uint16_t>(0x00CF), kProdId_CPP)},
    {std::make_pair(static_cast<std::uint16_t>(0x00DB), kProdId_RES)},
    {std::make_pair(static_cast<std::uint16_t>(0x00DC), kProdId_EXP)},
    {std::make_pair(static_cast<std::uint16_t>(0x00DD), kProdId_IMP)},
    {std::make_pair(static_cast<std::uint16_t>(0x00DE), kProdId_LNK)},
    {std::make_pair(static_cast<std::uint16_t>(0x00DF), kProdId_ASM)},
    {std::make_pair(static_cast<std::uint16_t>(0x00E0), kProdId_C)},
    {std::make_pair(static_cast<std::uint16_t>(0x00E1), kProdId_CPP)},
    {std::make_pair(static_cast<std::uint16_t>(0x00FF), kProdId_RES)},
    {std::make_pair(static_cast<std::uint16_t>(0x0100), kProdId_EXP)},
    {std::make_pair(static_cast<std::uint16_t>(0x0101), kProdId_IMP)},
    {std::make_pair(static_cast<std::uint16_t>(0x0102), kProdId_LNK)},
    {std::make_pair(static_cast<std::uint16_t>(0x0103), kProdId_ASM)},
    {std::make_pair(static_cast<std::uint16_t>(0x0104), kProdId_C)},
    {std::make_pair(static_cast<std::uint16_t>(0x0105), kProdId_CPP)}};

// Mapping of Rich header build number to version strings
static const std::map<std::uint16_t, const std::string> ProductMap = {
    // Source: https://github.com/dishather/richprint/blob/master/comp_id.txt
    {std::make_pair(static_cast<std::uint16_t>(0x0000), "Imported Functions")},
    {std::make_pair(static_cast<std::uint16_t>(0x0684),
                    "VS97 v5.0 SP3 cvtres 5.00.1668")},
    {std::make_pair(static_cast<std::uint16_t>(0x06B8),
                    "VS98 v6.0 cvtres build 1720")},
    {std::make_pair(static_cast<std::uint16_t>(0x06C8),
                    "VS98 v6.0 SP6 cvtres build 1736")},
    {std::make_pair(static_cast<std::uint16_t>(0x1C87),
                    "VS97 v5.0 SP3 link 5.10.7303")},
    {std::make_pair(static_cast<std::uint16_t>(0x5E92),
                    "VS2015 v14.0 UPD3 build 24210")},
    {std::make_pair(static_cast<std::uint16_t>(0x5E95),
                    "VS2015 UPD3 build 24213")},

    // http://bytepointer.com/articles/the_microsoft_rich_header.htm
    {std::make_pair(static_cast<std::uint16_t>(0x0BEC),
                    "VS2003 v7.1 Free Toolkit .NET build 3052")},
    {std::make_pair(static_cast<std::uint16_t>(0x0C05),
                    "VS2003 v7.1 .NET build 3077")},
    {std::make_pair(static_cast<std::uint16_t>(0x0FC3),
                    "VS2003 v7.1 | Windows Server 2003 SP1 DDK build 4035")},
    {std::make_pair(static_cast<std::uint16_t>(0x1C83), "MASM 6.13.7299")},
    {std::make_pair(static_cast<std::uint16_t>(0x178E),
                    "VS2003 v7.1 SP1 .NET build 6030")},
    {std::make_pair(static_cast<std::uint16_t>(0x1FE8),
                    "VS98 v6.0 RTM/SP1/SP2 build 8168")},
    {std::make_pair(static_cast<std::uint16_t>(0x1FE9),
                    "VB 6.0/SP1/SP2 build 8169")},
    {std::make_pair(static_cast<std::uint16_t>(0x20FC), "MASM 6.14.8444")},
    {std::make_pair(static_cast<std::uint16_t>(0x20FF),
                    "VC++ 6.0 SP3 build 8447")},
    {std::make_pair(static_cast<std::uint16_t>(0x212F),
                    "VB 6.0 SP3 build 8495")},
    {std::make_pair(static_cast<std::uint16_t>(0x225F),
                    "VS 6.0 SP4 build 8799")},
    {std::make_pair(static_cast<std::uint16_t>(0x2263), "MASM 6.15.8803")},
    {std::make_pair(static_cast<std::uint16_t>(0x22AD),
                    "VB 6.0 SP4 build 8877")},
    {std::make_pair(static_cast<std::uint16_t>(0x2304),
                    "VB 6.0 SP5 build 8964")},
    {std::make_pair(static_cast<std::uint16_t>(0x2306),
                    "VS 6.0 SP5 build 8966")},
    //  {std::make_pair(static_cast<std::uint16_t>(0x2346), "MASM 6.15.9030
    //  (VS.NET 7.0 BETA 1)")},
    {std::make_pair(static_cast<std::uint16_t>(0x2346),
                    "VS 7.0 2000 Beta 1 build 9030")},
    {std::make_pair(static_cast<std::uint16_t>(0x2354),
                    "VS 6.0 SP5 Processor Pack build 9044")},
    {std::make_pair(static_cast<std::uint16_t>(0x2426),
                    "VS2001 v7.0 Beta 2 build 9254")},
    {std::make_pair(static_cast<std::uint16_t>(0x24FA),
                    "VS2002 v7.0 .NET build 9466")},
    {std::make_pair(static_cast<std::uint16_t>(0x2636),
                    "VB 6.0 SP6 / VC++ build 9782")},
    {std::make_pair(static_cast<std::uint16_t>(0x26E3),
                    "VS2002 v7.0 SP1 build 9955")},
    {std::make_pair(static_cast<std::uint16_t>(0x520D),
                    "VS2013 v12.[0,1] build 21005")},
    {std::make_pair(static_cast<std::uint16_t>(0x521E),
                    "VS2008 v9.0 build 21022")},
    {std::make_pair(static_cast<std::uint16_t>(0x56C7),
                    "VS2015 v14.0 build 22215")},
    {std::make_pair(static_cast<std::uint16_t>(0x59F2),
                    "VS2015 v14.0 build 23026")},
    {std::make_pair(static_cast<std::uint16_t>(0x5BD2),
                    "VS2015 v14.0 UPD1 build 23506")},
    {std::make_pair(static_cast<std::uint16_t>(0x5D10),
                    "VS2015 v14.0 UPD2 build 23824")},
    {std::make_pair(static_cast<std::uint16_t>(0x5E97),
                    "VS2015 v14.0 UPD3.1 build 24215")},
    {std::make_pair(static_cast<std::uint16_t>(0x7725),
                    "VS2013 v12.0 UPD2 build 30501")},
    {std::make_pair(static_cast<std::uint16_t>(0x766F),
                    "VS2010 v10.0 build 30319")},
    {std::make_pair(static_cast<std::uint16_t>(0x7809),
                    "VS2008 v9.0 SP1 build 30729")},
    {std::make_pair(static_cast<std::uint16_t>(0x797D),
                    "VS2013 v12.0 UPD4 build 31101")},
    {std::make_pair(static_cast<std::uint16_t>(0x9D1B),
                    "VS2010 v10.0 SP1 build 40219")},
    {std::make_pair(static_cast<std::uint16_t>(0x9EB5),
                    "VS2013 v12.0 UPD5 build 40629")},
    {std::make_pair(static_cast<std::uint16_t>(0xC497),
                    "VS2005 v8.0 (Beta) build 50327")},
    {std::make_pair(static_cast<std::uint16_t>(0xC627),
                    "VS2005 v8.0 | VS2012 v11.0 build 50727")},
    {std::make_pair(static_cast<std::uint16_t>(0xC751),
                    "VS2012 v11.0 Nov CTP build 51025")},
    {std::make_pair(static_cast<std::uint16_t>(0xC7A2),
                    "VS2012 v11.0 UPD1 build 51106")},
    {std::make_pair(static_cast<std::uint16_t>(0xEB9B),
                    "VS2012 v11.0 UPD2 build 60315")},
    {std::make_pair(static_cast<std::uint16_t>(0xECC2),
                    "VS2012 v11.0 UPD3 build 60610")},
    {std::make_pair(static_cast<std::uint16_t>(0xEE66),
                    "VS2012 v11.0 UPD4 build 61030")},
    {std::make_pair(static_cast<std::uint16_t>(0x5E9A),
                    "VS2015 v14.0 build 24218")},
    {std::make_pair(static_cast<std::uint16_t>(0x61BB),
                    "VS2017 v14.1 build 25019")},

    // https://dev.to/yumetodo/list-of-mscver-and-mscfullver-8nd
    {std::make_pair(static_cast<std::uint16_t>(0x2264),
                    "VS 6 [SP5,SP6] build 8804")},
    {std::make_pair(static_cast<std::uint16_t>(0x23D8), "Windows XP SP1 DDK")},
    {std::make_pair(static_cast<std::uint16_t>(0x0883),
                    "Windows Server 2003 DDK")},
    {std::make_pair(static_cast<std::uint16_t>(0x08F4),
                    "VS2003 v7.1 .NET Beta build 2292")},
    {std::make_pair(static_cast<std::uint16_t>(0x9D76),
                    "Windows Server 2003 SP1 DDK (for AMD64)")},
    {std::make_pair(static_cast<std::uint16_t>(0x9E9F),
                    "VS2005 v8.0 Beta 1 build 40607")},
    {std::make_pair(static_cast<std::uint16_t>(0xC427),
                    "VS2005 v8.0 Beta 2 build 50215")},
    {std::make_pair(static_cast<std::uint16_t>(0xC490),
                    "VS2005 v8.0 build 50320")},
    {std::make_pair(static_cast<std::uint16_t>(0x50E2),
                    "VS2008 v9.0 Beta 2 build 20706")},
    {std::make_pair(static_cast<std::uint16_t>(0x501A),
                    "VS2010 v10.0 Beta 1 build 20506")},
    {std::make_pair(static_cast<std::uint16_t>(0x520B),
                    "VS2010 v10.0 Beta 2 build 21003")},
    {std::make_pair(static_cast<std::uint16_t>(0x5089),
                    "VS2013 v12.0 Preview build 20617")},
    {std::make_pair(static_cast<std::uint16_t>(0x515B),
                    "VS2013 v12.0 RC build 20827")},
    {std::make_pair(static_cast<std::uint16_t>(0x527A),
                    "VS2013 v12.0 Nov CTP build 21114")},
    {std::make_pair(static_cast<std::uint16_t>(0x63A3),
                    "VS2017 v15.3.3 build 25507")},
    {std::make_pair(static_cast<std::uint16_t>(0x63C6),
                    "VS2017 v15.4.4 build 25542")},
    {std::make_pair(static_cast<std::uint16_t>(0x63CB),
                    "VS2017 v15.4.5 build 25547")},
    {std::make_pair(static_cast<std::uint16_t>(0x7674),
                    "VS2013 v12.0 UPD2 RC build 30324")},

    // https://walbourn.github.io/visual-studio-2015-update-2/
    {std::make_pair(static_cast<std::uint16_t>(0x5D6E),
                    "VS2015 v14.0 UPD2 build 23918")},

    // https://walbourn.github.io/visual-studio-2017/
    {std::make_pair(static_cast<std::uint16_t>(0x61B9),
                    "VS2017 v15.[0,1] build 25017")},
    {std::make_pair(static_cast<std::uint16_t>(0x63A2),
                    "VS2017 v15.2 build 25019")},

    // https://walbourn.github.io/vs-2017-15-5-update/
    {std::make_pair(static_cast<std::uint16_t>(0x64E6),
                    "VS2017 v15 build 25830")},
    {std::make_pair(static_cast<std::uint16_t>(0x64E7),
                    "VS2017 v15.5.2 build 25831")},
    {std::make_pair(static_cast<std::uint16_t>(0x64EA),
                    "VS2017 v15.5.[3,4] build 25834")},
    {std::make_pair(static_cast<std::uint16_t>(0x64EB),
                    "VS2017 v15.5.[5,6,7] build 25835")},

    // https://walbourn.github.io/vs-2017-15-6-update/
    {std::make_pair(static_cast<std::uint16_t>(0x6610),
                    "VS2017 v15.6.[0,1,2] build 26128")},
    {std::make_pair(static_cast<std::uint16_t>(0x6611),
                    "VS2017 v15.6.[3,4] build 26129")},
    {std::make_pair(static_cast<std::uint16_t>(0x6613),
                    "VS2017 v15.6.6 build 26131")},
    {std::make_pair(static_cast<std::uint16_t>(0x6614),
                    "VS2017 v15.6.7 build 26132")},

    // https://devblogs.microsoft.com/visualstudio/visual-studio-2017-update/
    {std::make_pair(static_cast<std::uint16_t>(0x6723),
                    "VS2017 v15.1 build 26403")},

    // https://walbourn.github.io/vs-2017-15-7-update/
    {std::make_pair(static_cast<std::uint16_t>(0x673C),
                    "VS2017 v15.7.[0,1] build 26428")},
    {std::make_pair(static_cast<std::uint16_t>(0x673D),
                    "VS2017 v15.7.2 build 26429")},
    {std::make_pair(static_cast<std::uint16_t>(0x673E),
                    "VS2017 v15.7.3 build 26430")},
    {std::make_pair(static_cast<std::uint16_t>(0x673F),
                    "VS2017 v15.7.4 build 26431")},
    {std::make_pair(static_cast<std::uint16_t>(0x6741),
                    "VS2017 v15.7.5 build 26433")},

    // https://walbourn.github.io/visual-studio-2019/
    {std::make_pair(static_cast<std::uint16_t>(0x6B74),
                    "VS2019 v16.0.0 build 27508")},

    // https://walbourn.github.io/vs-2017-15-8-update/
    {std::make_pair(static_cast<std::uint16_t>(0x6866),
                    "VS2017 v15.8.0 build 26726")},
    {std::make_pair(static_cast<std::uint16_t>(0x6869),
                    "VS2017 v15.8.4 build 26729")},
    {std::make_pair(static_cast<std::uint16_t>(0x686A),
                    "VS2017 v15.8.9 build 26730")},
    {std::make_pair(static_cast<std::uint16_t>(0x686C),
                    "VS2017 v15.8.5 build 26732")},

    // https://walbourn.github.io/vs-2017-15-9-update/
    {std::make_pair(static_cast<std::uint16_t>(0x698F),
                    "VS2017 v15.9.[0,1] build 27023")},
    {std::make_pair(static_cast<std::uint16_t>(0x6990),
                    "VS2017 v15.9.2 build 27024")},
    {std::make_pair(static_cast<std::uint16_t>(0x6991),
                    "VS2017 v15.9.4 build 27025")},
    {std::make_pair(static_cast<std::uint16_t>(0x6992),
                    "VS2017 v15.9.5 build 27026")},
    {std::make_pair(static_cast<std::uint16_t>(0x6993),
                    "VS2017 v15.9.7 build 27027")},
    {std::make_pair(static_cast<std::uint16_t>(0x6996),
                    "VS2017 v15.9.11 build 27030")},
    {std::make_pair(static_cast<std::uint16_t>(0x6997),
                    "VS2017 v15.9.12 build 27031")},
    {std::make_pair(static_cast<std::uint16_t>(0x6998),
                    "VS2017 v15.9.14 build 27032")},
    {std::make_pair(static_cast<std::uint16_t>(0x699A),
                    "VS2017 v15.9.16 build 27034")},

    // https://walbourn.github.io/visual-studio-2019/
    {std::make_pair(static_cast<std::uint16_t>(0x6B74),
                    "VS2019 v16.0.0 RTM build 27508")},

    // https://walbourn.github.io/vs-2019-update-1/
    {std::make_pair(static_cast<std::uint16_t>(0x6C36),
                    "VS2019 v16.1.2 UPD1 build 27702")},

    // https://walbourn.github.io/vs-2019-update-2/
    {std::make_pair(static_cast<std::uint16_t>(0x6D01),
                    "VS2019 v16.2.3 UPD2 build 27905")},

    // https://walbourn.github.io/vs-2019-update-3/
    {std::make_pair(static_cast<std::uint16_t>(0x6DC9),
                    "VS2019 v16.3.2 UPD3 build 28105")},

    // https://walbourn.github.io/visual-studio-2013-update-3/
    {std::make_pair(static_cast<std::uint16_t>(0x7803),
                    "VS2013 v12.0 UPD3 build 30723")},

    // experimentation
    {std::make_pair(static_cast<std::uint16_t>(0x685B),
                    "VS2017 v15.8.? build 26715")},
};

static const std::string kUnknownProduct = "<unknown>";

// Returns a stringified Rich header object type given a product id
const std::string &GetRichObjectType(std::uint16_t prodId) {

  auto it = ProductIdMap.find(prodId);
  if (it != ProductIdMap.end()) {
    return it->second;
  } else {
    return kProdId_UNK;
  }
}

// Returns a stringified Rich header product name given a build number
const std::string &GetRichProductName(std::uint16_t buildNum) {

  auto it = ProductMap.find(buildNum);
  if (it != ProductMap.end()) {
    return it->second;
  } else {
    return kUnknownProduct;
  }
}

std::uint32_t err = 0;
std::string err_loc;

static const char *pe_err_str[] = {
    "None",
    "Out of memory",
    "Invalid header",
    "Invalid section",
    "Invalid resource",
    "Unable to get section for VA",
    "Unable to read data",
    "Unable to open",
    "Unable to stat",
    "Bad magic",
    "Invalid buffer",
    "Invalid address",
    "Invalid size",
};

std::uint32_t GetPEErr() {
  return err;
}

std::string GetPEErrString() {
  return pe_err_str[err];
}

std::string GetPEErrLoc() {
  return err_loc;
}

const char *GetSymbolTableStorageClassName(std::uint8_t id) {
  switch (id) {
    case IMAGE_SYM_CLASS_END_OF_FUNCTION:
      return "CLASS_END_OF_FUNCTION";
    case IMAGE_SYM_CLASS_NULL:
      return "CLASS_NULL";
    case IMAGE_SYM_CLASS_AUTOMATIC:
      return "CLASS_AUTOMATIC";
    case IMAGE_SYM_CLASS_EXTERNAL:
      return "CLASS_EXTERNAL";
    case IMAGE_SYM_CLASS_STATIC:
      return "CLASS_STATIC";
    case IMAGE_SYM_CLASS_REGISTER:
      return "CLASS_REGISTER";
    case IMAGE_SYM_CLASS_EXTERNAL_DEF:
      return "CLASS_EXTERNAL_DEF";
    case IMAGE_SYM_CLASS_LABEL:
      return "CLASS_LABEL";
    case IMAGE_SYM_CLASS_UNDEFINED_LABEL:
      return "CLASS_UNDEFINED_LABEL";
    case IMAGE_SYM_CLASS_MEMBER_OF_STRUCT:
      return "CLASS_MEMBER_OF_STRUCT";
    case IMAGE_SYM_CLASS_ARGUMENT:
      return "CLASS_ARGUMENT";
    case IMAGE_SYM_CLASS_STRUCT_TAG:
      return "CLASS_STRUCT_TAG";
    case IMAGE_SYM_CLASS_MEMBER_OF_UNION:
      return "CLASS_MEMBER_OF_UNION";
    case IMAGE_SYM_CLASS_UNION_TAG:
      return "CLASS_UNION_TAG";
    case IMAGE_SYM_CLASS_TYPE_DEFINITION:
      return "CLASS_TYPE_DEFINITION";
    case IMAGE_SYM_CLASS_UNDEFINED_STATIC:
      return "CLASS_UNDEFINED_STATIC";
    case IMAGE_SYM_CLASS_ENUM_TAG:
      return "CLASS_ENUM_TAG";
    case IMAGE_SYM_CLASS_MEMBER_OF_ENUM:
      return "CLASS_MEMBER_OF_ENUM";
    case IMAGE_SYM_CLASS_REGISTER_PARAM:
      return "CLASS_REGISTER_PARAM";
    case IMAGE_SYM_CLASS_BIT_FIELD:
      return "CLASS_BIT_FIELD";
    case IMAGE_SYM_CLASS_BLOCK:
      return "CLASS_BLOCK";
    case IMAGE_SYM_CLASS_FUNCTION:
      return "CLASS_FUNCTION";
    case IMAGE_SYM_CLASS_END_OF_STRUCT:
      return "CLASS_END_OF_STRUCT";
    case IMAGE_SYM_CLASS_FILE:
      return "CLASS_FILE";
    case IMAGE_SYM_CLASS_SECTION:
      return "CLASS_SECTION";
    case IMAGE_SYM_CLASS_WEAK_EXTERNAL:
      return "CLASS_WEAK_EXTERNAL";
    case IMAGE_SYM_CLASS_CLR_TOKEN:
      return "CLASS_CLR_TOKEN";
    default:
      return nullptr;
  }
}

static bool readCString(const bounded_buffer &buffer,
                        std::uint32_t off,
                        std::string &result) {
  if (off < buffer.bufLen) {
    std::uint8_t *p = buffer.buf;
    std::uint32_t n = buffer.bufLen;
    std::uint8_t *b = p + off;
    std::uint8_t *x = std::find(b, p + n, 0);

    if (x == p + n) {
      return false;
    }

    result.insert(result.end(), b, x);
    return true;
  }
  return false;
}

bool getSecForVA(const std::vector<section> &secs, VA v, section &sec) {
  for (section s : secs) {
    std::uint64_t low = s.sectionBase;
    std::uint64_t high = low + s.sec.Misc.VirtualSize;

    if (v >= low && v < high) {
      sec = s;
      return true;
    }
  }

  return false;
}

void IterRich(parsed_pe *pe, iterRich cb, void *cbd) {
  for (rich_entry &r : pe->peHeader.rich.Entries) {
    if (cb(cbd, r) != 0) {
      break;
    }
  }
}

void IterRsrc(parsed_pe *pe, iterRsrc cb, void *cbd) {
  parsed_pe_internal *pint = pe->internal;

  for (const resource &r : pint->rsrcs) {
    if (cb(cbd, r) != 0) {
      break;
    }
  }
}

bool parse_resource_id(bounded_buffer *data,
                       std::uint32_t id,
                       std::string &result) {
  std::uint16_t len;
  if (!readWord(data, id, len)) {
    return false;
  }
  id += 2;

  std::uint32_t rawSize = len * 2U;
  UCharString rawString;
  for (std::uint32_t i = 0; i < rawSize; i += 2) {
    char16_t c;
    if (!readChar16(data, id + i, c)) {
      return false;
    }
    rawString.push_back(c);
  }

  result = from_utf16(rawString);
  return true;
}

bool parse_resource_table(bounded_buffer *sectionData,
                          std::uint32_t o,
                          std::uint32_t virtaddr,
                          std::uint32_t depth,
                          resource_dir_entry *dirent,
                          std::vector<resource> &rsrcs) {
  resource_dir_table rdt;

  if (sectionData == nullptr) {
    return false;
  }

  READ_DWORD(sectionData, o, rdt, Characteristics);
  READ_DWORD(sectionData, o, rdt, TimeDateStamp);
  READ_WORD(sectionData, o, rdt, MajorVersion);
  READ_WORD(sectionData, o, rdt, MinorVersion);
  READ_WORD(sectionData, o, rdt, NameEntries);
  READ_WORD(sectionData, o, rdt, IDEntries);

  o += sizeof(resource_dir_table);

  if (rdt.NameEntries == 0u && rdt.IDEntries == 0u) {
    return true; // This is not a hard error. It does happen.
  }

  for (std::uint32_t i = 0;
       i < static_cast<std::uint32_t>(rdt.NameEntries + rdt.IDEntries);
       i++) {
    resource_dir_entry *rde = dirent;
    if (dirent == nullptr) {
      rde = new resource_dir_entry;
    }

    if (!readDword(sectionData, o + offsetof(__typeof__(*rde), ID), rde->ID)) {
      PE_ERR(PEERR_READ);
      if (dirent == nullptr) {
        delete rde;
      }
      return false;
    }

    if (!readDword(
            sectionData, o + offsetof(__typeof__(*rde), RVA), rde->RVA)) {
      PE_ERR(PEERR_READ);
      if (dirent == nullptr) {
        delete rde;
      }
      return false;
    }

    o += sizeof(resource_dir_entry_sz);

    if (depth == 0) {
      rde->type = rde->ID;
      if (i < rdt.NameEntries) {
        if (!parse_resource_id(
                sectionData, rde->ID & 0x0FFFFFFF, rde->type_str)) {
          if (dirent == nullptr) {
            delete rde;
          }
          return false;
        }
      }
    } else if (depth == 1) {
      rde->name = rde->ID;
      if (i < rdt.NameEntries) {
        if (!parse_resource_id(
                sectionData, rde->ID & 0x0FFFFFFF, rde->name_str)) {
          if (dirent == nullptr) {
            delete rde;
          }
          return false;
        }
      }
    } else if (depth == 2) {
      rde->lang = rde->ID;
      if (i < rdt.NameEntries) {
        if (!parse_resource_id(
                sectionData, rde->ID & 0x0FFFFFFF, rde->lang_str)) {
          if (dirent == nullptr) {
            delete rde;
          }
          return false;
        }
      }
    } else {
      /* .rsrc can accomodate up to 2**31 levels, but Windows only uses 3 by
       * convention. As such, any depth above 3 indicates potentially unchecked
       * recusion. See:
       * https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-rsrc-section
       */

      PE_ERR(PEERR_RESC);
      return false;
    }

    // High bit 0 = RVA to RDT.
    // High bit 1 = RVA to RDE.
    if (rde->RVA & 0x80000000) {
      if (!parse_resource_table(sectionData,
                                rde->RVA & 0x0FFFFFFF,
                                virtaddr,
                                depth + 1,
                                rde,
                                rsrcs)) {
        if (dirent == nullptr) {
          delete rde;
        }
        return false;
      }
    } else {
      resource_dat_entry rdat;

      /*
       * This one is using rde->RVA as an offset.
       *
       * This is because we don't want to set o because we have to keep the
       * original value when we are done parsing this resource data entry.
       * We could store the original o value and reset it when we are done,
       * but meh.
       */

      if (!readDword(sectionData,
                     rde->RVA + offsetof(__typeof__(rdat), RVA),
                     rdat.RVA)) {
        PE_ERR(PEERR_READ);
        if (dirent == nullptr) {
          delete rde;
        }
        return false;
      }

      if (!readDword(sectionData,
                     rde->RVA + offsetof(__typeof__(rdat), size),
                     rdat.size)) {
        PE_ERR(PEERR_READ);
        if (dirent == nullptr) {
          delete rde;
        }
        return false;
      }

      if (!readDword(sectionData,
                     rde->RVA + offsetof(__typeof__(rdat), codepage),
                     rdat.codepage)) {
        PE_ERR(PEERR_READ);
        if (dirent == nullptr) {
          delete rde;
        }
        return false;
      }

      if (!readDword(sectionData,
                     rde->RVA + offsetof(__typeof__(rdat), reserved),
                     rdat.reserved)) {
        PE_ERR(PEERR_READ);
        if (dirent == nullptr) {
          delete rde;
        }
        return false;
      }

      resource rsrc;
      rsrc.type_str = rde->type_str;
      rsrc.name_str = rde->name_str;
      rsrc.lang_str = rde->lang_str;
      rsrc.type = rde->type;
      rsrc.name = rde->name;
      rsrc.lang = rde->lang;
      rsrc.codepage = rdat.codepage;
      rsrc.RVA = rdat.RVA;
      rsrc.size = rdat.size;

      // The start address is (RVA - section virtual address).
      uint32_t start = rdat.RVA - virtaddr;
      /*
       * Some binaries (particularly packed) will have invalid addresses here.
       * If those happen, return a zero length buffer.
       * If the start is valid, try to get the data and if that fails return
       * a zero length buffer.
       */
      if (start > rdat.RVA) {
        rsrc.buf = splitBuffer(sectionData, 0, 0);
      } else {
        rsrc.buf = splitBuffer(sectionData, start, start + rdat.size);
        if (rsrc.buf == nullptr) {
          rsrc.buf = splitBuffer(sectionData, 0, 0);
        }
      }

      /* If we can't get even a zero length buffer, something is very wrong. */
      if (rsrc.buf == nullptr) {
        if (dirent == nullptr) {
          delete rde;
        }
        return false;
      }

      rsrcs.push_back(rsrc);
    }

    if (depth == 0) {
      rde->type_str.clear();
    } else if (depth == 1) {
      rde->name_str.clear();
    } else if (depth == 2) {
      rde->lang_str.clear();
    }

    if (dirent == nullptr) {
      delete rde;
    }
  }

  return true;
}

bool getResources(bounded_buffer *b,
                  bounded_buffer *fileBegin,
                  const std::vector<section> secs,
                  std::vector<resource> &rsrcs) {
  static_cast<void>(fileBegin);

  if (b == nullptr)
    return false;

  for (section s : secs) {
    if (s.sectionName != ".rsrc") {
      continue;
    }

    if (!parse_resource_table(
            s.sectionData, 0, s.sec.VirtualAddress, 0, nullptr, rsrcs)) {
      return false;
    }

    break; // Because there should only be one .rsrc
  }

  return true;
}

bool getSections(bounded_buffer *b,
                 bounded_buffer *fileBegin,
                 nt_header_32 &nthdr,
                 std::vector<section> &secs) {
  if (b == nullptr) {
    return false;
  }

  // get each of the sections...
  for (std::uint32_t i = 0; i < nthdr.FileHeader.NumberOfSections; i++) {
    image_section_header curSec;

    std::uint32_t o = i * sizeof(image_section_header);
    for (std::uint32_t k = 0; k < NT_SHORT_NAME_LEN; k++) {
      if (!readByte(b, o + k, curSec.Name[k])) {
        return false;
      }
    }

    READ_DWORD(b, o, curSec, Misc.VirtualSize);
    READ_DWORD(b, o, curSec, VirtualAddress);
    READ_DWORD(b, o, curSec, SizeOfRawData);
    READ_DWORD(b, o, curSec, PointerToRawData);
    READ_DWORD(b, o, curSec, PointerToRelocations);
    READ_DWORD(b, o, curSec, PointerToLinenumbers);
    READ_WORD(b, o, curSec, NumberOfRelocations);
    READ_WORD(b, o, curSec, NumberOfLinenumbers);
    READ_DWORD(b, o, curSec, Characteristics);

    // now we have the section header information, so fill in a section
    // object appropriately
    section thisSec;
    for (std::uint32_t charIndex = 0; charIndex < NT_SHORT_NAME_LEN;
         charIndex++) {
      std::uint8_t c = curSec.Name[charIndex];
      if (c == 0) {
        break;
      }

      thisSec.sectionName.push_back(static_cast<char>(c));
    }

    if (nthdr.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      thisSec.sectionBase =
          nthdr.OptionalHeader.ImageBase + curSec.VirtualAddress;
    } else if (nthdr.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
      thisSec.sectionBase =
          nthdr.OptionalHeader64.ImageBase + curSec.VirtualAddress;
    } else {
      PE_ERR(PEERR_MAGIC);
    }

    thisSec.sec = curSec;
    std::uint32_t lowOff = curSec.PointerToRawData;
    std::uint32_t highOff = lowOff + curSec.SizeOfRawData;
    thisSec.sectionData = splitBuffer(fileBegin, lowOff, highOff);

    // GH#109: we trusted [lowOff, highOff) to be a range that yields
    // a valid bounded_buffer, despite these being user-controllable.
    // splitBuffer correctly handles this, but we failed to check for
    // the nullptr it returns as a sentinel.
    if (thisSec.sectionData == nullptr) {
      return false;
    }

    secs.push_back(thisSec);
  }

  std::sort(
      secs.begin(), secs.end(), [](const section &lhs, const section &rhs) {
        return lhs.sec.PointerToRawData < rhs.sec.PointerToRawData;
      });

  return true;
}

bool readOptionalHeader(bounded_buffer *b, optional_header_32 &header) {
  READ_WORD(b, 0, header, Magic);

  READ_BYTE(b, 0, header, MajorLinkerVersion);
  READ_BYTE(b, 0, header, MinorLinkerVersion);
  READ_DWORD(b, 0, header, SizeOfCode);
  READ_DWORD(b, 0, header, SizeOfInitializedData);
  READ_DWORD(b, 0, header, SizeOfUninitializedData);
  READ_DWORD(b, 0, header, AddressOfEntryPoint);
  READ_DWORD(b, 0, header, BaseOfCode);
  READ_DWORD(b, 0, header, BaseOfData);
  READ_DWORD(b, 0, header, ImageBase);
  READ_DWORD(b, 0, header, SectionAlignment);
  READ_DWORD(b, 0, header, FileAlignment);
  READ_WORD(b, 0, header, MajorOperatingSystemVersion);
  READ_WORD(b, 0, header, MinorOperatingSystemVersion);
  READ_WORD(b, 0, header, MajorImageVersion);
  READ_WORD(b, 0, header, MinorImageVersion);
  READ_WORD(b, 0, header, MajorSubsystemVersion);
  READ_WORD(b, 0, header, MinorSubsystemVersion);
  READ_DWORD(b, 0, header, Win32VersionValue);
  READ_DWORD(b, 0, header, SizeOfImage);
  READ_DWORD(b, 0, header, SizeOfHeaders);
  READ_DWORD(b, 0, header, CheckSum);
  READ_WORD(b, 0, header, Subsystem);
  READ_WORD(b, 0, header, DllCharacteristics);
  READ_DWORD(b, 0, header, SizeOfStackReserve);
  READ_DWORD(b, 0, header, SizeOfStackCommit);
  READ_DWORD(b, 0, header, SizeOfHeapReserve);
  READ_DWORD(b, 0, header, SizeOfHeapCommit);
  READ_DWORD(b, 0, header, LoaderFlags);
  READ_DWORD(b, 0, header, NumberOfRvaAndSizes);

  if (header.NumberOfRvaAndSizes > NUM_DIR_ENTRIES) {
    header.NumberOfRvaAndSizes = NUM_DIR_ENTRIES;
  }

  for (std::uint32_t i = 0; i < header.NumberOfRvaAndSizes; i++) {
    std::uint32_t c = (i * sizeof(data_directory));
    c += offsetof(optional_header_32, DataDirectory[0]);
    std::uint32_t o;

    o = c + offsetof(data_directory, VirtualAddress);
    if (!readDword(b, o, header.DataDirectory[i].VirtualAddress)) {
      return false;
    }

    o = c + offsetof(data_directory, Size);
    if (!readDword(b, o, header.DataDirectory[i].Size)) {
      return false;
    }
  }

  return true;
}

bool readOptionalHeader64(bounded_buffer *b, optional_header_64 &header) {
  READ_WORD(b, 0, header, Magic);

  READ_BYTE(b, 0, header, MajorLinkerVersion);
  READ_BYTE(b, 0, header, MinorLinkerVersion);
  READ_DWORD(b, 0, header, SizeOfCode);
  READ_DWORD(b, 0, header, SizeOfInitializedData);
  READ_DWORD(b, 0, header, SizeOfUninitializedData);
  READ_DWORD(b, 0, header, AddressOfEntryPoint);
  READ_DWORD(b, 0, header, BaseOfCode);
  READ_QWORD(b, 0, header, ImageBase);
  READ_DWORD(b, 0, header, SectionAlignment);
  READ_DWORD(b, 0, header, FileAlignment);
  READ_WORD(b, 0, header, MajorOperatingSystemVersion);
  READ_WORD(b, 0, header, MinorOperatingSystemVersion);
  READ_WORD(b, 0, header, MajorImageVersion);
  READ_WORD(b, 0, header, MinorImageVersion);
  READ_WORD(b, 0, header, MajorSubsystemVersion);
  READ_WORD(b, 0, header, MinorSubsystemVersion);
  READ_DWORD(b, 0, header, Win32VersionValue);
  READ_DWORD(b, 0, header, SizeOfImage);
  READ_DWORD(b, 0, header, SizeOfHeaders);
  READ_DWORD(b, 0, header, CheckSum);
  READ_WORD(b, 0, header, Subsystem);
  READ_WORD(b, 0, header, DllCharacteristics);
  READ_QWORD(b, 0, header, SizeOfStackReserve);
  READ_QWORD(b, 0, header, SizeOfStackCommit);
  READ_QWORD(b, 0, header, SizeOfHeapReserve);
  READ_QWORD(b, 0, header, SizeOfHeapCommit);
  READ_DWORD(b, 0, header, LoaderFlags);
  READ_DWORD(b, 0, header, NumberOfRvaAndSizes);

  if (header.NumberOfRvaAndSizes > NUM_DIR_ENTRIES) {
    header.NumberOfRvaAndSizes = NUM_DIR_ENTRIES;
  }

  for (std::uint32_t i = 0; i < header.NumberOfRvaAndSizes; i++) {
    std::uint32_t c = (i * sizeof(data_directory));
    c += offsetof(optional_header_64, DataDirectory[0]);
    std::uint32_t o;

    o = c + offsetof(data_directory, VirtualAddress);
    if (!readDword(b, o, header.DataDirectory[i].VirtualAddress)) {
      return false;
    }

    o = c + offsetof(data_directory, Size);
    if (!readDword(b, o, header.DataDirectory[i].Size)) {
      return false;
    }
  }

  return true;
}

bool readFileHeader(bounded_buffer *b, file_header &header) {
  READ_WORD(b, 0, header, Machine);
  READ_WORD(b, 0, header, NumberOfSections);
  READ_DWORD(b, 0, header, TimeDateStamp);
  READ_DWORD(b, 0, header, PointerToSymbolTable);
  READ_DWORD(b, 0, header, NumberOfSymbols);
  READ_WORD(b, 0, header, SizeOfOptionalHeader);
  READ_WORD(b, 0, header, Characteristics);

  return true;
}

bool readNtHeader(bounded_buffer *b, nt_header_32 &header) {
  if (b == nullptr) {
    return false;
  }

  std::uint32_t pe_magic;
  std::uint32_t curOffset = 0;
  if (!readDword(b, curOffset, pe_magic) || pe_magic != NT_MAGIC) {
    PE_ERR(PEERR_READ);
    return false;
  }

  header.Signature = pe_magic;
  bounded_buffer *fhb =
      splitBuffer(b, offsetof(nt_header_32, FileHeader), b->bufLen);

  if (fhb == nullptr) {
    PE_ERR(PEERR_MEM);
    return false;
  }

  if (!readFileHeader(fhb, header.FileHeader)) {
    deleteBuffer(fhb);
    return false;
  }

  if (TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_ARM, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_M32R, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_POWERPC, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_R4000, IMAGE_FILE_BYTES_REVERSED_HI) ||
      TEST_MACHINE_CHARACTERISTICS(
          header, IMAGE_FILE_MACHINE_WCEMIPSV2, IMAGE_FILE_BYTES_REVERSED_HI)) {
    b->swapBytes = true;
  }

  /*
   * The buffer is split using the OptionalHeader offset, even if it turns
   * out to be a PE32+. The start of the buffer is at the same spot in the
   * buffer regardless.
   */
  bounded_buffer *ohb =
      splitBuffer(b, offsetof(nt_header_32, OptionalHeader), b->bufLen);

  if (ohb == nullptr) {
    deleteBuffer(fhb);
    PE_ERR(PEERR_MEM);
    return false;
  }

  /*
   * Read the Magic to determine if it is 32 or 64.
   */
  if (!readWord(ohb, 0, header.OptionalMagic)) {
    PE_ERR(PEERR_READ);
    if (ohb != nullptr) {
      deleteBuffer(ohb);
    }
    deleteBuffer(fhb);
    return false;
  }
  if (header.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
    if (!readOptionalHeader(ohb, header.OptionalHeader)) {
      deleteBuffer(ohb);
      deleteBuffer(fhb);
      return false;
    }
  } else if (header.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
    if (!readOptionalHeader64(ohb, header.OptionalHeader64)) {
      deleteBuffer(ohb);
      deleteBuffer(fhb);
      return false;
    }
  } else {
    PE_ERR(PEERR_MAGIC);
    deleteBuffer(ohb);
    deleteBuffer(fhb);
    return false;
  }

  deleteBuffer(ohb);
  deleteBuffer(fhb);

  return true;
}

// zero extends its first argument to 32 bits and then performs a rotate left
// operation equal to the second arguments value of the first argument’s bits
static inline std::uint32_t rol(std::uint32_t val, std::uint32_t num) {
  assert(num < 32);
  // Disable MSVC warning for unary minus operator applied to unsigned type
#if defined(_MSC_VER) || defined(_MSC_FULL_VER)
#pragma warning(push)
#pragma warning(disable : 4146)
#endif
  // https://blog.regehr.org/archives/1063
  return (val << num) | (val >> (-num & 31));
#if defined(_MSC_VER) || defined(_MSC_FULL_VER)
#pragma warning(pop)
#endif
}

std::uint32_t calculateRichChecksum(const bounded_buffer *b, pe_header &p) {

  // First, calculate the sum of the DOS header bytes each rotated left the
  // number of times their position relative to the start of the DOS header e.g.
  // second byte is rotated left 2x using rol operation
  std::uint32_t checksum = 0;

  for (uint8_t i = 0; i < RICH_OFFSET; i++) {

    // skip over dos e_lfanew field at offset 0x3C
    if (i >= 0x3C && i <= 0x3F) {
      continue;
    }
    checksum += rol(b->buf[i], i & 0x1F);
  }

  // Next, take summation of each Rich header entry by combining its ProductId
  // and BuildNumber into a single 32 bit number and rotating by its count.
  for (rich_entry entry : p.rich.Entries) {
    std::uint32_t num =
        static_cast<std::uint32_t>((entry.ProductId << 16) | entry.BuildNumber);
    checksum += rol(num, entry.Count & 0x1F);
  }

  checksum += RICH_OFFSET;

  return checksum;
}

bool readRichHeader(bounded_buffer *rich_buf,
                    std::uint32_t key,
                    rich_header &rich_hdr) {
  if (rich_buf == nullptr) {
    return false;
  }

  std::uint32_t encrypted_dword;
  std::uint32_t decrypted_dword;

  // Confirm DanS signature exists first.
  // The first decrypted DWORD value of the rich header
  // at offset 0 should be 0x536e6144 aka the "DanS" signature
  if (!readDword(rich_buf, 0, encrypted_dword)) {
    PE_ERR(PEERR_READ);
    return false;
  }

  decrypted_dword = encrypted_dword ^ key;

  if (decrypted_dword == RICH_MAGIC_START) {
    // DanS magic found
    rich_hdr.isPresent = true;
    rich_hdr.StartSignature = decrypted_dword;
  } else {
    // DanS magic not found
    rich_hdr.isPresent = false;
    return false;
  }

  // Iterate over the remaining entries.
  // Start from buffer offset 16 because after "DanS" there
  // are three DWORDs of zero padding that can be skipped over.
  // a DWORD is 4 bytes. Loop is incrementing 8 bytes, however
  // we are reading two DWORDS at a time, which is the size
  // of one rich header entry.
  for (std::uint32_t i = 16; i < rich_buf->bufLen - 8; i += 8) {
    rich_entry entry;
    // Read first DWORD of entry and decrypt it
    if (!readDword(rich_buf, i, encrypted_dword)) {
      PE_ERR(PEERR_READ);
      return false;
    }
    decrypted_dword = encrypted_dword ^ key;
    // The high WORD of the first DWORD is the Product ID
    entry.ProductId = (decrypted_dword & 0xFFFF0000) >> 16;
    // The low WORD of the first DWORD is the Build Number
    entry.BuildNumber = (decrypted_dword & 0xFFFF);

    // The second DWORD represents the use count
    if (!readDword(rich_buf, i + 4, encrypted_dword)) {
      PE_ERR(PEERR_READ);
      return false;
    }
    decrypted_dword = encrypted_dword ^ key;
    // The full 32-bit DWORD is the count
    entry.Count = decrypted_dword;

    // Preserve the individual entry
    rich_hdr.Entries.push_back(entry);
  }

  // Preserve the end signature aka "Rich" magic
  if (!readDword(rich_buf, rich_buf->bufLen - 4, rich_hdr.EndSignature)) {
    PE_ERR(PEERR_READ);
    return false;
  };
  if (rich_hdr.EndSignature != RICH_MAGIC_END) {
    PE_ERR(PEERR_MAGIC);
    return false;
  }

  // Preserve the decryption key
  rich_hdr.DecryptionKey = key;

  return true;
}

bool readDosHeader(bounded_buffer *file, dos_header &dos_hdr) {
  if (file == nullptr) {
    return false;
  }

  READ_WORD(file, 0, dos_hdr, e_magic);
  READ_WORD(file, 0, dos_hdr, e_cblp);
  READ_WORD(file, 0, dos_hdr, e_cp);
  READ_WORD(file, 0, dos_hdr, e_crlc);
  READ_WORD(file, 0, dos_hdr, e_cparhdr);
  READ_WORD(file, 0, dos_hdr, e_minalloc);
  READ_WORD(file, 0, dos_hdr, e_maxalloc);
  READ_WORD(file, 0, dos_hdr, e_ss);
  READ_WORD(file, 0, dos_hdr, e_sp);
  READ_WORD(file, 0, dos_hdr, e_csum);
  READ_WORD(file, 0, dos_hdr, e_ip);
  READ_WORD(file, 0, dos_hdr, e_cs);
  READ_WORD(file, 0, dos_hdr, e_lfarlc);
  READ_WORD(file, 0, dos_hdr, e_ovno);
  READ_WORD(file, 0, dos_hdr, e_res[0]);
  READ_WORD(file, 0, dos_hdr, e_res[1]);
  READ_WORD(file, 0, dos_hdr, e_res[2]);
  READ_WORD(file, 0, dos_hdr, e_res[3]);
  READ_WORD(file, 0, dos_hdr, e_oemid);
  READ_WORD(file, 0, dos_hdr, e_oeminfo);
  READ_WORD(file, 0, dos_hdr, e_res2[0]);
  READ_WORD(file, 0, dos_hdr, e_res2[1]);
  READ_WORD(file, 0, dos_hdr, e_res2[2]);
  READ_WORD(file, 0, dos_hdr, e_res2[3]);
  READ_WORD(file, 0, dos_hdr, e_res2[4]);
  READ_WORD(file, 0, dos_hdr, e_res2[5]);
  READ_WORD(file, 0, dos_hdr, e_res2[6]);
  READ_WORD(file, 0, dos_hdr, e_res2[7]);
  READ_WORD(file, 0, dos_hdr, e_res2[8]);
  READ_WORD(file, 0, dos_hdr, e_res2[9]);
  READ_DWORD(file, 0, dos_hdr, e_lfanew);

  return true;
}

bool getHeader(bounded_buffer *file, pe_header &p, bounded_buffer *&rem) {
  if (file == nullptr) {
    return false;
  }

  // read the DOS header
  readDosHeader(file, p.dos);

  if (p.dos.e_magic != MZ_MAGIC) {
    PE_ERR(PEERR_MAGIC);
    return false;
  }

  // get the offset to the NT headers
  std::uint32_t offset = p.dos.e_lfanew;
  std::uint32_t curOffset = offset;

  // read rich header
  std::uint32_t dword;
  std::uint32_t rich_end_signature_offset = 0;
  std::uint32_t xor_key;
  bool found_rich = false;

  // Start reading from RICH_OFFSET (0x80), a known Rich header offset.
  // Note: 0x80 is based on anecdotal evidence.
  //
  // Iterate over the DWORDs, hence why i increments 4 bytes at a time.
  for (std::uint32_t i = RICH_OFFSET; i < offset; i += 4) {
    if (!readDword(file, i, dword)) {
      PE_ERR(PEERR_READ);
      return false;
    }

    // Found the trailing Rich signature
    if (dword == RICH_MAGIC_END) {
      found_rich = true;
      rich_end_signature_offset = i;
      break;
    }
  }

  if (found_rich) {
    // Get the XOR decryption key.  It is the DWORD immediately
    // after the Rich signature.
    if (!readDword(file, rich_end_signature_offset + 4, xor_key)) {
      PE_ERR(PEERR_READ);
      return false;
    }

    // Split the Rich header out into its own buffer
    bounded_buffer *richBuf =
        splitBuffer(file, 0x80, rich_end_signature_offset + 4);
    if (richBuf == nullptr) {
      return false;
    }

    readRichHeader(richBuf, xor_key, p.rich);
    if (richBuf != nullptr) {
      deleteBuffer(richBuf);
    }

    // Split the DOS header into a separate buffer which
    // starts at offset 0 and has length 0x80
    bounded_buffer *dosBuf = splitBuffer(file, 0, RICH_OFFSET);
    if (dosBuf == nullptr) {
      return false;
    }
    // Calculate checksum
    p.rich.Checksum = calculateRichChecksum(dosBuf, p);
    if (p.rich.Checksum == p.rich.DecryptionKey) {
      p.rich.isValid = true;
    } else {
      p.rich.isValid = false;
    }
    if (dosBuf != nullptr) {
      deleteBuffer(dosBuf);
    }

    // Rich header not present
  } else {
    p.rich.isPresent = false;
  }

  // now, we can read out the fields of the NT headers
  bounded_buffer *ntBuf = splitBuffer(file, curOffset, file->bufLen);

  if (!readNtHeader(ntBuf, p.nt)) {
    // err is set by readNtHeader
    if (ntBuf != nullptr) {
      deleteBuffer(ntBuf);
    }
    return false;
  }

  /*
   * Need to determine if this is a PE32 or PE32+ binary and use the
   # correct size.
   */
  std::uint32_t rem_size;
  if (p.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
    // signature + file_header + optional_header_32
    rem_size = sizeof(std::uint32_t) + sizeof(file_header) +
               sizeof(optional_header_32);
  } else if (p.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
    // signature + file_header + optional_header_64
    rem_size = sizeof(std::uint32_t) + sizeof(file_header) +
               sizeof(optional_header_64);
  } else {
    PE_ERR(PEERR_MAGIC);
    deleteBuffer(ntBuf);
    return false;
  }

  // update 'rem' to point to the space after the header
  rem = splitBuffer(ntBuf, rem_size, ntBuf->bufLen);
  deleteBuffer(ntBuf);

  return true;
}

bool getExports(parsed_pe *p) {
  data_directory exportDir;
  if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
    exportDir = p->peHeader.nt.OptionalHeader.DataDirectory[DIR_EXPORT];
  } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
    exportDir = p->peHeader.nt.OptionalHeader64.DataDirectory[DIR_EXPORT];
  } else {
    return false;
  }

  if (exportDir.Size != 0) {
    section s;
    VA addr;
    if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      addr = exportDir.VirtualAddress + p->peHeader.nt.OptionalHeader.ImageBase;
    } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
      addr =
          exportDir.VirtualAddress + p->peHeader.nt.OptionalHeader64.ImageBase;
    } else {
      return false;
    }

    if (!getSecForVA(p->internal->secs, addr, s)) {
      return false;
    }

    auto rvaofft = static_cast<std::uint32_t>(addr - s.sectionBase);

    // get the name of this module
    std::uint32_t nameRva;
    if (!readDword(s.sectionData,
                   rvaofft + offsetof(export_dir_table, NameRVA),
                   nameRva)) {
      return false;
    }

    VA nameVA;
    if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      nameVA = nameRva + p->peHeader.nt.OptionalHeader.ImageBase;
    } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
      nameVA = nameRva + p->peHeader.nt.OptionalHeader64.ImageBase;
    } else {
      return false;
    }

    section nameSec;
    if (!getSecForVA(p->internal->secs, nameVA, nameSec)) {
      return false;
    }

    auto nameOff = static_cast<std::uint32_t>(nameVA - nameSec.sectionBase);
    std::string modName;
    if (!readCString(*nameSec.sectionData, nameOff, modName)) {
      return false;
    }

    // now, get all the named export symbols
    std::uint32_t numNames;
    if (!readDword(s.sectionData,
                   rvaofft + offsetof(export_dir_table, NumberOfNamePointers),
                   numNames)) {
      return false;
    }

    if (numNames > 0) {
      // get the names section
      std::uint32_t namesRVA;
      if (!readDword(s.sectionData,
                     rvaofft + offsetof(export_dir_table, NamePointerRVA),
                     namesRVA)) {
        return false;
      }

      VA namesVA;
      if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
        namesVA = namesRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
        namesVA = namesRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
      } else {
        return false;
      }

      section namesSec;
      if (!getSecForVA(p->internal->secs, namesVA, namesSec)) {
        return false;
      }

      auto namesOff =
          static_cast<std::uint32_t>(namesVA - namesSec.sectionBase);

      // get the EAT section
      std::uint32_t eatRVA;
      if (!readDword(s.sectionData,
                     rvaofft +
                         offsetof(export_dir_table, ExportAddressTableRVA),
                     eatRVA)) {
        return false;
      }

      VA eatVA;
      if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
        eatVA = eatRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
        eatVA = eatRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
      } else {
        return false;
      }

      section eatSec;
      if (!getSecForVA(p->internal->secs, eatVA, eatSec)) {
        return false;
      }

      auto eatOff = static_cast<std::uint32_t>(eatVA - eatSec.sectionBase);

      // get the ordinal base
      std::uint32_t ordinalBase;
      if (!readDword(s.sectionData,
                     rvaofft + offsetof(export_dir_table, OrdinalBase),
                     ordinalBase)) {
        return false;
      }

      // get the ordinal table
      std::uint32_t ordinalTableRVA;
      if (!readDword(s.sectionData,
                     rvaofft + offsetof(export_dir_table, OrdinalTableRVA),
                     ordinalTableRVA)) {
        return false;
      }

      VA ordinalTableVA;
      if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
        ordinalTableVA =
            ordinalTableRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
        ordinalTableVA =
            ordinalTableRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
      } else {
        return false;
      }

      section ordinalTableSec;
      if (!getSecForVA(p->internal->secs, ordinalTableVA, ordinalTableSec)) {
        return false;
      }

      auto ordinalOff = static_cast<std::uint32_t>(ordinalTableVA -
                                                   ordinalTableSec.sectionBase);

      for (std::uint32_t i = 0; i < numNames; i++) {
        std::uint32_t curNameRVA;
        if (!readDword(namesSec.sectionData,
                       namesOff + (i * sizeof(std::uint32_t)),
                       curNameRVA)) {
          return false;
        }

        VA curNameVA;
        if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
          curNameVA = curNameRVA + p->peHeader.nt.OptionalHeader.ImageBase;
        } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
          curNameVA = curNameRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
        } else {
          return false;
        }

        section curNameSec;

        if (!getSecForVA(p->internal->secs, curNameVA, curNameSec)) {
          return false;
        }

        auto curNameOff =
            static_cast<std::uint32_t>(curNameVA - curNameSec.sectionBase);
        std::string symName;
        std::uint8_t d;

        do {
          if (!readByte(curNameSec.sectionData, curNameOff, d)) {
            return false;
          }

          if (d == 0) {
            break;
          }

          symName.push_back(static_cast<char>(d));
          curNameOff++;
        } while (true);

        // now, for this i, look it up in the ExportOrdinalTable
        std::uint16_t ordinal;
        if (!readWord(ordinalTableSec.sectionData,
                      ordinalOff + (i * sizeof(std::uint16_t)),
                      ordinal)) {
          return false;
        }

        //::uint32_t  eatIdx = ordinal - ordinalBase;
        std::uint32_t eatIdx = (ordinal * sizeof(std::uint32_t));

        std::uint32_t symRVA;
        if (!readDword(eatSec.sectionData, eatOff + eatIdx, symRVA)) {
          return false;
        }

        bool isForwarded =
            ((symRVA >= exportDir.VirtualAddress) &&
             (symRVA < exportDir.VirtualAddress + exportDir.Size));

        if (!isForwarded) {
          VA symVA;
          if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
            symVA = symRVA + p->peHeader.nt.OptionalHeader.ImageBase;
          } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
            symVA = symRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
          } else {
            return false;
          }

          exportent a;

          a.addr = symVA;
          a.symbolName = symName;
          a.moduleName = modName;
          p->internal->exports.push_back(a);
        }
      }
    }
  }

  return true;
}

bool getRelocations(parsed_pe *p) {
  data_directory relocDir;
  if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
    relocDir = p->peHeader.nt.OptionalHeader.DataDirectory[DIR_BASERELOC];
  } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
    relocDir = p->peHeader.nt.OptionalHeader64.DataDirectory[DIR_BASERELOC];
  } else {
    return false;
  }

  if (relocDir.Size != 0) {
    section d;
    VA vaAddr;
    if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      vaAddr =
          relocDir.VirtualAddress + p->peHeader.nt.OptionalHeader.ImageBase;
    } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
      vaAddr =
          relocDir.VirtualAddress + p->peHeader.nt.OptionalHeader64.ImageBase;
    } else {
      return false;
    }

    if (!getSecForVA(p->internal->secs, vaAddr, d)) {
      return false;
    }

    auto rvaofft = static_cast<std::uint32_t>(vaAddr - d.sectionBase);

    while (rvaofft < relocDir.Size) {
      std::uint32_t pageRva;
      std::uint32_t blockSize;

      if (!readDword(d.sectionData,
                     rvaofft + offsetof(reloc_block, PageRVA),
                     pageRva)) {
        return false;
      }

      if (!readDword(d.sectionData,
                     rvaofft + offsetof(reloc_block, BlockSize),
                     blockSize)) {
        return false;
      }

      // BlockSize - The total number of bytes in the base relocation block,
      // including the Page RVA and Block Size fields and the Type/Offset fields
      // that follow. Therefore we should subtract 8 bytes from BlockSize to
      // exclude the Page RVA and Block Size fields.
      std::uint32_t entryCount = (blockSize - 8) / sizeof(std::uint16_t);

      // Skip the Page RVA and Block Size fields
      rvaofft += sizeof(reloc_block);

      // Iterate over all of the block Type/Offset entries
      while (entryCount != 0) {
        std::uint16_t entry;
        std::uint8_t type;
        std::uint16_t offset;

        if (!readWord(d.sectionData, rvaofft, entry)) {
          return false;
        }

        // Mask out the type and assign
        type = entry >> 12;
        // Mask out the offset and assign
        offset = entry & ~0xf000;

        // Produce the VA of the relocation
        VA relocVA;
        if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
          relocVA = pageRva + offset + p->peHeader.nt.OptionalHeader.ImageBase;
        } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
          relocVA =
              pageRva + offset + p->peHeader.nt.OptionalHeader64.ImageBase;
        } else {
          return false;
        }

        // Store in our list
        reloc r;

        r.shiftedAddr = relocVA;
        r.type = static_cast<reloc_type>(type);
        p->internal->relocs.push_back(r);

        entryCount--;
        rvaofft += sizeof(std::uint16_t);
      }
    }
  }

  return true;
}

bool getImports(parsed_pe *p) {
  data_directory importDir;
  if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
    importDir = p->peHeader.nt.OptionalHeader.DataDirectory[DIR_IMPORT];
  } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
    importDir = p->peHeader.nt.OptionalHeader64.DataDirectory[DIR_IMPORT];
  } else {
    return false;
  }

  if (importDir.Size != 0) {
    // get section for the RVA in importDir
    section c;
    VA addr;
    if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      addr = importDir.VirtualAddress + p->peHeader.nt.OptionalHeader.ImageBase;
    } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
      addr =
          importDir.VirtualAddress + p->peHeader.nt.OptionalHeader64.ImageBase;
    } else {
      return false;
    }

    if (!getSecForVA(p->internal->secs, addr, c)) {
      return false;
    }

    // get import directory from this section
    auto offt = static_cast<std::uint32_t>(addr - c.sectionBase);

    import_dir_entry emptyEnt;
    memset(&emptyEnt, 0, sizeof(import_dir_entry));

    do {
      // read each directory entry out
      import_dir_entry curEnt = emptyEnt;

      READ_DWORD(c.sectionData, offt, curEnt, LookupTableRVA);
      READ_DWORD(c.sectionData, offt, curEnt, TimeStamp);
      READ_DWORD(c.sectionData, offt, curEnt, ForwarderChain);
      READ_DWORD(c.sectionData, offt, curEnt, NameRVA);
      READ_DWORD(c.sectionData, offt, curEnt, AddressRVA);

      // are all the fields in curEnt null? then we break
      if (curEnt.LookupTableRVA == 0 && curEnt.NameRVA == 0 &&
          curEnt.AddressRVA == 0) {
        break;
      }

      // then, try and get the name of this particular module...
      VA name;
      if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
        name = curEnt.NameRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
        name = curEnt.NameRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
      } else {
        return false;
      }

      section nameSec;
      if (!getSecForVA(p->internal->secs, name, nameSec)) {
        return false;
      }

      auto nameOff = static_cast<std::uint32_t>(name - nameSec.sectionBase);
      std::string modName;
      if (!readCString(*nameSec.sectionData, nameOff, modName)) {
        return false;
      }

      // clang-format off
      std::transform(
        modName.begin(),
        modName.end(),
        modName.begin(),

        [](char chr) -> char {
          return static_cast<char>(::toupper(chr));
        }
      );
      // clang-format on

      // then, try and get all of the sub-symbols
      VA lookupVA = 0;
      if (curEnt.LookupTableRVA != 0) {
        if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
          lookupVA =
              curEnt.LookupTableRVA + p->peHeader.nt.OptionalHeader.ImageBase;
        } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
          lookupVA =
              curEnt.LookupTableRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
        } else {
          return false;
        }
      } else if (curEnt.AddressRVA != 0) {
        if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
          lookupVA =
              curEnt.AddressRVA + p->peHeader.nt.OptionalHeader.ImageBase;
        } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
          lookupVA =
              curEnt.AddressRVA + p->peHeader.nt.OptionalHeader64.ImageBase;
        } else {
          return false;
        }
      }

      section lookupSec;
      if (lookupVA == 0 ||
          !getSecForVA(p->internal->secs, lookupVA, lookupSec)) {
        return false;
      }

      auto lookupOff =
          static_cast<std::uint32_t>(lookupVA - lookupSec.sectionBase);
      std::uint32_t offInTable = 0;
      do {
        VA valVA = 0;
        std::uint8_t ord = 0;
        std::uint16_t oval = 0;
        std::uint32_t val32 = 0;
        std::uint64_t val64 = 0;
        if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
          if (!readDword(lookupSec.sectionData, lookupOff, val32)) {
            return false;
          }
          if (val32 == 0) {
            break;
          }
          ord = (val32 >> 31);
          oval = (val32 & ~0xFFFF0000);
          valVA = val32 + p->peHeader.nt.OptionalHeader.ImageBase;
        } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
          if (!readQword(lookupSec.sectionData, lookupOff, val64)) {
            return false;
          }
          if (val64 == 0) {
            break;
          }
          ord = (val64 >> 63);
          oval = (val64 & ~0xFFFF0000);
          valVA = val64 + p->peHeader.nt.OptionalHeader64.ImageBase;
        } else {
          return false;
        }

        if (ord == 0) {
          // import by name
          std::string symName;
          section symNameSec;

          if (!getSecForVA(p->internal->secs, valVA, symNameSec)) {
            return false;
          }

          std::uint32_t nameOffset =
              static_cast<std::uint32_t>(valVA - symNameSec.sectionBase) +
              sizeof(std::uint16_t);
          do {
            std::uint8_t chr;
            if (!readByte(symNameSec.sectionData, nameOffset, chr)) {
              return false;
            }

            if (chr == 0) {
              break;
            }

            symName.push_back(static_cast<char>(chr));
            nameOffset++;
          } while (true);

          // okay now we know the pair... add it
          importent ent;

          if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
            ent.addr = offInTable + curEnt.AddressRVA +
                       p->peHeader.nt.OptionalHeader.ImageBase;
          } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
            ent.addr = offInTable + curEnt.AddressRVA +
                       p->peHeader.nt.OptionalHeader64.ImageBase;
          } else {
            return false;
          }

          ent.symbolName = symName;
          ent.moduleName = modName;
          p->internal->imports.push_back(ent);
        } else {
          std::string symName = "ORDINAL_" + modName + "_" +
                                to_string<std::uint32_t>(oval, std::dec);

          importent ent;

          if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
            ent.addr = offInTable + curEnt.AddressRVA +
                       p->peHeader.nt.OptionalHeader.ImageBase;
          } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
            ent.addr = offInTable + curEnt.AddressRVA +
                       p->peHeader.nt.OptionalHeader64.ImageBase;
          } else {
            return false;
          }

          ent.symbolName = symName;
          ent.moduleName = modName;

          p->internal->imports.push_back(ent);
        }

        if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
          lookupOff += sizeof(std::uint32_t);
          offInTable += sizeof(std::uint32_t);
        } else if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
          lookupOff += sizeof(std::uint64_t);
          offInTable += sizeof(std::uint64_t);
        } else {
          return false;
        }
      } while (true);

      offt += sizeof(import_dir_entry);
    } while (true);
  }

  return true;
}

bool getSymbolTable(parsed_pe *p) {
  if (p->peHeader.nt.FileHeader.PointerToSymbolTable == 0) {
    return true;
  }

  std::uint32_t strTableOffset =
      p->peHeader.nt.FileHeader.PointerToSymbolTable +
      (p->peHeader.nt.FileHeader.NumberOfSymbols * SYMTAB_RECORD_LEN);

  std::uint32_t offset = p->peHeader.nt.FileHeader.PointerToSymbolTable;

  for (std::uint32_t i = 0; i < p->peHeader.nt.FileHeader.NumberOfSymbols;
       i++) {
    symbol sym;

    // Read name
    if (!readQword(p->fileBuffer, offset, sym.name.data)) {
      PE_ERR(PEERR_MAGIC);
      return false;
    }

    if (sym.name.zeroes == 0) {
      // The symbol name is greater than 8 bytes so it is stored in the string
      // table. In this case instead of name, an offset of the string in the
      // string table is provided.

      uint32_t strOffset = strTableOffset + SYMBOL_NAME_OFFSET(sym.name);
      uint8_t ch;
      for (;;) {
        if (!readByte(p->fileBuffer, strOffset, ch)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }
        if (ch == 0u) {
          break;
        }
        sym.strName.push_back(static_cast<char>(ch));
        strOffset += sizeof(std::uint8_t);
      }
    } else {
      for (std::uint8_t n = 0;
           n < NT_SHORT_NAME_LEN && sym.name.shortName[n] != 0;
           n++) {
        sym.strName.push_back(static_cast<char>(sym.name.shortName[n]));
      }
    }

    offset += sizeof(std::uint64_t);

    // Read value
    if (!readDword(p->fileBuffer, offset, sym.value)) {
      PE_ERR(PEERR_MAGIC);
      return false;
    }

    offset += sizeof(std::uint32_t);

    // Read section number
    uint16_t secNum;
    if (!readWord(p->fileBuffer, offset, secNum)) {
      PE_ERR(PEERR_MAGIC);
      return false;
    }
    sym.sectionNumber = static_cast<std::int16_t>(secNum);

    offset += sizeof(std::uint16_t);

    // Read type
    if (!readWord(p->fileBuffer, offset, sym.type)) {
      PE_ERR(PEERR_MAGIC);
      return false;
    }

    offset += sizeof(std::uint16_t);

    // Read storage class
    if (!readByte(p->fileBuffer, offset, sym.storageClass)) {
      PE_ERR(PEERR_MAGIC);
      return false;
    }

    offset += sizeof(std::uint8_t);

    // Read number of auxiliary symbols
    if (!readByte(p->fileBuffer, offset, sym.numberOfAuxSymbols)) {
      PE_ERR(PEERR_MAGIC);
      return false;
    }

    // Set offset to next symbol
    offset += sizeof(std::uint8_t);

    // Save the symbol
    p->internal->symbols.push_back(sym);

    if (sym.numberOfAuxSymbols == 0) {
      continue;
    }

    // Read auxiliary symbol records
    auto nextSymbolOffset =
        offset + (static_cast<std::uint32_t>(sym.numberOfAuxSymbols) *
                  static_cast<std::uint32_t>(SYMTAB_RECORD_LEN));

    i += sym.numberOfAuxSymbols;

    if (sym.storageClass == IMAGE_SYM_CLASS_EXTERNAL &&
        SYMBOL_TYPE_HI(sym) == 0x20 && sym.sectionNumber > 0) {
      // Auxiliary Format 1: Function Definitions

      for (std::uint8_t n = 0; n < sym.numberOfAuxSymbols; n++) {
        aux_symbol_f1 asym;

        // Read tag index
        if (!readDword(p->fileBuffer, offset, asym.tagIndex)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint32_t);

        // Read total size
        if (!readDword(p->fileBuffer, offset, asym.totalSize)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint32_t);

        // Read pointer to line number
        if (!readDword(p->fileBuffer, offset, asym.pointerToLineNumber)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint32_t);

        // Read pointer to next function
        if (!readDword(p->fileBuffer, offset, asym.pointerToNextFunction)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        // Skip the processed 4 bytes + unused 2 bytes
        offset += sizeof(std::uint8_t) * 6;

        // Save the record
        sym.aux_symbols_f1.push_back(asym);
      }

    } else if (sym.storageClass == IMAGE_SYM_CLASS_FUNCTION) {
      // Auxiliary Format 2: .bf and .ef Symbols

      for (std::uint8_t n = 0; n < sym.numberOfAuxSymbols; n++) {
        aux_symbol_f2 asym;
        // Skip unused 4 bytes
        offset += sizeof(std::uint32_t);

        // Read line number
        if (!readWord(p->fileBuffer, offset, asym.lineNumber)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint16_t);

        // Skip unused 6 bytes
        offset += sizeof(std::uint8_t) * 6;

        // Read pointer to next function
        if (!readDword(p->fileBuffer, offset, asym.pointerToNextFunction)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        // Skip the processed 4 bytes + unused 2 bytes
        offset += sizeof(std::uint8_t) * 6;

        // Save the record
        sym.aux_symbols_f2.push_back(asym);
      }

    } else if (sym.storageClass == IMAGE_SYM_CLASS_EXTERNAL &&
               sym.sectionNumber == IMAGE_SYM_UNDEFINED && sym.value == 0) {
      // Auxiliary Format 3: Weak Externals

      for (std::uint8_t n = 0; n < sym.numberOfAuxSymbols; n++) {
        aux_symbol_f3 asym;

        // Read line number
        if (!readDword(p->fileBuffer, offset, asym.tagIndex)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        // Read characteristics
        if (!readDword(p->fileBuffer, offset, asym.characteristics)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        // Skip unused 10 bytes
        offset += sizeof(std::uint8_t) * 10;

        // Save the record
        sym.aux_symbols_f3.push_back(asym);
      }

    } else if (sym.storageClass == IMAGE_SYM_CLASS_FILE) {
      // Auxiliary Format 4: Files

      for (std::uint8_t n = 0; n < sym.numberOfAuxSymbols; n++) {
        aux_symbol_f4 asym;

        // Read filename
        bool terminatorFound = false;

        for (std::uint16_t j = 0; j < SYMTAB_RECORD_LEN; j++) {
          // Save the raw field
          if (!readByte(p->fileBuffer, offset, asym.filename[j])) {
            PE_ERR(PEERR_MAGIC);
            return false;
          }

          offset += sizeof(std::uint8_t);

          if (asym.filename[j] == 0) {
            terminatorFound = true;
          }

          if (!terminatorFound) {
            asym.strFilename.push_back(static_cast<char>(asym.filename[j]));
          }
        }

        // Save the record
        sym.aux_symbols_f4.push_back(asym);
      }

    } else if (sym.storageClass == IMAGE_SYM_CLASS_STATIC) {
      // Auxiliary Format 5: Section Definitions

      for (std::uint8_t n = 0; n < sym.numberOfAuxSymbols; n++) {
        aux_symbol_f5 asym;

        // Read length
        if (!readDword(p->fileBuffer, offset, asym.length)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint32_t);

        // Read number of relocations
        if (!readWord(p->fileBuffer, offset, asym.numberOfRelocations)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint16_t);

        // Read number of line numbers
        if (!readWord(p->fileBuffer, offset, asym.numberOfLineNumbers)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint16_t);

        // Read checksum
        if (!readDword(p->fileBuffer, offset, asym.checkSum)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint32_t);

        // Read number
        if (!readWord(p->fileBuffer, offset, asym.number)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint16_t);

        // Read selection
        if (!readByte(p->fileBuffer, offset, asym.selection)) {
          PE_ERR(PEERR_MAGIC);
          return false;
        }

        offset += sizeof(std::uint8_t);

        // Skip unused 3 bytes
        offset += sizeof(std::uint8_t) * 3;

        // Save the record
        sym.aux_symbols_f5.push_back(asym);
      }

    } else {
#ifdef PEPARSE_LIBRARY_WARNINGS
      std::ios::fmtflags originalStreamFlags(std::cerr.flags());

      auto storageClassName = GetSymbolTableStorageClassName(sym.storageClass);
      if (storageClassName == nullptr) {
        std::cerr << "Warning: Skipping auxiliary symbol of type 0x" << std::hex
                  << static_cast<std::uint32_t>(sym.storageClass)
                  << " at offset 0x" << std::hex << offset << "\n";
      } else {

        std::cerr << "Warning: Skipping auxiliary symbol of type "
                  << storageClassName << " at offset 0x" << std::hex << offset
                  << "\n";
      }

      std::cerr.flags(originalStreamFlags);
#endif
      offset = nextSymbolOffset;
    }

    if (offset != nextSymbolOffset) {
#ifdef PEPARSE_LIBRARY_WARNINGS
      std::ios::fmtflags originalStreamFlags(std::cerr.flags());

      std::cerr << "Warning: Invalid internal offset (current: 0x" << std::hex
                << offset << ", expected: 0x" << std::hex << nextSymbolOffset
                << ")\n";

      std::cerr.flags(originalStreamFlags);
#endif
      offset = nextSymbolOffset;
    }
  }

  return true;
}

parsed_pe *ParsePEFromBuffer(bounded_buffer *buffer) {
  // First, create a new parsed_pe structure
  // We pass std::nothrow parameter to new so in case of failure it returns
  // nullptr instead of throwing exception std::bad_alloc.
  parsed_pe *p = new (std::nothrow) parsed_pe();

  if (p == nullptr) {
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  // Make a new buffer object to hold just our file data
  p->fileBuffer = buffer;

  p->internal = new (std::nothrow) parsed_pe_internal();

  if (p->internal == nullptr) {
    deleteBuffer(p->fileBuffer);
    delete p;
    PE_ERR(PEERR_MEM);
    return nullptr;
  }

  // get header information
  bounded_buffer *remaining = nullptr;
  if (!getHeader(p->fileBuffer, p->peHeader, remaining)) {
    deleteBuffer(remaining);
    DestructParsedPE(p);
    // err is set by getHeader
    return nullptr;
  }

  bounded_buffer *file = p->fileBuffer;
  if (!getSections(remaining, file, p->peHeader.nt, p->internal->secs)) {
    deleteBuffer(remaining);
    DestructParsedPE(p);
    PE_ERR(PEERR_SECT);
    return nullptr;
  }

  if (!getResources(remaining, file, p->internal->secs, p->internal->rsrcs)) {
    deleteBuffer(remaining);
    DestructParsedPE(p);
    PE_ERR(PEERR_RESC);
    return nullptr;
  }

  // Get exports
  if (!getExports(p)) {
    deleteBuffer(remaining);
    DestructParsedPE(p);
    PE_ERR(PEERR_MAGIC);
    return nullptr;
  }

  // Get relocations, if exist
  if (!getRelocations(p)) {
    deleteBuffer(remaining);
    DestructParsedPE(p);
    PE_ERR(PEERR_MAGIC);
    return nullptr;
  }

  // Get imports
  if (!getImports(p)) {
    deleteBuffer(remaining);
    DestructParsedPE(p);
    return nullptr;
  }

  // Get symbol table
  if (!getSymbolTable(p)) {
    deleteBuffer(remaining);
    DestructParsedPE(p);
    return nullptr;
  }

  deleteBuffer(remaining);

  return p;
}

parsed_pe *ParsePEFromFile(const char *filePath) {
  auto buffer = readFileToFileBuffer(filePath);

  if (buffer == nullptr) {
    // err is set by readFileToFileBuffer
    return nullptr;
  }

  return ParsePEFromBuffer(buffer);
}

parsed_pe *ParsePEFromPointer(std::uint8_t *ptr, std::uint32_t sz) {
  auto buffer = makeBufferFromPointer(ptr, sz);

  if (buffer == nullptr) {
    // err is set by makeBufferFromPointer
    return nullptr;
  }

  return ParsePEFromBuffer(buffer);
}

void DestructParsedPE(parsed_pe *p) {
  if (p == nullptr) {
    return;
  }

  deleteBuffer(p->fileBuffer);

  for (section s : p->internal->secs) {
    if (s.sectionData != nullptr) {
      deleteBuffer(s.sectionData);
    }
  }
  for (resource r : p->internal->rsrcs) {
    if (r.buf != nullptr) {
      deleteBuffer(r.buf);
    }
  }

  delete p->internal;
  delete p;
  return;
}

// iterate over the imports by VA and string
void IterImpVAString(parsed_pe *pe, iterVAStr cb, void *cbd) {
  std::vector<importent> &l = pe->internal->imports;

  for (importent &i : l) {
    if (cb(cbd, i.addr, i.moduleName, i.symbolName) != 0) {
      break;
    }
  }

  return;
}

// iterate over relocations in the PE file
void IterRelocs(parsed_pe *pe, iterReloc cb, void *cbd) {
  std::vector<reloc> &l = pe->internal->relocs;

  for (reloc &r : l) {
    if (cb(cbd, r.shiftedAddr, r.type) != 0) {
      break;
    }
  }

  return;
}

// Iterate over symbols (symbol table) in the PE file
void IterSymbols(parsed_pe *pe, iterSymbol cb, void *cbd) {
  std::vector<symbol> &l = pe->internal->symbols;

  for (symbol &s : l) {
    if (cb(cbd,
           s.strName,
           s.value,
           s.sectionNumber,
           s.type,
           s.storageClass,
           s.numberOfAuxSymbols) != 0) {
      break;
    }
  }

  return;
}

// iterate over the exports by VA
void IterExpVA(parsed_pe *pe, iterExp cb, void *cbd) {
  std::vector<exportent> &l = pe->internal->exports;

  for (exportent &i : l) {
    if (cb(cbd, i.addr, i.moduleName, i.symbolName) != 0) {
      break;
    }
  }

  return;
}

// iterate over sections
void IterSec(parsed_pe *pe, iterSec cb, void *cbd) {
  parsed_pe_internal *pint = pe->internal;

  for (section &s : pint->secs) {
    if (cb(cbd, s.sectionBase, s.sectionName, s.sec, s.sectionData) != 0) {
      break;
    }
  }

  return;
}

bool ReadByteAtVA(parsed_pe *pe, VA v, std::uint8_t &b) {
  // find this VA in a section
  section s;

  if (!getSecForVA(pe->internal->secs, v, s)) {
    PE_ERR(PEERR_SECTVA);
    return false;
  }

  auto off = static_cast<std::uint32_t>(v - s.sectionBase);
  return readByte(s.sectionData, off, b);
}

bool GetEntryPoint(parsed_pe *pe, VA &v) {

  if (pe != nullptr) {
    nt_header_32 *nthdr = &pe->peHeader.nt;

    if (nthdr->OptionalMagic == NT_OPTIONAL_32_MAGIC) {
      v = nthdr->OptionalHeader.AddressOfEntryPoint +
          nthdr->OptionalHeader.ImageBase;
    } else if (nthdr->OptionalMagic == NT_OPTIONAL_64_MAGIC) {
      v = nthdr->OptionalHeader64.AddressOfEntryPoint +
          nthdr->OptionalHeader64.ImageBase;
    } else {
      PE_ERR(PEERR_MAGIC);
      return false;
    }

    return true;
  }

  return false;
}

const char *GetMachineAsString(parsed_pe *pe) {
  if (pe == nullptr)
    return nullptr;

  switch (pe->peHeader.nt.FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_I386:
      return "x86";
    case IMAGE_FILE_MACHINE_ARMNT:
      return "ARM Thumb-2 Little-Endian";
    case IMAGE_FILE_MACHINE_IA64:
      return "Intel IA64";
    case IMAGE_FILE_MACHINE_AMD64:
      return "x64";
    case IMAGE_FILE_MACHINE_ARM64:
      return "ARM64";
    case IMAGE_FILE_MACHINE_CEE:
      return "CLR Pure MSIL";
    default:
      return nullptr;
  }
}

const char *GetSubsystemAsString(parsed_pe *pe) {
  if (pe == nullptr)
    return nullptr;

  std::uint16_t subsystem;
  if (pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC)
    subsystem = pe->peHeader.nt.OptionalHeader.Subsystem;
  else if (pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC)
    subsystem = pe->peHeader.nt.OptionalHeader64.Subsystem;
  else
    return nullptr;

  switch (subsystem) {
    case IMAGE_SUBSYSTEM_UNKNOWN:
      return "UNKNOWN";
    case IMAGE_SUBSYSTEM_NATIVE:
      return "NATIVE";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
      return "WINDOWS_GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
      return "WINDOWS_CUI";
    case IMAGE_SUBSYSTEM_OS2_CUI:
      return "OS2_CUI";
    case IMAGE_SUBSYSTEM_POSIX_CUI:
      return "POSIX_CUI";
    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
      return "NATIVE_WINDOWS";
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
      return "WINDOWS_CE_GUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
      return "EFI_APPLICATION";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
      return "EFI_BOOT_SERVICE_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
      return "EFI_RUNTIME_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_ROM:
      return "EFI_ROM";
    case IMAGE_SUBSYSTEM_XBOX:
      return "XBOX";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
      return "WINDOWS_BOOT_APPLICATION";
    case IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG:
      return "XBOX_CODE_CATALOG";
    default:
      return nullptr;
  }
}

bool GetDataDirectoryEntry(parsed_pe *pe,
                           data_directory_kind dirnum,
                           std::vector<std::uint8_t> &raw_entry) {
  raw_entry.clear();

  if (pe == nullptr) {
    PE_ERR(PEERR_NONE);
    return false;
  }

  data_directory dir;
  VA addr;
  if (pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
    dir = pe->peHeader.nt.OptionalHeader.DataDirectory[dirnum];
    addr = dir.VirtualAddress + pe->peHeader.nt.OptionalHeader.ImageBase;
  } else if (pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_64_MAGIC) {
    dir = pe->peHeader.nt.OptionalHeader64.DataDirectory[dirnum];
    addr = dir.VirtualAddress + pe->peHeader.nt.OptionalHeader64.ImageBase;
  } else {
    PE_ERR(PEERR_MAGIC);
    return false;
  }

  if (dir.Size <= 0) {
    PE_ERR(PEERR_SIZE);
    return false;
  }

  /* NOTE(ww): DIR_SECURITY is an annoying special case: its contents
   * are never mapped into memory, so its "RVA" is actually a direct
   * file offset.
   * See:
   * https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
   */
  if (dirnum == DIR_SECURITY) {
    auto *buf = splitBuffer(
        pe->fileBuffer, dir.VirtualAddress, dir.VirtualAddress + dir.Size);
    if (buf == nullptr) {
      PE_ERR(PEERR_SIZE);
      return false;
    }

    raw_entry.assign(buf->buf, buf->buf + buf->bufLen);
    deleteBuffer(buf);
  } else {
    section sec;
    if (!getSecForVA(pe->internal->secs, addr, sec)) {
      PE_ERR(PEERR_SECTVA);
      return false;
    }

    auto off = static_cast<std::uint32_t>(addr - sec.sectionBase);
    if (off + dir.Size >= sec.sectionData->bufLen) {
      PE_ERR(PEERR_SIZE);
      return false;
    }

    raw_entry.assign(sec.sectionData->buf + off,
                     sec.sectionData->buf + off + dir.Size);
  }

  return true;
}

} // namespace peparse
