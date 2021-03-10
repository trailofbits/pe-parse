#include <pe-parse/parse.h>

#include <catch2/catch.hpp>

#include "filesystem_compat.h"

namespace peparse {

TEST_CASE("Simple testing of PE", "[example]") {
  fs::path path = fs::path(ASSETS_DIR) / "example.exe";
  parsed_pe *p = ParsePEFromFile(path.string().c_str());

  REQUIRE(p);

  SECTION("dos header correctness") {
    auto dos = p->peHeader.dos;
    REQUIRE(dos.e_magic == 0x5a4d);
    REQUIRE(dos.e_cp == 0x3);
    REQUIRE(dos.e_crlc == 0x0);
    REQUIRE(dos.e_cparhdr == 0x4);
    REQUIRE(dos.e_minalloc == 0x0);
    REQUIRE(dos.e_maxalloc == 0xffff);
    REQUIRE(dos.e_ss == 0x0);
    REQUIRE(dos.e_sp == 0xb8);
    REQUIRE(dos.e_csum == 0x0);
    REQUIRE(dos.e_ip == 0x0);
    REQUIRE(dos.e_cs == 0x0);
    REQUIRE(dos.e_lfarlc == 0x40);
    REQUIRE(dos.e_ovno == 0x0);
    REQUIRE(dos.e_res[0] == 0x0);
    REQUIRE(dos.e_res[1] == 0x0);
    REQUIRE(dos.e_res[2] == 0x0);
    REQUIRE(dos.e_res[3] == 0x0);
    REQUIRE(dos.e_oemid == 0x0);
    REQUIRE(dos.e_oeminfo == 0x0);
    REQUIRE(dos.e_res2[0] == 0x0);
    REQUIRE(dos.e_res2[1] == 0x0);
    REQUIRE(dos.e_res2[2] == 0x0);
    REQUIRE(dos.e_res2[3] == 0x0);
    REQUIRE(dos.e_res2[4] == 0x0);
    REQUIRE(dos.e_res2[5] == 0x0);
    REQUIRE(dos.e_res2[6] == 0x0);
    REQUIRE(dos.e_res2[7] == 0x0);
    REQUIRE(dos.e_res2[8] == 0x0);
    REQUIRE(dos.e_res2[9] == 0x0);
    REQUIRE(dos.e_lfanew == 0xf8);
  }

  DestructParsedPE(p);
}

} // namespace peparse
