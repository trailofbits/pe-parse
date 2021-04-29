#include <pe-parse/parse.h>

#include <catch2/catch.hpp>

#include "filesystem_compat.h"

namespace peparse {
TEST_CASE("malformed PE (GH#153) does not parse", "[pr_153]") {
  auto path = fs::path(ASSETS_DIR) / "pr_153.exe";
  auto *p = ParsePEFromFile(path.string().c_str());

  // pr_153.exe should not parse, and should return an error indicating
  // that the magic was invalid (masking the underlying PEERR_ADDRESS error).
  REQUIRE(p == nullptr);
  REQUIRE(GetPEErr() == PEERR_MAGIC);
}
} // namespace peparse
