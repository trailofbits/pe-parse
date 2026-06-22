#include <pe-parse/parse.h>

#include <catch2/catch.hpp>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include "filesystem_compat.h"

// Whether the corkami testset has been downloaded
// Path to corkami PEs
#if defined(CORKAMI_PE_PATH)

// Return a vector of all PE files immediately under `dir`
static std::vector<fs::path> PEFilesInDir(const fs::path &dir) {
  std::vector<fs::path> all_entries;
  if (!fs::exists(dir)) {
    return all_entries;
  }

  for (const auto &entry : fs::directory_iterator(dir)) {
    if ((entry.path().extension() == ".exe" ||
         entry.path().extension() == ".dll" ||
         entry.path().extension() == ".sys") &&
        fs::is_regular_file(entry)) {
      all_entries.emplace_back(entry.path());
    }
  }
  return all_entries;
}

namespace peparse {

struct ExportInfo {
  VA addr;
  std::uint16_t ordinal;
  std::string symbolName;
  std::string forwardName;
};

static int captureExport(void *ctx,
                         const VA &addr,
                         std::uint16_t ordinal,
                         const std::string &,
                         const std::string &symbolName,
                         const std::string &forwardName) {
  auto *exports = static_cast<std::vector<ExportInfo> *>(ctx);
  exports->push_back({addr, ordinal, symbolName, forwardName});
  return 0;
}

static const std::unordered_set<std::string> kKnownPEFailure{
    "virtsectblXP.exe", "maxsec_lowaligW7.exe",
    "maxsecXP.exe",     "nullSOH-XP.exe",
    "tinyXP.exe",       "tinydllXP.dll",
    "virtrelocXP.exe",  "foldedhdrW7.exe",
    "maxvals.exe",      "d_nonnull.dll",
    "reloccrypt.exe",   "d_resource.dll",
    "fakerelocs.exe",   "lfanew_relocW7.exe",
    "bigSoRD.exe",      "tinyW7.exe",
    "reloccryptW8.exe", "standard.exe",
    "exe2pe.exe",       "tinygui.exe",
    "dllfwloop.dll",    "tinydrivXP.sys",
    "tiny.exe",         "tinydll.dll",
    "foldedhdr.exe",    "dllmaxvals.dll",
    "reloccryptXP.exe", "dosZMXP.exe",
    "tinyW7_3264.exe",  "dllfw.dll",
    "hdrcode.exe",      "ibrelocW7.exe",
    "d_tiny.dll",       "sc.exe"};

TEST_CASE("Corkami PEs smoketest", "[corkami]") {
  for (fs::path path : PEFilesInDir(CORKAMI_PE_PATH)) {
    std::string pe_name = path.filename().string();
    SECTION(pe_name) {
      parsed_pe *p = ParsePEFromFile(path.string().c_str());

      if (kKnownPEFailure.count(pe_name)) {
        CHECKED_ELSE(!p) {
          FAIL("Previously failing test now passes! Remove from set");
        }
      } else {
        CHECKED_ELSE(p) {
          FAIL(GetPEErrString() + " at " + GetPEErrLoc());
        }
        DestructParsedPE(p);
      }
    }
  }
}

TEST_CASE("Corkami ordinal-only export is reported", "[corkami][exports]") {
  fs::path path = fs::path(CORKAMI_PE_PATH) / "dllemptyexp.dll";
  REQUIRE(fs::exists(path));

  parsed_pe *p = ParsePEFromFile(path.string().c_str());
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<ExportInfo> exports;
  IterExpFull(p, captureExport, &exports);
  DestructParsedPE(p);

  REQUIRE(exports.size() == 1);
  REQUIRE(exports[0].addr == 0x1001008);
  REQUIRE(exports[0].ordinal == 0);
  REQUIRE(exports[0].symbolName.empty());
  REQUIRE(exports[0].forwardName.empty());
}

} // namespace peparse
#endif
