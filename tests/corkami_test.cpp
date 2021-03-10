#include <pe-parse/parse.h>

#include <catch2/catch.hpp>
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

} // namespace peparse
#endif
