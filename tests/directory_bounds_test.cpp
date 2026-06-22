#include <pe-parse/parse.h>

#include <array>
#include <catch2/catch.hpp>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace peparse {
namespace {

constexpr std::uint32_t kNtHeaderOffset = 0x80;
constexpr std::uint32_t kSectionRva = 0x2000;
constexpr std::uint32_t kSectionRawOffset = 0x200;
constexpr std::uint32_t kSectionRawSize = 0x1200;
constexpr std::uint32_t kDebugDirectoryRva = 0x2f50;
constexpr std::uint32_t kDebugDataRva = 0x2fa4;
constexpr std::size_t kFileSize = kSectionRawOffset + kSectionRawSize;

using TestPe = std::array<std::uint8_t, kFileSize>;
using ParsedPePtr = std::unique_ptr<parsed_pe, void (*)(parsed_pe *)>;

struct ExportInfo {
  VA addr;
  std::uint16_t ordinal;
  std::string symbolName;
  std::string forwardName;
};

template <typename T>
void put16(T &buffer, std::size_t offset, std::uint16_t value) {
  buffer[offset] = static_cast<std::uint8_t>(value);
  buffer[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

template <typename T>
void put32(T &buffer, std::size_t offset, std::uint32_t value) {
  buffer[offset] = static_cast<std::uint8_t>(value);
  buffer[offset + 1] = static_cast<std::uint8_t>(value >> 8);
  buffer[offset + 2] = static_cast<std::uint8_t>(value >> 16);
  buffer[offset + 3] = static_cast<std::uint8_t>(value >> 24);
}

template <typename T>
void putCString(T &buffer, std::size_t offset, const char *value) {
  while (*value != '\0') {
    buffer[offset++] = static_cast<std::uint8_t>(*value++);
  }
  buffer[offset] = 0;
}

constexpr std::size_t optionalHeaderOffset() {
  return kNtHeaderOffset + sizeof(std::uint32_t) + sizeof(file_header);
}

constexpr std::size_t sectionHeaderOffset() {
  return optionalHeaderOffset() + sizeof(optional_header_32);
}

constexpr std::size_t dataDirectoryOffset(data_directory_kind kind) {
  return optionalHeaderOffset() + offsetof(optional_header_32, DataDirectory) +
         (static_cast<std::size_t>(kind) * sizeof(data_directory));
}

void putDataDirectory(TestPe &pe,
                      data_directory_kind kind,
                      std::uint32_t virtualAddress,
                      std::uint32_t size) {
  const auto offset = dataDirectoryOffset(kind);
  put32(pe, offset + offsetof(data_directory, VirtualAddress), virtualAddress);
  put32(pe, offset + offsetof(data_directory, Size), size);
}

std::uint32_t sectionEndRva() {
  return kSectionRva + kSectionRawSize;
}

std::size_t sectionOffset(std::uint32_t rva) {
  return kSectionRawOffset + (rva - kSectionRva);
}

std::size_t sectionOffset(std::uint32_t sectionRva, std::uint32_t rva) {
  return kSectionRawOffset + (rva - sectionRva);
}

std::uint32_t sectionRvaAt(std::uint32_t sectionRva, std::uint32_t offset) {
  return sectionRva + offset;
}

std::size_t debugEntryOffset() {
  return sectionOffset(kDebugDirectoryRva);
}

void putSectionRawRange(TestPe &pe,
                        std::uint32_t rawOffset,
                        std::uint32_t rawSize) {
  constexpr auto kSectionHeaderOffset = sectionHeaderOffset();
  put32(pe,
        kSectionHeaderOffset + offsetof(image_section_header, SizeOfRawData),
        rawSize);
  put32(pe,
        kSectionHeaderOffset + offsetof(image_section_header, PointerToRawData),
        rawOffset);
}

void putDebugEntry(TestPe &pe,
                   std::uint32_t sizeOfData,
                   std::uint32_t addressOfRawData) {
  put32(pe,
        debugEntryOffset() + offsetof(debug_dir_entry, SizeOfData),
        sizeOfData);
  put32(pe,
        debugEntryOffset() + offsetof(debug_dir_entry, AddressOfRawData),
        addressOfRawData);
}

void putExportDirectoryDword(TestPe &pe,
                             std::uint32_t exportSectionRva,
                             std::size_t fieldOffset,
                             std::uint32_t value) {
  put32(pe,
        sectionOffset(exportSectionRva, exportSectionRva) + fieldOffset,
        value);
}

void putExportDword(TestPe &pe,
                    std::uint32_t exportSectionRva,
                    std::uint32_t rva,
                    std::uint32_t value) {
  put32(pe, sectionOffset(exportSectionRva, rva), value);
}

void putExportWord(TestPe &pe,
                   std::uint32_t exportSectionRva,
                   std::uint32_t rva,
                   std::uint16_t value) {
  put16(pe, sectionOffset(exportSectionRva, rva), value);
}

void putExportCString(TestPe &pe,
                      std::uint32_t exportSectionRva,
                      std::uint32_t rva,
                      const char *value) {
  putCString(pe, sectionOffset(exportSectionRva, rva), value);
}

TestPe makeMinimalPe(std::uint32_t sectionRva = kSectionRva,
                     std::uint32_t sectionRawSize = kSectionRawSize) {
  TestPe pe{};

  put16(pe, offsetof(dos_header, e_magic), MZ_MAGIC);
  put32(pe, offsetof(dos_header, e_lfanew), kNtHeaderOffset);
  put32(pe, kNtHeaderOffset, NT_MAGIC);

  constexpr auto kFileHeaderOffset =
      kNtHeaderOffset + offsetof(nt_header_32, FileHeader);
  put16(pe,
        kFileHeaderOffset + offsetof(file_header, Machine),
        IMAGE_FILE_MACHINE_I386);
  put16(pe, kFileHeaderOffset + offsetof(file_header, NumberOfSections), 1);

  put16(pe,
        optionalHeaderOffset() + offsetof(optional_header_32, Magic),
        NT_OPTIONAL_32_MAGIC);
  put32(pe,
        optionalHeaderOffset() +
            offsetof(optional_header_32, NumberOfRvaAndSizes),
        NUM_DIR_ENTRIES);

  constexpr auto kSectionHeaderOffset = sectionHeaderOffset();
  put32(pe,
        kSectionHeaderOffset + offsetof(image_section_header, Misc.VirtualSize),
        sectionRawSize);
  put32(pe,
        kSectionHeaderOffset + offsetof(image_section_header, VirtualAddress),
        sectionRva);
  putSectionRawRange(pe, kSectionRawOffset, sectionRawSize);

  return pe;
}

ParsedPePtr parse(TestPe &pe) {
  return ParsedPePtr(
      ParsePEFromPointer(pe.data(), static_cast<std::uint32_t>(pe.size())),
      DestructParsedPE);
}

int countDebugDirectory(void *ctx,
                        const std::uint32_t &,
                        const bounded_buffer *) {
  auto *count = static_cast<std::size_t *>(ctx);
  ++(*count);
  return 0;
}

int captureDebugDataSize(void *ctx,
                         const std::uint32_t &,
                         const bounded_buffer *data) {
  auto *sizes = static_cast<std::vector<std::uint32_t> *>(ctx);
  sizes->push_back(data->bufLen);
  return 0;
}

int captureExport(void *ctx,
                  const VA &addr,
                  std::uint16_t ordinal,
                  const std::string &,
                  const std::string &symbolName,
                  const std::string &forwardName) {
  auto *exports = static_cast<std::vector<ExportInfo> *>(ctx);
  exports->push_back({addr, ordinal, symbolName, forwardName});
  return 0;
}

} // namespace

TEST_CASE("splitBufferByLength enforces exact range boundaries", "[buffer]") {
  std::array<std::uint8_t, 8> bytes{{0, 1, 2, 3, 4, 5, 6, 7}};
  auto *buffer = makeBufferFromPointer(
      bytes.data(), static_cast<std::uint32_t>(bytes.size()));
  REQUIRE(buffer != nullptr);
  buffer->swapBytes = true;

  auto *slice = splitBufferByLength(buffer, 4, 4);
  REQUIRE(slice != nullptr);
  REQUIRE(slice->buf == bytes.data() + 4);
  REQUIRE(slice->bufLen == 4);
  REQUIRE(slice->copy);
  REQUIRE(slice->swapBytes);
  REQUIRE(slice->detail == nullptr);
  deleteBuffer(slice);

  auto *empty =
      splitBufferByLength(buffer, static_cast<std::uint32_t>(bytes.size()), 0);
  REQUIRE(empty != nullptr);
  REQUIRE(empty->buf == bytes.data() + bytes.size());
  REQUIRE(empty->bufLen == 0);
  REQUIRE(empty->copy);
  REQUIRE(empty->swapBytes);
  REQUIRE(empty->detail == nullptr);
  deleteBuffer(empty);

  REQUIRE(splitBufferByLength(buffer, 5, 4) == nullptr);
  REQUIRE(splitBufferByLength(
              buffer, 4, std::numeric_limits<std::uint32_t>::max()) == nullptr);

  auto *legacySlice = splitBuffer(buffer, 2, 6);
  REQUIRE(legacySlice != nullptr);
  REQUIRE(legacySlice->buf == bytes.data() + 2);
  REQUIRE(legacySlice->bufLen == 4);
  REQUIRE(legacySlice->copy);
  REQUIRE(legacySlice->swapBytes);
  REQUIRE(legacySlice->detail == nullptr);
  deleteBuffer(legacySlice);

  REQUIRE(splitBuffer(buffer, 6, 2) == nullptr);
  deleteBuffer(buffer);
}

TEST_CASE("oversized section raw data range is rejected", "[sections]") {
  auto pe = makeMinimalPe();
  putSectionRawRange(pe, static_cast<std::uint32_t>(kFileSize - 4), 5);

  auto p = parse(pe);

  REQUIRE_FALSE(p);
  REQUIRE(GetPEErr() == PEERR_SECT);
}

TEST_CASE("debug directory data can end at section boundary", "[debug]") {
  auto pe = makeMinimalPe();
  putDataDirectory(pe, DIR_DEBUG, kDebugDirectoryRva, sizeof(debug_dir_entry));
  putDebugEntry(pe, 4, sectionEndRva() - 4);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<std::uint32_t> sizes;
  IterDebugs(p.get(), captureDebugDataSize, &sizes);
  REQUIRE(sizes == std::vector<std::uint32_t>{4});
}

TEST_CASE("oversized debug directory data range is skipped", "[debug]") {
  auto pe = makeMinimalPe();
  putDataDirectory(pe, DIR_DEBUG, kDebugDirectoryRva, sizeof(debug_dir_entry));
  putDebugEntry(pe, 5, sectionEndRva() - 4);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::size_t debugDirectoryCount = 0;
  IterDebugs(p.get(), countDebugDirectory, &debugDirectoryCount);
  REQUIRE(debugDirectoryCount == 0);
}

TEST_CASE("overflowing debug directory data range is skipped", "[debug]") {
  auto pe = makeMinimalPe();
  putDataDirectory(pe, DIR_DEBUG, kDebugDirectoryRva, sizeof(debug_dir_entry));
  putDebugEntry(pe, std::numeric_limits<std::uint32_t>::max(), kDebugDataRva);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::size_t debugDirectoryCount = 0;
  IterDebugs(p.get(), countDebugDirectory, &debugDirectoryCount);
  REQUIRE(debugDirectoryCount == 0);
}

TEST_CASE("data directory entry can end at section boundary",
          "[data_directory]") {
  auto pe = makeMinimalPe();
  putDataDirectory(pe, DIR_LOAD_CONFIG, sectionEndRva() - 4, 4);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<std::uint8_t> rawEntry;
  REQUIRE(GetDataDirectoryEntry(p.get(), DIR_LOAD_CONFIG, rawEntry));
  REQUIRE(rawEntry.size() == 4);
}

TEST_CASE("oversized data directory entry is rejected", "[data_directory]") {
  auto pe = makeMinimalPe();
  putDataDirectory(pe, DIR_LOAD_CONFIG, sectionEndRva() - 4, 5);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<std::uint8_t> rawEntry;
  REQUIRE_FALSE(GetDataDirectoryEntry(p.get(), DIR_LOAD_CONFIG, rawEntry));
  REQUIRE(GetPEErr() == PEERR_SIZE);
  REQUIRE(rawEntry.empty());
}

TEST_CASE("overflowing export directory range can contain forwarded exports",
          "[exports]") {
  constexpr std::uint32_t kExportSectionRva = 0xffffff00;
  constexpr std::uint32_t kExportDirectorySize = 0x200;

  auto pe = makeMinimalPe(kExportSectionRva, kExportDirectorySize);
  putDataDirectory(pe, DIR_EXPORT, kExportSectionRva, kExportDirectorySize);

  constexpr std::uint32_t kAddressTableOffset = 0x40;
  constexpr std::uint32_t kNamePointerOffset = 0x50;
  constexpr std::uint32_t kOrdinalTableOffset = 0x60;
  constexpr std::uint32_t kExportNameOffset = 0x70;
  constexpr std::uint32_t kModuleNameOffset = 0x80;
  constexpr std::uint32_t kForwardNameOffset = 0x90;

  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NameRVA),
                          sectionRvaAt(kExportSectionRva, kModuleNameOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NumberOfNamePointers),
                          1);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, AddressTableEntries),
                          1);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, ExportAddressTableRVA),
                          sectionRvaAt(kExportSectionRva, kAddressTableOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NamePointerRVA),
                          sectionRvaAt(kExportSectionRva, kNamePointerOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, OrdinalTableRVA),
                          sectionRvaAt(kExportSectionRva, kOrdinalTableOffset));

  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset),
                 sectionRvaAt(kExportSectionRva, kForwardNameOffset));
  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kNamePointerOffset),
                 sectionRvaAt(kExportSectionRva, kExportNameOffset));
  putExportWord(pe,
                kExportSectionRva,
                sectionRvaAt(kExportSectionRva, kOrdinalTableOffset),
                0);
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kExportNameOffset),
                   "Exported");
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kModuleNameOffset),
                   "module.dll");
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kForwardNameOffset),
                   "target.dll.Func");

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<ExportInfo> exports;
  IterExpFull(p.get(), captureExport, &exports);

  REQUIRE(exports.size() == 1);
  REQUIRE(exports[0].addr == 0);
  REQUIRE(exports[0].forwardName == "target.dll.Func");
}

TEST_CASE("ordinal-only exports are included", "[exports]") {
  constexpr std::uint32_t kExportSectionRva = kSectionRva;
  constexpr std::uint32_t kExportDirectorySize = 0x100;
  constexpr std::uint32_t kAddressTableOffset = 0x40;
  constexpr std::uint32_t kModuleNameOffset = 0x80;
  constexpr std::uint32_t kExportTargetRva = kExportSectionRva + 0x300;

  auto pe = makeMinimalPe(kExportSectionRva);
  putDataDirectory(pe, DIR_EXPORT, kExportSectionRva, kExportDirectorySize);

  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NameRVA),
                          sectionRvaAt(kExportSectionRva, kModuleNameOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, AddressTableEntries),
                          1);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NumberOfNamePointers),
                          0);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, ExportAddressTableRVA),
                          sectionRvaAt(kExportSectionRva, kAddressTableOffset));

  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset),
                 kExportTargetRva);
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kModuleNameOffset),
                   "module.dll");

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<ExportInfo> exports;
  IterExpFull(p.get(), captureExport, &exports);

  REQUIRE(exports.size() == 1);
  REQUIRE(exports[0].addr == kExportTargetRva);
  REQUIRE(exports[0].ordinal == 0);
  REQUIRE(exports[0].symbolName.empty());
  REQUIRE(exports[0].forwardName.empty());
}

TEST_CASE("empty ordinal-only export slots are skipped", "[exports]") {
  constexpr std::uint32_t kExportSectionRva = kSectionRva;
  constexpr std::uint32_t kExportDirectorySize = 0x100;
  constexpr std::uint32_t kAddressTableOffset = 0x40;
  constexpr std::uint32_t kModuleNameOffset = 0x80;
  constexpr std::uint32_t kExportTargetRva = kExportSectionRva + 0x300;

  auto pe = makeMinimalPe(kExportSectionRva);
  putDataDirectory(pe, DIR_EXPORT, kExportSectionRva, kExportDirectorySize);

  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NameRVA),
                          sectionRvaAt(kExportSectionRva, kModuleNameOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, AddressTableEntries),
                          2);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NumberOfNamePointers),
                          0);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, ExportAddressTableRVA),
                          sectionRvaAt(kExportSectionRva, kAddressTableOffset));

  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset),
                 0);
  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset + 4),
                 kExportTargetRva);
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kModuleNameOffset),
                   "module.dll");

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<ExportInfo> exports;
  IterExpFull(p.get(), captureExport, &exports);

  REQUIRE(exports.size() == 1);
  REQUIRE(exports[0].addr == kExportTargetRva);
  REQUIRE(exports[0].ordinal == 1);
  REQUIRE(exports[0].symbolName.empty());
  REQUIRE(exports[0].forwardName.empty());
}

TEST_CASE("mixed named and ordinal-only exports are included once",
          "[exports]") {
  constexpr std::uint32_t kExportSectionRva = kSectionRva;
  constexpr std::uint32_t kExportDirectorySize = 0x180;
  constexpr std::uint32_t kAddressTableOffset = 0x40;
  constexpr std::uint32_t kNamePointerOffset = 0x60;
  constexpr std::uint32_t kOrdinalTableOffset = 0x70;
  constexpr std::uint32_t kNameTwoOffset = 0x80;
  constexpr std::uint32_t kNameZeroOffset = 0x90;
  constexpr std::uint32_t kModuleNameOffset = 0xa0;
  constexpr std::uint32_t kForwardNameOffset = 0xb0;
  constexpr std::uint32_t kNamedZeroTargetRva = kExportSectionRva + 0x300;
  constexpr std::uint32_t kNamedTwoTargetRva = kExportSectionRva + 0x304;

  auto pe = makeMinimalPe(kExportSectionRva);
  putDataDirectory(pe, DIR_EXPORT, kExportSectionRva, kExportDirectorySize);

  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NameRVA),
                          sectionRvaAt(kExportSectionRva, kModuleNameOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, AddressTableEntries),
                          3);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NumberOfNamePointers),
                          2);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, ExportAddressTableRVA),
                          sectionRvaAt(kExportSectionRva, kAddressTableOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NamePointerRVA),
                          sectionRvaAt(kExportSectionRva, kNamePointerOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, OrdinalTableRVA),
                          sectionRvaAt(kExportSectionRva, kOrdinalTableOffset));

  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset),
                 kNamedZeroTargetRva);
  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset + 4),
                 sectionRvaAt(kExportSectionRva, kForwardNameOffset));
  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset + 8),
                 kNamedTwoTargetRva);

  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kNamePointerOffset),
                 sectionRvaAt(kExportSectionRva, kNameTwoOffset));
  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kNamePointerOffset + 4),
                 sectionRvaAt(kExportSectionRva, kNameZeroOffset));
  putExportWord(pe,
                kExportSectionRva,
                sectionRvaAt(kExportSectionRva, kOrdinalTableOffset),
                2);
  putExportWord(pe,
                kExportSectionRva,
                sectionRvaAt(kExportSectionRva, kOrdinalTableOffset + 2),
                0);

  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kNameTwoOffset),
                   "NamedTwo");
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kNameZeroOffset),
                   "NamedZero");
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kModuleNameOffset),
                   "module.dll");
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kForwardNameOffset),
                   "target.dll.Func");

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<ExportInfo> exports;
  IterExpFull(p.get(), captureExport, &exports);

  REQUIRE(exports.size() == 3);
  REQUIRE(exports[0].addr == kNamedTwoTargetRva);
  REQUIRE(exports[0].ordinal == 2);
  REQUIRE(exports[0].symbolName == "NamedTwo");
  REQUIRE(exports[0].forwardName.empty());
  REQUIRE(exports[1].addr == kNamedZeroTargetRva);
  REQUIRE(exports[1].ordinal == 0);
  REQUIRE(exports[1].symbolName == "NamedZero");
  REQUIRE(exports[1].forwardName.empty());
  REQUIRE(exports[2].addr == 0);
  REQUIRE(exports[2].ordinal == 1);
  REQUIRE(exports[2].symbolName.empty());
  REQUIRE(exports[2].forwardName == "target.dll.Func");
}

} // namespace peparse
