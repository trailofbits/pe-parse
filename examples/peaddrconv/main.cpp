#include <iostream>
#include <limits>
#include <memory>
#include <algorithm>

#include <climits>
#include <cstring>

#include <parser-library/parse.h>

using ParsedPeRef =
    std::unique_ptr<peparse::parsed_pe, void (*)(peparse::parsed_pe *)>;

ParsedPeRef openExecutable(const std::string &path) noexcept {
  // The factory function does not throw exceptions!
  ParsedPeRef obj(peparse::ParsePEFromFile(path.data()),
                  peparse::DestructParsedPE);
  if (!obj) {
    return ParsedPeRef(nullptr, peparse::DestructParsedPE);
  }

  return obj;
}

enum class AddressType {
  PhysicalOffset,
  RelativeVirtualAddress,
  VirtualAddress
};

bool convertAddress(ParsedPeRef &pe,
                    std::uint64_t address,
                    AddressType source_type,
                    AddressType destination_type,
                    std::uint64_t &result) noexcept {
  if (source_type == destination_type) {
    result = address;
    return true;
  }

  std::uint64_t image_base_address = 0U;
  if (pe->peHeader.nt.FileHeader.Machine == peparse::IMAGE_FILE_MACHINE_AMD64) {
    image_base_address = pe->peHeader.nt.OptionalHeader64.ImageBase;
  } else {
    image_base_address = pe->peHeader.nt.OptionalHeader.ImageBase;
  }

  struct SectionAddressLimits final {
    std::uintptr_t lowest_rva;
    std::uintptr_t lowest_offset;

    std::uintptr_t highest_rva;
    std::uintptr_t highest_offset;
  };

  auto L_getSectionAddressLimits = [](void *N,
                                      peparse::VA secBase,
                                      std::string &secName,
                                      peparse::image_section_header s,
                                      peparse::bounded_buffer *data) -> int {
    static_cast<void>(secBase);
    static_cast<void>(secName);
    static_cast<void>(data);

    SectionAddressLimits *section_address_limits =
        static_cast<SectionAddressLimits *>(N);

    section_address_limits->lowest_rva =
        std::min(section_address_limits->lowest_rva,
                 static_cast<std::uintptr_t>(s.VirtualAddress));

    section_address_limits->lowest_offset =
        std::min(section_address_limits->lowest_offset,
                 static_cast<std::uintptr_t>(s.PointerToRawData));

    std::uintptr_t sectionSize;
    if (s.SizeOfRawData != 0) {
      sectionSize = s.SizeOfRawData;
    } else {
      sectionSize = s.Misc.VirtualSize;
    }

    section_address_limits->highest_rva =
        std::max(section_address_limits->highest_rva,
                 static_cast<std::uintptr_t>(s.VirtualAddress + sectionSize));

    section_address_limits->highest_offset =
        std::max(section_address_limits->highest_offset,
                 static_cast<std::uintptr_t>(s.PointerToRawData + sectionSize));

    return 0;
  };

  SectionAddressLimits section_address_limits = {
      std::numeric_limits<std::uintptr_t>::max(),
      std::numeric_limits<std::uintptr_t>::max(),
      std::numeric_limits<std::uintptr_t>::min(),
      std::numeric_limits<std::uintptr_t>::min()};

  IterSec(pe.get(), L_getSectionAddressLimits, &section_address_limits);

  switch (source_type) {
    case AddressType::PhysicalOffset: {
      if (address >= section_address_limits.highest_offset) {
        return false;
      }

      if (destination_type == AddressType::RelativeVirtualAddress) {
        struct CallbackData final {
          bool found;
          std::uint64_t address;
          std::uint64_t result;
        };

        auto L_inspectSection = [](void *N,
                                   peparse::VA secBase,
                                   std::string &secName,
                                   peparse::image_section_header s,
                                   peparse::bounded_buffer *data) -> int {
          static_cast<void>(secBase);
          static_cast<void>(secName);
          static_cast<void>(data);

          std::uintptr_t sectionBaseOffset = s.PointerToRawData;

          std::uintptr_t sectionEndOffset = sectionBaseOffset;
          if (s.SizeOfRawData != 0) {
            sectionEndOffset += s.SizeOfRawData;
          } else {
            sectionEndOffset += s.Misc.VirtualSize;
          }

          auto callback_data = static_cast<CallbackData *>(N);
          if (callback_data->address >= sectionBaseOffset &&
              callback_data->address < sectionEndOffset) {
            callback_data->result = s.VirtualAddress + (callback_data->address -
                                                        s.PointerToRawData);

            callback_data->found = true;
            return 1;
          }

          return 0;
        };

        CallbackData callback_data = {false, address, 0U};
        IterSec(pe.get(), L_inspectSection, &callback_data);

        if (!callback_data.found) {
          return false;
        }

        result = callback_data.result;
        return true;

      } else if (destination_type == AddressType::VirtualAddress) {
        std::uint64_t rva = 0U;
        if (!convertAddress(pe,
                            address,
                            source_type,
                            AddressType::RelativeVirtualAddress,
                            rva)) {
          return false;
        }

        result = image_base_address + rva;
        return true;
      }

      return false;
    }

    case AddressType::RelativeVirtualAddress: {
      if (address < section_address_limits.lowest_rva) {
        result = address;
        return true;
      } else if (address >= section_address_limits.highest_rva) {
        return false;
      }

      if (destination_type == AddressType::PhysicalOffset) {
        struct CallbackData final {
          bool found;
          std::uint64_t address;
          std::uint64_t result;
        };

        auto L_inspectSection = [](void *N,
                                   peparse::VA secBase,
                                   std::string &secName,
                                   peparse::image_section_header s,
                                   peparse::bounded_buffer *data) -> int {
          static_cast<void>(secBase);
          static_cast<void>(secName);
          static_cast<void>(data);

          std::uintptr_t sectionBaseAddress = s.VirtualAddress;
          std::uintptr_t sectionEndAddress =
              sectionBaseAddress + s.Misc.VirtualSize;

          auto callback_data = static_cast<CallbackData *>(N);
          if (callback_data->address >= sectionBaseAddress &&
              callback_data->address < sectionEndAddress) {
            callback_data->result =
                s.PointerToRawData +
                (callback_data->address - sectionBaseAddress);

            callback_data->found = true;
            return 1;
          }

          return 0;
        };

        CallbackData callback_data = {false, address, 0U};
        IterSec(pe.get(), L_inspectSection, &callback_data);

        if (!callback_data.found) {
          return false;
        }

        result = callback_data.result;
        return true;

      } else if (destination_type == AddressType::VirtualAddress) {
        result = image_base_address + address;
        return true;
      }

      return false;
    }

    case AddressType::VirtualAddress: {
      if (address < image_base_address) {
        return false;
      }

      std::uint64_t rva = address - image_base_address;
      return convertAddress(pe,
                            rva,
                            AddressType::RelativeVirtualAddress,
                            destination_type,
                            result);
    }

    default: { return false; }
  }
}

int main(int argc, char *argv[]) {
  if (argc != 3 || (argc == 2 && std::strcmp(argv[1], "--help") == 0)) {
    std::cout << "PE address conversion utility from Trail of Bits\n";
    std::cout << "Usage:\n\tpeaddrconv /path/to/executable.exe address\n\n";
    std::cout << "The <address> parameter is always interpreted as hex!\n";

    return 1;
  }

  const char *executable_path = argv[1];
  const char *address_as_string = argv[2];

  char *last_parsed_char = nullptr;
  errno = 0;

  std::uint64_t address = std::strtoull(address_as_string, &last_parsed_char, 16);
  if (address == 0U && *last_parsed_char != 0) {
    std::cout << "Invalid address specified\n";
    return 1;

  } else if (address == ULLONG_MAX && errno == ERANGE) {
    std::cout << "The address you specified is too big\n";
    return 1;
  }

  auto pe = openExecutable(executable_path);
  if (!pe) {
    std::cout << "Failed to open the executable\n\n";

    std::cout << "Error: " << peparse::GetPEErr() << " ("
              << peparse::GetPEErrString() << ")\n";

    std::cout << "Location: " << peparse::GetPEErrLoc() << "\n";
    return 1;
  }

  std::uint64_t image_base_address = 0U;
  if (pe->peHeader.nt.FileHeader.Machine == peparse::IMAGE_FILE_MACHINE_AMD64) {
    image_base_address = pe->peHeader.nt.OptionalHeader64.ImageBase;
  } else {
    image_base_address = pe->peHeader.nt.OptionalHeader.ImageBase;
  }

  std::cout << "Image base address: 0x" << std::hex << image_base_address
            << "\n";
  std::cout << "Converting address 0x" << std::hex << address << "...\n\n";

  std::uint64_t result = 0U;

  std::cout << "as Physical offset (off)\n";
  std::cout << "  to rva:\t";
  if (convertAddress(pe,
                     address,
                     AddressType::PhysicalOffset,
                     AddressType::RelativeVirtualAddress,
                     result)) {
    std::cout << "0x" << std::hex << result;
  } else {
    std::cout << "-";
  }
  std::cout << "\n";

  std::cout << "  to va:\t";
  if (convertAddress(pe,
                     address,
                     AddressType::PhysicalOffset,
                     AddressType::VirtualAddress,
                     result)) {
    std::cout << "0x" << std::hex << result;
  } else {
    std::cout << "-";
  }
  std::cout << "\n\n";

  std::cout << "as Relative virtual address (rva)\n";
  std::cout << "  to off:\t";
  if (convertAddress(pe,
                     address,
                     AddressType::RelativeVirtualAddress,
                     AddressType::PhysicalOffset,
                     result)) {
    std::cout << "0x" << std::hex << result;
  } else {
    std::cout << "-";
  }
  std::cout << "\n";

  std::cout << "  to va:\t";
  if (convertAddress(pe,
                     address,
                     AddressType::RelativeVirtualAddress,
                     AddressType::VirtualAddress,
                     result)) {
    std::cout << "0x" << std::hex << result;
  } else {
    std::cout << "-";
  }
  std::cout << "\n\n";

  std::cout << "as Virtual address (va)\n";
  std::cout << "  to off:\t";
  if (convertAddress(pe,
                     address,
                     AddressType::VirtualAddress,
                     AddressType::PhysicalOffset,
                     result)) {
    std::cout << "0x" << std::hex << result;
  } else {
    std::cout << "-";
  }
  std::cout << "\n";

  std::cout << "  to rva:\t";
  if (convertAddress(pe,
                     address,
                     AddressType::VirtualAddress,
                     AddressType::RelativeVirtualAddress,
                     result)) {
    std::cout << "0x" << std::hex << result;
  } else {
    std::cout << "-";
  }
  std::cout << "\n";

  return 0;
}
