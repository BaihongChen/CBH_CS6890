#include "elf_parser.hpp"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace {

std::string hex_value(std::uint64_t value) {
  std::ostringstream output;
  output << "0x" << std::hex << value;
  return output.str();
}

std::string object_type_name(std::uint16_t type) {
  switch (type) {
  case 0:
    return "NONE (No file type)";
  case 1:
    return "REL (Relocatable file)";
  case 2:
    return "EXEC (Executable file)";
  case 3:
    return "DYN (Shared object file)";
  case 4:
    return "CORE (Core file)";
  default:
    if (type >= 0xfe00 && type <= 0xfeff) {
      return "OS-specific";
    }
    if (type >= 0xff00) {
      return "Processor-specific";
    }
    return "Unknown";
  }
}

std::string program_type_name(std::uint32_t type) {
  switch (type) {
  case 0:
    return "NULL";
  case 1:
    return "LOAD";
  case 2:
    return "DYNAMIC";
  case 3:
    return "INTERP";
  case 4:
    return "NOTE";
  case 5:
    return "SHLIB";
  case 6:
    return "PHDR";
  case 7:
    return "TLS";
  case 0x6474e550:
    return "GNU_EH_FRAME";
  case 0x6474e551:
    return "GNU_STACK";
  case 0x6474e552:
    return "GNU_RELRO";
  case 0x6474e553:
    return "GNU_PROPERTY";
  default:
    if (type >= 0x60000000 && type <= 0x6fffffff) {
      return "OS-specific";
    }
    if (type >= 0x70000000 && type <= 0x7fffffff) {
      return "Processor-specific";
    }
    return "Unknown";
  }
}

std::string section_type_name(std::uint32_t type) {
  switch (type) {
  case 0:
    return "NULL";
  case 1:
    return "PROGBITS";
  case 2:
    return "SYMTAB";
  case 3:
    return "STRTAB";
  case 4:
    return "RELA";
  case 5:
    return "HASH";
  case 6:
    return "DYNAMIC";
  case 7:
    return "NOTE";
  case 8:
    return "NOBITS";
  case 9:
    return "REL";
  case 10:
    return "SHLIB";
  case 11:
    return "DYNSYM";
  case 14:
    return "INIT_ARRAY";
  case 15:
    return "FINI_ARRAY";
  case 16:
    return "PREINIT_ARRAY";
  case 17:
    return "GROUP";
  case 18:
    return "SYMTAB_SHNDX";
  case 0x6ffffff6:
    return "GNU_HASH";
  case 0x6ffffffd:
    return "GNU_VERDEF";
  case 0x6ffffffe:
    return "GNU_VERNEED";
  case 0x6fffffff:
    return "GNU_VERSYM";
  default:
    if (type >= 0x60000000 && type <= 0x6fffffff) {
      return "OS-specific";
    }
    if (type >= 0x70000000 && type <= 0x7fffffff) {
      return "Processor-specific";
    }
    return "Unknown";
  }
}

std::string program_flags(std::uint32_t flags) {
  std::string result;
  result += (flags & 0x4U) != 0U ? 'R' : '-';
  result += (flags & 0x2U) != 0U ? 'W' : '-';
  result += (flags & 0x1U) != 0U ? 'E' : '-';
  return result;
}

std::string section_flags(std::uint64_t flags) {
  std::string result;
  if ((flags & 0x1U) != 0U) {
    result += 'W';
  }
  if ((flags & 0x2U) != 0U) {
    result += 'A';
  }
  if ((flags & 0x4U) != 0U) {
    result += 'X';
  }
  if ((flags & 0x10U) != 0U) {
    result += 'M';
  }
  if ((flags & 0x20U) != 0U) {
    result += 'S';
  }
  if ((flags & 0x40U) != 0U) {
    result += 'I';
  }
  if ((flags & 0x80U) != 0U) {
    result += 'L';
  }
  if ((flags & 0x100U) != 0U) {
    result += 'O';
  }
  if ((flags & 0x200U) != 0U) {
    result += 'G';
  }
  if ((flags & 0x400U) != 0U) {
    result += 'T';
  }
  if ((flags & 0x800U) != 0U) {
    result += 'C';
  }
  return result.empty() ? "-" : result;
}

std::string printable_name(const std::string &name) {
  if (name.empty()) {
    return "<none>";
  }

  std::ostringstream output;
  for (const unsigned char character : name) {
    if (character >= 0x20U && character <= 0x7eU && character != '\\') {
      output << static_cast<char>(character);
    } else if (character == '\\') {
      output << "\\\\";
    } else {
      output << "\\x" << std::hex << std::setw(2) << std::setfill('0')
             << static_cast<unsigned int>(character) << std::dec;
    }
  }
  return output.str();
}

void print_report(const elf_inspector::ElfFile &file) {
  const auto &header = file.header;

  std::cout << "ELF Header:\n"
            << "  Class:                             ELF64\n"
            << "  Data:                              Little-endian\n"
            << "  Type:                              "
            << object_type_name(header.type) << " (" << header.type << ")\n"
            << "  Machine:                           AMD x86-64 ("
            << header.machine << ")\n"
            << "  Entry point:                       "
            << hex_value(header.entry_point) << '\n'
            << "  Program header table offset:       "
            << header.program_header_offset << " ("
            << hex_value(header.program_header_offset) << ")\n"
            << "  Program header entry size:         "
            << header.program_header_entry_size << '\n'
            << "  Program header count:              "
            << header.program_header_count << '\n'
            << "  Section header table offset:       "
            << header.section_header_offset << " ("
            << hex_value(header.section_header_offset) << ")\n"
            << "  Section header entry size:         "
            << header.section_header_entry_size << '\n'
            << "  Section header count:              "
            << header.section_header_count << '\n'
            << "  Section-name string table index:   "
            << header.section_name_table_index << "\n\n";

  std::cout << "Program Headers (" << file.program_headers.size() << "):\n";
  if (file.program_headers.empty()) {
    std::cout << "  <none>\n";
  }
  for (std::size_t index = 0; index < file.program_headers.size(); ++index) {
    const auto &program = file.program_headers[index];
    std::cout << "  [" << index << "]\n"
              << "    Type:             " << program_type_name(program.type)
              << " (" << hex_value(program.type) << ")\n"
              << "    Flags:            " << program_flags(program.flags)
              << " (" << hex_value(program.flags) << ")\n"
              << "    File offset:      " << program.offset << " ("
              << hex_value(program.offset) << ")\n"
              << "    Virtual address:  " << hex_value(program.virtual_address)
              << '\n'
              << "    File size:        " << program.file_size << '\n'
              << "    Memory size:      " << program.memory_size << '\n';
  }

  std::cout << "\nSection Headers (" << file.section_headers.size() << "):\n";
  if (file.section_headers.empty()) {
    std::cout << "  <none>\n";
  }
  for (std::size_t index = 0; index < file.section_headers.size(); ++index) {
    const auto &section = file.section_headers[index];
    std::cout << "  [" << index << "] " << printable_name(section.name) << '\n'
              << "    Type:         " << section_type_name(section.type) << " ("
              << hex_value(section.type) << ")\n"
              << "    Flags:        " << section_flags(section.flags) << " ("
              << hex_value(section.flags) << ")\n"
              << "    File offset:  " << section.offset << " ("
              << hex_value(section.offset) << ")\n"
              << "    Size:         " << section.size << '\n';
  }
}

} // namespace

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <elf-file>\n";
    return 2;
  }

  const auto result = elf_inspector::parse_elf_file(argv[1]);
  if (!result) {
    if (result.status == elf_inspector::ParseStatus::UnsupportedFormat) {
      std::cerr << "Unsupported ELF format: " << result.message << '\n';
      return 3;
    }
    std::cerr << "Error: " << result.message << '\n';
    return 1;
  }

  print_report(result.file);
  return 0;
}
