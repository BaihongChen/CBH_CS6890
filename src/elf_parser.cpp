#include "elf_parser.hpp"

#include <cstddef>
#include <fstream>
#include <limits>
#include <new>
#include <sstream>
#include <utility>

namespace elf_inspector {
namespace {

constexpr std::size_t elf_header_size = 64;
constexpr std::uint16_t elf64_program_header_size = 56;
constexpr std::uint16_t elf64_section_header_size = 64;
constexpr std::uint8_t elf_class_64 = 2;
constexpr std::uint8_t elf_data_little_endian = 1;
constexpr std::uint8_t elf_current_version = 1;
constexpr std::uint16_t machine_x86_64 = 62;
constexpr std::uint16_t extended_program_header_count = 0xffff;
constexpr std::uint16_t extended_section_name_index = 0xffff;
constexpr std::uint32_t program_type_load = 1;
constexpr std::uint32_t section_type_null = 0;
constexpr std::uint32_t section_type_string_table = 3;
constexpr std::uint32_t section_type_no_bits = 8;

class ByteReader {
public:
  explicit ByteReader(const std::vector<std::uint8_t> &bytes) : bytes_(bytes) {}

  bool contains(std::uint64_t offset, std::uint64_t length) const noexcept {
    const auto size = static_cast<std::uint64_t>(bytes_.size());
    return offset <= size && length <= size - offset;
  }

  std::uint8_t u8(std::uint64_t offset) const {
    return bytes_[static_cast<std::size_t>(offset)];
  }

  std::uint16_t u16(std::uint64_t offset) const {
    return static_cast<std::uint16_t>(u8(offset)) |
           static_cast<std::uint16_t>(u8(offset + 1)) << 8U;
  }

  std::uint32_t u32(std::uint64_t offset) const {
    return static_cast<std::uint32_t>(u8(offset)) |
           static_cast<std::uint32_t>(u8(offset + 1)) << 8U |
           static_cast<std::uint32_t>(u8(offset + 2)) << 16U |
           static_cast<std::uint32_t>(u8(offset + 3)) << 24U;
  }

  std::uint64_t u64(std::uint64_t offset) const {
    std::uint64_t value = 0;
    for (std::uint64_t index = 0; index < 8; ++index) {
      value |= static_cast<std::uint64_t>(u8(offset + index)) << (index * 8U);
    }
    return value;
  }

  bool read_string(std::uint64_t table_offset, std::uint64_t table_size,
                   std::uint32_t string_offset, std::string &output) const {
    if (string_offset >= table_size) {
      return false;
    }

    const std::uint64_t start = table_offset + string_offset;
    const std::uint64_t remaining = table_size - string_offset;
    if (!contains(start, remaining)) {
      return false;
    }

    output.clear();
    for (std::uint64_t index = 0; index < remaining; ++index) {
      const auto character = u8(start + index);
      if (character == 0) {
        return true;
      }
      output.push_back(static_cast<char>(character));
    }
    return false;
  }

private:
  const std::vector<std::uint8_t> &bytes_;
};

ParseResult failure(ParseStatus status, std::string message) {
  ParseResult result;
  result.status = status;
  result.message = std::move(message);
  return result;
}

ParseResult invalid(std::string message) {
  return failure(ParseStatus::InvalidFile, std::move(message));
}

ParseResult unsupported(std::string message) {
  return failure(ParseStatus::UnsupportedFormat, std::move(message));
}

bool table_fits(const ByteReader &reader, std::uint64_t offset,
                std::uint64_t count, std::uint16_t entry_size) {
  if (entry_size != 0 &&
      count > std::numeric_limits<std::uint64_t>::max() / entry_size) {
    return false;
  }
  return reader.contains(offset,
                         static_cast<std::uint64_t>(count) * entry_size);
}

std::string indexed_error(const char *table, std::uint64_t index,
                          const char *problem) {
  std::ostringstream message;
  message << table << " entry " << index << ' ' << problem;
  return message.str();
}

} // namespace

ParseResult parse_elf_bytes(const std::vector<std::uint8_t> &bytes) {
  const ByteReader reader{bytes};

  if (bytes.size() < 4) {
    return invalid("file is too small to contain an ELF signature");
  }
  if (reader.u8(0) != 0x7f || reader.u8(1) != 'E' || reader.u8(2) != 'L' ||
      reader.u8(3) != 'F') {
    return invalid("ELF signature is missing");
  }
  if (bytes.size() < 16) {
    return invalid("ELF identification bytes are truncated");
  }
  if (reader.u8(4) != elf_class_64) {
    return unsupported("only ELF64 files are supported");
  }
  if (reader.u8(5) != elf_data_little_endian) {
    return unsupported("only little-endian ELF files are supported");
  }
  if (reader.u8(6) != elf_current_version) {
    return invalid("ELF identification has an invalid version");
  }
  if (bytes.size() < elf_header_size) {
    return invalid("ELF64 header is truncated");
  }

  ElfFile file;
  auto &header = file.header;
  header.type = reader.u16(16);
  header.machine = reader.u16(18);
  const auto object_version = reader.u32(20);
  header.entry_point = reader.u64(24);
  header.program_header_offset = reader.u64(32);
  header.section_header_offset = reader.u64(40);
  const auto declared_header_size = reader.u16(52);
  header.program_header_entry_size = reader.u16(54);
  const auto encoded_program_header_count = reader.u16(56);
  header.section_header_entry_size = reader.u16(58);
  const auto encoded_section_header_count = reader.u16(60);
  const auto encoded_section_name_table_index = reader.u16(62);

  if (object_version != elf_current_version) {
    return invalid("ELF header has an invalid object-file version");
  }
  if (header.machine != machine_x86_64) {
    return unsupported("only the x86-64 machine architecture is supported");
  }
  if (declared_header_size != elf_header_size) {
    return invalid("ELF header size is not the ELF64 size of 64 bytes");
  }
  header.program_header_count = encoded_program_header_count;
  header.section_header_count = encoded_section_header_count;
  header.section_name_table_index = encoded_section_name_table_index;

  const bool uses_extended_section_count =
      encoded_section_header_count == 0 && header.section_header_offset != 0;
  const bool needs_section_zero =
      uses_extended_section_count ||
      encoded_program_header_count == extended_program_header_count ||
      encoded_section_name_table_index == extended_section_name_index;
  if (needs_section_zero) {
    if (header.section_header_offset == 0) {
      return invalid("extended ELF numbering requires section-header entry 0");
    }
    if (header.section_header_entry_size != elf64_section_header_size) {
      return invalid(
          "section-header entry size is not the ELF64 size of 64 bytes");
    }
    if (!reader.contains(header.section_header_offset,
                         elf64_section_header_size)) {
      return invalid("section-header entry 0 extends beyond the file");
    }
    if (reader.u32(header.section_header_offset + 4) != section_type_null) {
      return invalid("section-header entry 0 is not the required NULL entry");
    }

    if (uses_extended_section_count) {
      header.section_header_count =
          reader.u64(header.section_header_offset + 32);
      if (header.section_header_count == 0) {
        return invalid("extended section-header count is zero");
      }
    }
    if (encoded_program_header_count == extended_program_header_count) {
      header.program_header_count =
          reader.u32(header.section_header_offset + 44);
    }
    if (encoded_section_name_table_index == extended_section_name_index) {
      header.section_name_table_index =
          reader.u32(header.section_header_offset + 40);
    }
  }

  if (header.program_header_count > 0) {
    if (header.program_header_offset == 0) {
      return invalid(
          "program-header count is nonzero but its table offset is zero");
    }
    if (header.program_header_entry_size != elf64_program_header_size) {
      return invalid(
          "program-header entry size is not the ELF64 size of 56 bytes");
    }
    if (!table_fits(reader, header.program_header_offset,
                    header.program_header_count,
                    header.program_header_entry_size)) {
      return invalid("program-header table extends beyond the file");
    }
  }

  if (header.section_header_count > 0) {
    if (header.section_header_offset == 0) {
      return invalid(
          "section-header count is nonzero but its table offset is zero");
    }
    if (header.section_header_entry_size != elf64_section_header_size) {
      return invalid(
          "section-header entry size is not the ELF64 size of 64 bytes");
    }
    if (!table_fits(reader, header.section_header_offset,
                    header.section_header_count,
                    header.section_header_entry_size)) {
      return invalid("section-header table extends beyond the file");
    }
    if (header.section_name_table_index >= header.section_header_count &&
        header.section_name_table_index != 0) {
      return invalid("section-name string table index is out of range");
    }
  } else if (header.section_name_table_index != 0) {
    return invalid(
        "section-name table index is nonzero when no sections exist");
  }

  if (header.program_header_count > file.program_headers.max_size()) {
    return invalid("program-header count is too large to represent safely");
  }
  file.program_headers.reserve(
      static_cast<std::size_t>(header.program_header_count));
  for (std::uint64_t index = 0; index < header.program_header_count; ++index) {
    const auto offset =
        header.program_header_offset + index * header.program_header_entry_size;
    ProgramHeader program;
    program.type = reader.u32(offset);
    program.flags = reader.u32(offset + 4);
    program.offset = reader.u64(offset + 8);
    program.virtual_address = reader.u64(offset + 16);
    program.physical_address = reader.u64(offset + 24);
    program.file_size = reader.u64(offset + 32);
    program.memory_size = reader.u64(offset + 40);
    program.alignment = reader.u64(offset + 48);

    if (program.type != 0 && program.file_size > 0 &&
        !reader.contains(program.offset, program.file_size)) {
      return invalid(indexed_error("program-header", index,
                                   "describes bytes beyond the file"));
    }
    if (program.type == program_type_load &&
        program.file_size > program.memory_size) {
      return invalid(
          indexed_error("program-header", index,
                        "has a file size larger than its memory size"));
    }
    file.program_headers.push_back(program);
  }

  if (header.section_header_count > file.section_headers.max_size()) {
    return invalid("section-header count is too large to represent safely");
  }
  file.section_headers.reserve(
      static_cast<std::size_t>(header.section_header_count));
  for (std::uint64_t index = 0; index < header.section_header_count; ++index) {
    const auto offset =
        header.section_header_offset + index * header.section_header_entry_size;
    SectionHeader section;
    section.name_offset = reader.u32(offset);
    section.type = reader.u32(offset + 4);
    section.flags = reader.u64(offset + 8);
    section.address = reader.u64(offset + 16);
    section.offset = reader.u64(offset + 24);
    section.size = reader.u64(offset + 32);
    section.link = reader.u32(offset + 40);
    section.info = reader.u32(offset + 44);
    section.address_alignment = reader.u64(offset + 48);
    section.entry_size = reader.u64(offset + 56);

    if (section.type != section_type_null &&
        section.type != section_type_no_bits && section.size > 0 &&
        !reader.contains(section.offset, section.size)) {
      return invalid(indexed_error("section-header", index,
                                   "describes bytes beyond the file"));
    }
    file.section_headers.push_back(std::move(section));
  }

  if (!file.section_headers.empty() &&
      file.section_headers.front().type != section_type_null) {
    return invalid("section-header entry 0 is not the required NULL entry");
  }

  if (header.section_name_table_index != 0) {
    const auto &string_table = file.section_headers[static_cast<std::size_t>(
        header.section_name_table_index)];
    if (string_table.type != section_type_string_table) {
      return invalid(
          "section-name table does not reference a string-table section");
    }
    for (std::size_t index = 0; index < file.section_headers.size(); ++index) {
      auto &section = file.section_headers[index];
      if (!reader.read_string(string_table.offset, string_table.size,
                              section.name_offset, section.name)) {
        return invalid(indexed_error("section-header", index,
                                     "has an invalid or unterminated name"));
      }
    }
  }

  ParseResult result;
  result.status = ParseStatus::Success;
  result.file = std::move(file);
  return result;
}

ParseResult parse_elf_file(const std::string &path) {
  std::ifstream input{path, std::ios::binary | std::ios::ate};
  if (!input) {
    return failure(ParseStatus::IoError, "unable to open '" + path + "'");
  }

  const auto end_position = input.tellg();
  if (end_position < 0) {
    return failure(ParseStatus::IoError,
                   "unable to determine the size of '" + path + "'");
  }

  const auto file_size = static_cast<std::uint64_t>(end_position);
  if (file_size > std::numeric_limits<std::size_t>::max() ||
      file_size > static_cast<std::uint64_t>(
                      std::numeric_limits<std::streamsize>::max())) {
    return failure(ParseStatus::IoError, "file is too large to read safely");
  }

  try {
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(file_size));
    input.seekg(0, std::ios::beg);
    if (!input) {
      return failure(ParseStatus::IoError, "unable to seek in '" + path + "'");
    }
    if (!bytes.empty()) {
      input.read(reinterpret_cast<char *>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
      if (!input ||
          input.gcount() != static_cast<std::streamsize>(bytes.size())) {
        return failure(ParseStatus::IoError,
                       "unable to read all bytes from '" + path + "'");
      }
    }
    return parse_elf_bytes(bytes);
  } catch (const std::bad_alloc &) {
    return failure(ParseStatus::IoError,
                   "not enough memory to read '" + path + "'");
  }
}

} // namespace elf_inspector
