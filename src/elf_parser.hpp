#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace elf_inspector {

enum class ParseStatus {
  Success,
  InvalidFile,
  UnsupportedFormat,
  IoError,
};

struct ElfHeader {
  std::uint16_t type{};
  std::uint16_t machine{};
  std::uint64_t entry_point{};
  std::uint64_t program_header_offset{};
  std::uint64_t section_header_offset{};
  std::uint16_t program_header_entry_size{};
  std::uint64_t program_header_count{};
  std::uint16_t section_header_entry_size{};
  std::uint64_t section_header_count{};
  std::uint64_t section_name_table_index{};
};

struct ProgramHeader {
  std::uint32_t type{};
  std::uint32_t flags{};
  std::uint64_t offset{};
  std::uint64_t virtual_address{};
  std::uint64_t physical_address{};
  std::uint64_t file_size{};
  std::uint64_t memory_size{};
  std::uint64_t alignment{};
};

struct SectionHeader {
  std::uint32_t name_offset{};
  std::string name;
  std::uint32_t type{};
  std::uint64_t flags{};
  std::uint64_t address{};
  std::uint64_t offset{};
  std::uint64_t size{};
  std::uint32_t link{};
  std::uint32_t info{};
  std::uint64_t address_alignment{};
  std::uint64_t entry_size{};
};

struct ElfFile {
  ElfHeader header;
  std::vector<ProgramHeader> program_headers;
  std::vector<SectionHeader> section_headers;
};

struct ParseResult {
  ParseStatus status{ParseStatus::InvalidFile};
  ElfFile file;
  std::string message;

  explicit operator bool() const noexcept {
    return status == ParseStatus::Success;
  }
};

ParseResult parse_elf_bytes(const std::vector<std::uint8_t> &bytes);
ParseResult parse_elf_file(const std::string &path);

} // namespace elf_inspector
