#include "elf_parser.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

int failures = 0;

void expect(bool condition, const std::string &description) {
  if (!condition) {
    std::cerr << "FAIL: " << description << '\n';
    ++failures;
  }
}

void put_u16(std::vector<std::uint8_t> &bytes, std::size_t offset,
             std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value);
  bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8U);
}

void put_u32(std::vector<std::uint8_t> &bytes, std::size_t offset,
             std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
  }
}

void put_u64(std::vector<std::uint8_t> &bytes, std::size_t offset,
             std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
  }
}

std::vector<std::uint8_t> minimal_elf() {
  std::vector<std::uint8_t> bytes(64, 0);
  bytes[0] = 0x7f;
  bytes[1] = 'E';
  bytes[2] = 'L';
  bytes[3] = 'F';
  bytes[4] = 2;           // ELF64
  bytes[5] = 1;           // Little-endian
  bytes[6] = 1;           // Current ELF version
  put_u16(bytes, 16, 2);  // Executable
  put_u16(bytes, 18, 62); // x86-64
  put_u32(bytes, 20, 1);  // Current object version
  put_u64(bytes, 24, 0x401000);
  put_u16(bytes, 52, 64); // ELF64 header size
  put_u16(bytes, 54, 56); // ELF64 program-header size
  put_u16(bytes, 58, 64); // ELF64 section-header size
  return bytes;
}

std::vector<std::uint8_t> elf_with_tables() {
  constexpr std::size_t file_size = 356;
  constexpr std::size_t program_offset = 64;
  constexpr std::size_t section_offset = 128;
  constexpr std::size_t string_offset = 320;
  constexpr std::size_t text_offset = 352;
  const std::string names{"\0.shstrtab\0.text\0", 17};

  auto bytes = minimal_elf();
  bytes.resize(file_size, 0);
  put_u64(bytes, 32, program_offset);
  put_u64(bytes, 40, section_offset);
  put_u16(bytes, 56, 1);
  put_u16(bytes, 60, 3);
  put_u16(bytes, 62, 1);

  put_u32(bytes, program_offset, 1);     // LOAD
  put_u32(bytes, program_offset + 4, 5); // R-E
  put_u64(bytes, program_offset + 8, 0);
  put_u64(bytes, program_offset + 16, 0x400000);
  put_u64(bytes, program_offset + 24, 0x400000);
  put_u64(bytes, program_offset + 32, file_size);
  put_u64(bytes, program_offset + 40, file_size + 4);
  put_u64(bytes, program_offset + 48, 0x1000);

  const auto string_header = section_offset + 64;
  put_u32(bytes, string_header, 1);     // .shstrtab
  put_u32(bytes, string_header + 4, 3); // STRTAB
  put_u64(bytes, string_header + 24, string_offset);
  put_u64(bytes, string_header + 32, names.size());
  put_u64(bytes, string_header + 48, 1);

  const auto text_header = section_offset + 128;
  put_u32(bytes, text_header, 11);    // .text
  put_u32(bytes, text_header + 4, 1); // PROGBITS
  put_u64(bytes, text_header + 8, 6); // ALLOC | EXEC
  put_u64(bytes, text_header + 16, 0x401000);
  put_u64(bytes, text_header + 24, text_offset);
  put_u64(bytes, text_header + 32, 4);
  put_u64(bytes, text_header + 48, 16);

  std::copy(names.begin(), names.end(), bytes.begin() + string_offset);
  bytes[text_offset] = 0x90;
  bytes[text_offset + 1] = 0x90;
  bytes[text_offset + 2] = 0x90;
  bytes[text_offset + 3] = 0xc3;
  return bytes;
}

void test_minimal_header() {
  const auto result = elf_inspector::parse_elf_bytes(minimal_elf());
  expect(static_cast<bool>(result), "minimal ELF64 header is accepted");
  if (!result) {
    return;
  }
  expect(result.file.header.type == 2, "object type is parsed");
  expect(result.file.header.machine == 62, "machine is parsed");
  expect(result.file.header.entry_point == 0x401000, "entry point is parsed");
  expect(result.file.program_headers.empty(),
         "absent program table is supported");
  expect(result.file.section_headers.empty(),
         "absent section table is supported");
}

void test_complete_tables() {
  const auto result = elf_inspector::parse_elf_bytes(elf_with_tables());
  expect(static_cast<bool>(result),
         "ELF with program and section tables is accepted");
  if (!result) {
    return;
  }
  expect(result.file.program_headers.size() == 1,
         "program header is enumerated");
  expect(result.file.program_headers[0].type == 1, "program type is parsed");
  expect(result.file.program_headers[0].flags == 5, "program flags are parsed");
  expect(result.file.program_headers[0].offset == 0,
         "program offset is parsed");
  expect(result.file.program_headers[0].virtual_address == 0x400000,
         "program virtual address is parsed");
  expect(result.file.program_headers[0].file_size == 356,
         "program file size is parsed");
  expect(result.file.program_headers[0].memory_size == 360,
         "program memory size is parsed");
  expect(result.file.section_headers.size() == 3,
         "section headers are enumerated");
  expect(result.file.section_headers[1].name == ".shstrtab",
         "section-name table name is resolved");
  expect(result.file.section_headers[2].name == ".text",
         "section name is resolved");
  expect(result.file.section_headers[2].type == 1, "section type is parsed");
  expect(result.file.section_headers[2].flags == 6, "section flags are parsed");
  expect(result.file.section_headers[2].offset == 352,
         "section offset is parsed");
  expect(result.file.section_headers[2].size == 4, "section size is parsed");
}

void test_format_rejection() {
  auto bytes = minimal_elf();
  bytes[0] = 0;
  expect(elf_inspector::parse_elf_bytes(bytes).status ==
             elf_inspector::ParseStatus::InvalidFile,
         "bad ELF magic is rejected");

  bytes = minimal_elf();
  bytes[4] = 1;
  expect(elf_inspector::parse_elf_bytes(bytes).status ==
             elf_inspector::ParseStatus::UnsupportedFormat,
         "ELF32 is reported as unsupported");

  bytes = minimal_elf();
  bytes[5] = 2;
  expect(elf_inspector::parse_elf_bytes(bytes).status ==
             elf_inspector::ParseStatus::UnsupportedFormat,
         "big-endian ELF is reported as unsupported");

  bytes = minimal_elf();
  put_u16(bytes, 18, 3);
  expect(elf_inspector::parse_elf_bytes(bytes).status ==
             elf_inspector::ParseStatus::UnsupportedFormat,
         "non-x86-64 ELF is reported as unsupported");

  bytes = minimal_elf();
  bytes.resize(63);
  expect(elf_inspector::parse_elf_bytes(bytes).status ==
             elf_inspector::ParseStatus::InvalidFile,
         "truncated ELF header is rejected");
}

void test_bounds_checks() {
  auto bytes = minimal_elf();
  put_u64(bytes, 32, 64);
  put_u16(bytes, 56, 1);
  expect(elf_inspector::parse_elf_bytes(bytes).status ==
             elf_inspector::ParseStatus::InvalidFile,
         "out-of-range program-header table is rejected");

  bytes = minimal_elf();
  put_u64(bytes, 40, 64);
  put_u16(bytes, 60, 1);
  expect(elf_inspector::parse_elf_bytes(bytes).status ==
             elf_inspector::ParseStatus::InvalidFile,
         "out-of-range section-header table is rejected");

  bytes = elf_with_tables();
  put_u64(bytes, 64 + 32, 1000);
  expect(elf_inspector::parse_elf_bytes(bytes).status ==
             elf_inspector::ParseStatus::InvalidFile,
         "out-of-range segment bytes are rejected");

  bytes = elf_with_tables();
  put_u32(bytes, 128 + 128, 30);
  expect(elf_inspector::parse_elf_bytes(bytes).status ==
             elf_inspector::ParseStatus::InvalidFile,
         "out-of-range section name is rejected");

  bytes = elf_with_tables();
  bytes[336] = 'X';
  expect(elf_inspector::parse_elf_bytes(bytes).status ==
             elf_inspector::ParseStatus::InvalidFile,
         "unterminated section name is rejected");

  bytes = elf_with_tables();
  put_u32(bytes, 128 + 64 + 4, 1);
  expect(elf_inspector::parse_elf_bytes(bytes).status ==
             elf_inspector::ParseStatus::InvalidFile,
         "non-string section-name table is rejected");

  const auto complete = elf_with_tables();
  bool all_truncations_rejected = true;
  for (std::size_t size = 0; size < complete.size(); ++size) {
    auto truncated = complete;
    truncated.resize(size);
    if (elf_inspector::parse_elf_bytes(truncated)) {
      all_truncations_rejected = false;
      break;
    }
  }
  expect(all_truncations_rejected, "every truncated prefix is rejected safely");
}

void test_no_bits_section() {
  auto bytes = elf_with_tables();
  const auto text_header = 128 + 128;
  put_u32(bytes, text_header + 4, 8); // NOBITS
  put_u64(bytes, text_header + 24, 10000);
  put_u64(bytes, text_header + 32, 4096);
  const auto result = elf_inspector::parse_elf_bytes(bytes);
  expect(static_cast<bool>(result),
         "NOBITS section need not occupy file bytes");
}

void test_null_entries_do_not_claim_file_bytes() {
  auto bytes = elf_with_tables();
  put_u32(bytes, 64, 0); // PT_NULL
  put_u64(bytes, 64 + 8, UINT64_MAX);
  put_u64(bytes, 64 + 32, UINT64_MAX);
  const auto result = elf_inspector::parse_elf_bytes(bytes);
  expect(static_cast<bool>(result),
         "PT_NULL entry ignores its undefined file range");
}

void test_extended_numbering() {
  auto bytes = elf_with_tables();
  put_u16(bytes, 56, 0xffff);
  put_u32(bytes, 128 + 44, 1);
  auto result = elf_inspector::parse_elf_bytes(bytes);
  expect(static_cast<bool>(result) && result.file.program_headers.size() == 1,
         "extended program-header count is resolved through section 0");

  bytes = elf_with_tables();
  put_u16(bytes, 60, 0);
  put_u64(bytes, 128 + 32, 3);
  result = elf_inspector::parse_elf_bytes(bytes);
  expect(static_cast<bool>(result) && result.file.section_headers.size() == 3,
         "extended section-header count is resolved through section 0");

  bytes = elf_with_tables();
  put_u16(bytes, 62, 0xffff);
  put_u32(bytes, 128 + 40, 1);
  result = elf_inspector::parse_elf_bytes(bytes);
  expect(static_cast<bool>(result) &&
             result.file.section_headers[2].name == ".text",
         "extended section-name index is resolved through section 0");

  bytes = minimal_elf();
  put_u16(bytes, 56, 0xffff);
  expect(elf_inspector::parse_elf_bytes(bytes).status ==
             elf_inspector::ParseStatus::InvalidFile,
         "extended numbering without section 0 is rejected");
}

} // namespace

int main() {
  test_minimal_header();
  test_complete_tables();
  test_format_rejection();
  test_bounds_checks();
  test_no_bits_section();
  test_null_entries_do_not_claim_file_bytes();
  test_extended_numbering();

  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "All ELF parser tests passed\n";
  return 0;
}
