# ELF Binary Inspector

A command-line C++17 parser that validates and reports the structure of a
clearly defined subset of ELF files. This repository contains the Milestone 1
implementation for Secure Coding and Testing.

## Team

| Name | A-number | Email | Role |
| --- | --- | --- | --- |
| Baihong Chen | A02483973 | b.chen@usu.edu | Team Leader |

The Team Leader and primary contact is **Baihong Chen**.

## Supported scope

The inspector supports:

- 64-bit ELF files (`ELFCLASS64`)
- Little-endian byte order (`ELFDATA2LSB`)
- The x86-64 machine architecture (`EM_X86_64`)
- ELF header identification and reporting
- Program-header enumeration
- Section-header enumeration and section-name resolution
- Standard extended ELF table counts and section-name indices

For the ELF header, the report includes the object type, machine, entry point,
and the offsets, entry sizes, and counts of the program-header and
section-header tables. Each program header reports its segment type, flags,
file offset, virtual address, file size, and memory size. Each section header
reports its resolved name, type, flags, file offset, and size.

ELF32, big-endian ELF, and architectures other than x86-64 are recognized as
unsupported and produce a clear diagnostic.

## Build and test

Prerequisites:

- A C++17-capable `clang++`
- CMake 3.16 or newer

From a clean checkout, run:

```bash
./build.sh
```

The script configures CMake, builds the inspector and its tests, and runs the
test suite. The resulting executable is:

```text
build/elf_binary_inspector
```

Tests can also be rerun without rebuilding:

```bash
cd build
ctest --output-on-failure
```

## Usage

```bash
./build/elf_binary_inspector <elf-file>
```

Examples:

```bash
./build/elf_binary_inspector /bin/ls
./build/elf_binary_inspector ./build/elf_binary_inspector
```

Exit status is `0` for a successfully parsed file, `1` for an I/O error or
malformed ELF file, `2` for incorrect command-line usage, and `3` for a valid
ELF identity outside the supported format.

## Design summary

The parser follows this processing flow:

```text
ELF file
  -> read bytes
  -> validate ELF identity and supported format
  -> decode and validate the ELF header
  -> bounds-check and decode program headers
  -> bounds-check and decode section headers
  -> resolve names through the section-name string table
  -> print the structural report
```

Untrusted input is first read into an immutable byte buffer. Integer fields are
decoded explicitly from their ELF64 offsets with small little-endian reader
functions. The implementation does not cast file bytes to native C++ structs,
so it does not depend on host alignment, padding, or endianness.

Before reading any table or file-backed segment/section data, the parser checks
that its offset and size fit within the input. The range checks use subtraction
instead of unchecked `offset + size` arithmetic to avoid integer overflow.
`SHT_NOBITS` sections are handled specially because their memory size does not
occupy bytes in the file. Section names must lie inside the designated string
table and end with a null byte. Names are escaped before display so control
bytes from an untrusted file cannot be written directly to the terminal.

Malformed input stops parsing with a diagnostic; unsupported class, byte order,
or architecture is reported separately. This keeps the fixed Milestone 1
boundary explicit while preventing partial reports from invalid table data.

## Validation approach

The automated tests construct known ELF byte sequences and verify:

- Core ELF header fields
- Program-header fields and enumeration
- Section-header fields and section-name resolution
- ELF32, big-endian, and non-x86-64 rejection
- Truncated headers and out-of-range tables, segments, sections, and names
- Correct file-range behavior for `SHT_NOBITS`
- Standard extended table-count and section-name-index handling
- Successful inspection of the built executable

For manual comparison with the system reference tool:

```bash
readelf -h -l -S /bin/ls
./build/elf_binary_inspector /bin/ls
```

## Known limitations

- Only ELF64, little-endian, x86-64 files are supported.
- Symbol tables, relocations, dynamic entries, notes, and section contents are
  not decoded; their containing headers are still reported.
- The complete input file is held in memory while it is parsed.

## References

- [System V ELF ABI](https://gabi.xinuos.com/elf/01-intro.html)
- [Linux `elf(5)`](https://man7.org/linux/man-pages/man5/elf.5.html)
- [GNU `readelf`](https://sourceware.org/binutils/docs/binutils/readelf.html)

## Repository

<https://github.com/BaihongChen/CBH_CS6890>
