# ELF Binary Inspector

Milestone 1 implements a command-line C++17 program that parses and reports
the required ELF file structures.

## Team

| Name | A-number | Email | Role |
| --- | --- | --- | --- |
| Baihong Chen | A02483973 | b.chen@usu.edu | Team Leader |

## Supported scope

The program supports little-endian, x86-64 ELF64 files. It reports:

- ELF type, machine, entry point, and program/section table locations and counts
- Program-header type, flags, file offset, virtual address, file size, and memory size
- Section name, type, flags, file offset, and size

ELF32, big-endian ELF, and architectures other than x86-64 are reported as
unsupported.

## Build

Requirements are a C++17-capable `clang++` and CMake 3.16 or newer. From the
repository root, run:

```bash
./build.sh
```

This builds the program and runs its automated tests. The executable is created
at `build/elf_binary_inspector`.

## Usage

```bash
./build/elf_binary_inspector <elf-file>
```

Example:

```bash
./build/elf_binary_inspector /bin/ls
```

## Design summary

The program reads the input as untrusted bytes, validates its ELF identity and
supported format, checks every offset and size before access, parses the ELF,
program, and section headers, resolves section names through the section-name
string table, and prints a summary. Integer fields are decoded directly from
little-endian bytes rather than casting the input to native C++ structs.

## Known limitations

- Only little-endian, x86-64 ELF64 files are supported.
- Symbol tables, relocations, dynamic entries, notes, and section contents are
  not decoded.
- The complete input file is held in memory while parsing.
