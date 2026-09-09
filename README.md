# ELF Binary Inspector

Semester project repository for an **ELF Binary Inspector**.

## Team

| Name | A-number | Email | Role |
| --- | --- | --- | --- |
| Baihong Chen | A02483973 | b.chen@usu.edu | Team Leader |

The Team Leader and primary contact is **Baihong Chen**.

## Project

The selected semester project is **ELF Binary Inspector**.

This initial version accepts a file path and checks whether the file begins with
the ELF magic bytes (`0x7f`, `E`, `L`, `F`). It establishes the required project
layout and a working command-line build for future development.

## Build

The development environment used for this initial setup provides:

- `clang++` 16.0.0
- CMake 3.16.3
- Git 2.25.1

Build from the repository root:

```bash
./build.sh
```

The executable is generated at `build/elf_binary_inspector`.

## Run

```bash
./build/elf_binary_inspector /path/to/binary
```

For example, the inspector can inspect itself:

```bash
./build/elf_binary_inspector ./build/elf_binary_inspector
```
