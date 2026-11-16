# AddressSanitizer Dynamic Analysis Report

## Environment and method

- Analysis date: November 16, 2026.
- Base source revision: `3382a28` (`Add milestone 2 static analysis script and report`).
- Platform: Ubuntu 24.04.4 LTS, x86-64 Linux.
- Tools: Clang/Clang++ 18.1.3, CMake 3.28.3, CTest 3.28.3, and
  Python 3.12.3.
- Configuration: C++17, CMake Debug build, `BUILD_TESTING=ON`, `-O1 -g
  -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls`,
  and `-fsanitize=address` at the final link step.
- Runtime settings: `halt_on_error=1`, `abort_on_error=1`, `detect_leaks=1`,
  and `detect_stack_use_after_return=1` in `ASAN_OPTIONS`.

The build settings follow the official
[Clang AddressSanitizer documentation](https://clang.llvm.org/docs/AddressSanitizer.html),
including compiler and linker instrumentation, debug information, and retained
frame pointers for useful stack traces. On this machine, Clang selected an
incomplete GCC 14 installation that lacks `libstdc++.so`; the script detects
that condition and uses the complete GCC installation selected by `g++`. This
compatibility branch is not used on a normally configured Clang installation.

Run the analysis from any working directory with:

```bash
/path/to/project/dynamic_analysis/dyn_analysis.sh
```

The prerequisites are Bash, Clang/Clang++, CMake, CTest, Python 3, and an
ASan runtime compatible with Clang. The script checks these commands, creates a
new `build/dynamic_analysis/run-XXXXXX/` directory on every invocation, builds
all project targets with ASan, runs CTest, generates the binary test corpus, and
runs command-line scenarios. A new directory prevents cached, uninstrumented
objects from being reused. The ignored run directory retains:

- `analysis.log`, containing tool versions, compiler/linker commands, test
  output, and sanitizer diagnostics;
- `test-output/inputs/`, containing the generated input files;
- `test-output/case-logs/`, containing stdout and stderr for every scenario;
- `test-output/case_results.tsv`, containing the result summary.

## Test design

The test driver contains explicit field-level recipes rather than opaque binary
fixtures. It generates the same bytes on each run and verifies both exit codes
and representative messages. The final run executed 42 command-line scenarios:

| Category | Count | Representative inputs and targeted behavior |
| --- | ---: | --- |
| Normal | 4 | Minimum valid ELF64 header; complete program, section, and string tables; valid extended ELF numbering; inspection of the newly built ASan executable. These exercise successful parsing, table iteration, name resolution, and report formatting. |
| Boundary | 10 | Empty input; lengths 1, 4, 15, 16, and 63; a program table ending exactly at EOF; `SHT_NOBITS` with maximum offset/size; maximum program offset; and an extended section count that would overflow table-size multiplication. These target validation boundaries and overflow-safe range checks. |
| Malformed | 22 | Plain text, ELF32, big-endian ELF, invalid versions/machine/header size, zero or truncated table locations, incorrect entry sizes, segment/section ranges outside the file, `PT_LOAD` size inconsistency, invalid section zero, invalid string-table type/index/termination, and extended numbering without section zero. These target distinct rejection branches. |
| Failure | 6 | Missing and extra CLI arguments, missing path, directory input, non-seekable FIFO, and external `SIGTERM` while a 256 MiB sparse regular input is being acquired. These exercise error reporting, non-regular resources, interruption, and process cleanup. |

The ASan-instrumented `elf_parser_unit_tests` also runs in one process. It
covers valid headers/tables, unsupported formats, bounds checks, NOBITS/NULL
entries, extended numbering, and every truncated prefix of a 356-byte valid ELF.
Running many parse operations in one process complements the CLI cases and lets
LeakSanitizer inspect their combined resource lifetime at normal process exit.

The interruption scenario expects termination by `SIGTERM` and checks its
captured output for sanitizer diagnostics. Cleanup after an unhandled
termination signal is performed by the operating system; it does not claim to
test application-level signal recovery.

## Analysis results

### Initial run

The initial run (`run-MmFssT`) passed both CTest tests and 41 of the 42 CLI
scenarios. The directory-input scenario produced one ASan finding and aborted:

```text
ERROR: AddressSanitizer: requested allocation size 0x7fffffffffffffff
    #7 elf_inspector::parse_elf_file(...) src/elf_parser.cpp:362
SUMMARY: AddressSanitizer: allocation-size-too-big in operator new(unsigned long)
```

The finding was reproducible by passing an existing directory as the only
argument to the ASan-instrumented executable. It is a confirmed defect, not a
false positive: the application interpreted an invalid size result as a valid
file size and attempted an enormous allocation instead of returning an I/O
error.

Classification totals for the initial run are **1 confirmed defect, 0 false
positives, and 0 unresolved findings**. No out-of-bounds access, use-after-free,
double free, stack-use-after-return, or memory leak was reported in any other
scenario.

### Final run

After the fix, the clean run `run-yUh4iY` completed with status 0:

- CTest: **2/2 passed**.
- Command-line scenarios: **42/42 passed**.
- Directory regression: exited with the expected I/O error and no sanitizer
  diagnostic.
- AddressSanitizer/LeakSanitizer findings: **0**.

## Root cause and fix

### Confirmed defect: huge allocation for directory input

**Reproduction.** The `directory_input` failure scenario invokes
`elf_binary_inspector` with the generated input directory rather than a regular
file. Before the fix, this resulted in the ASan diagnostic shown above.

**Root cause.** `parse_elf_file` opened the path with `std::ios::ate`, called
`tellg()`, and rejected only positions less than zero or sizes greater than the
type limits. For a directory on this Linux/libstdc++ combination, `tellg()`
yielded `0x7fffffffffffffff`, exactly the maximum signed stream size. The value
passed the strict-greater-than check. Constructing a byte vector of that size
then caused ASan's allocator to abort before the existing `std::bad_alloc`
handler could return an `IoError`.

**Correction.** `parse_elf_file` now queries the path with the non-throwing
`std::filesystem::status` overload before opening it. Any existing path that is
not a regular file is rejected with `ParseStatus::IoError`, so directories,
FIFOs, devices, and sockets cannot reach file-size calculation or allocation.
Missing paths still follow the original open-failure branch. No sanitizer
suppression or `allocator_may_return_null` option was used to hide the finding.

**Verification.** In `run-yUh4iY`, the same directory case returned exit code 1
with `input is not a regular file`, and the FIFO case was also rejected without
blocking. All other normal and error-path expectations continued to pass. ASan
and LeakSanitizer emitted no diagnostics in the complete rerun.

## Limitations

- Dynamic analysis covers only executed paths. The finite generated corpus and
  existing tests do not enumerate all possible combinations of 64-bit ELF
  fields or all valid ELF files.
- Inputs are deterministic and field-directed, not coverage-guided fuzzing.
  Long-running randomized fuzzing could reach additional parser states.
- The project supports only little-endian x86-64 ELF64, so successful ELF32,
  big-endian, and other-architecture parsing is outside its intended scope.
- Allocation-failure handling for genuinely enormous regular files was not
  forced because ASan reserves a large virtual address range and process memory
  limits interact poorly with that reservation. The parser still reads the
  entire file into memory by design.
- Permission-denied behavior is not asserted because the analysis may run as a
  privileged user. Missing, directory, and FIFO paths exercise portable I/O
  failure branches instead.
- The `SIGTERM` case verifies safe OS cleanup after external interruption, not
  graceful application-level signal handling or LeakSanitizer execution at
  normal exit.
- ASan primarily detects memory errors that occur at runtime. A clean final run
  does not prove the absence of memory-safety vulnerabilities, data races,
  uninitialized reads, integer logic errors, or ELF semantic errors.
