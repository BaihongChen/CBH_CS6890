# Static Analysis Bug Report

## Environment and method

- Analysis date: November 1, 2026.
- Source revision: `8f7d22d6d9ade7b4f2f53165b163cc407d2f7492`.
- Platform: Ubuntu 20.04.6 LTS, x86-64 Linux.
- Tools: LLVM `scan-build` from `/usr/local/bin/scan-build`, Clang/Clang++
  16.0.0 (LLVM revision `08d094a0e457360ad8b94b017d2dc277e697ca76`),
  and CMake 3.16.3. These tools were already installed.
- Configuration: CMake Debug, Unix Makefiles, project C++17 requirement,
  `BUILD_TESTING=ON`, and the analyzer's default checkers. No checkers or
  project source files were excluded.

The procedure follows the official [Clang Static Analyzer documentation](https://clang.llvm.org/docs/ClangStaticAnalyzer.html)
and [scan-build usage guide](https://clang.llvm.org/docs/analyzer/user-docs/CommandLineUsage.html).

Run from the repository root:

```bash
./static_analysis/st_analysis.sh
```

Prerequisites are Bash, CMake, GNU Make, CTest, Clang/Clang++, and LLVM
scan-build on `PATH`. The script checks the required build and analysis tools.
Each invocation creates an empty `build/static_analysis/run-XXXXXX/build`
directory, so no previous CMake cache or object files can skip analysis.
Both configuration and compilation run through scan-build; CMake selects
`c++-analyzer` as its compiler wrapper. Compilation uses Clang++ and analysis
uses Clang, with their paths selected explicitly.

The script prints the run directory and preserves:

- `analysis.log`: tool versions, configuration, compiler/analyzer invocations,
  diagnostics, and test results.
- `reports/`: project analysis results in PLIST/HTML format.
- `configure-reports/`: results from CMake's configuration checks, kept
  separate from project analysis.

HTML diagnostic pages are generated when warnings exist. For these zero-warning
runs, the retained PLIST files and log provide the results; there are no HTML
bug pages. All generated files are inside the repository's already ignored
`build/` directory and are not part of the submission. Build or test failures
produce a nonzero script exit status. Warnings are recorded in the reports;
the script uses scan-build's default exit behavior, which does not fail a
successful build solely because warnings exist.

## Results and investigation

Two complete runs were performed, one from the repository root and one from
`/tmp` using the script's absolute path. Both exited with status 0.

| Run directory under `build/static_analysis/` | Project analyzer warnings | CTest result |
| --- | --- | --- |
| `run-IwKR2P` | 0 | 2/2 passed |
| `run-io5ji9` | 0 | 2/2 passed |

In each run, the build recompiled and analyzed all three translation units:
`src/elf_parser.cpp`, `src/main.cpp`, and `tests/elf_parser_tests.cpp`.
The included `src/elf_parser.hpp` was processed with these translation units.
Verbose logs contain Clang `-analyze` invocations and path-analysis progress,
confirming that analysis actually ran. Each project report directory contains
three PLIST files, all with empty `diagnostics` arrays. Both project analysis
summaries report `scan-build: No bugs found.` No analyzer failure directories
or compiler warnings/errors were observed.

There are no reported warning locations or execution paths to investigate.
The classification totals are: **0 confirmed bugs, 0 false positives, and
0 unresolved reported issues**. Root-cause analysis and fixes are not
applicable because no warnings were reported and no bugs were confirmed in
this investigation. No source-code changes were made.

## Verification

The repeated clean run reproduced the zero-warning result without reusing
build artifacts. In both runs, the script also executed the existing tests:

- `elf_parser_unit_tests`: passed; covers valid headers/tables, unsupported
  formats, truncated inputs, bounds checks, section names, NOBITS/NULL entries,
  and extended numbering.
- `inspect_built_executable`: passed; the inspector successfully parsed its
  newly built executable.

## Limitations

Zero warnings do not prove the program is free of defects. This result applies
to the recorded source revision, toolchain, default checkers, and build
configuration. Path exploration and loop handling are bounded, and models of
C++ library operations such as vectors, strings, and file streams are incomplete;
some input-dependent bounds errors, integer errors, or failure paths may be
missed. This scan-build run does not enable cross-translation-unit analysis,
so calls between separately compiled source files are not fully followed.
Static analysis also does not establish complete ELF-format correctness or
behavior for every malformed file. The existing tests provide additional
evidence only for the cases they exercise.
