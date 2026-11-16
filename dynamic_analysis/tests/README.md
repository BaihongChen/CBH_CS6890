# Dynamic Test Inputs

`run_test_cases.py` deterministically generates the binary inputs in a retained
analysis run directory and executes the ASan-instrumented command-line program.
Keeping the recipes here instead of committing opaque binary files makes every
field mutation reviewable and reproducible.

The generated corpus contains these behavior groups:

- **Normal:** a minimum ELF64 header, a complete ELF with program/section/name
  tables, extended ELF numbering, and the ASan-instrumented executable itself.
- **Boundary:** empty and truncated files at validation boundaries, a table
  ending exactly at EOF, `SHT_NOBITS` ranges outside the file, maximum offsets,
  and a section-count multiplication overflow attempt.
- **Malformed:** wrong identity fields, unsupported formats, inconsistent table
  metadata, invalid ranges, invalid section zero, and invalid string tables.
- **Failure:** bad CLI arity, a missing path, a directory, a non-seekable FIFO,
  and external termination while a large regular input is being acquired.

The driver checks exit codes and representative output for every case. It also
fails if captured output contains an AddressSanitizer or LeakSanitizer marker.
Generated inputs, per-case stdout/stderr, and `case_results.tsv` are stored under
`build/dynamic_analysis/run-*/test-output/`.
