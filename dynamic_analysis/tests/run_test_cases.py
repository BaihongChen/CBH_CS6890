#!/usr/bin/env python3
"""Generate ELF test inputs and run the ASan-instrumented command-line tool."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class FileCase:
    category: str
    name: str
    data: bytes
    return_code: int
    expected_text: str


def put_u16(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", data, offset, value)


def put_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def put_u64(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", data, offset, value)


def minimal_elf() -> bytearray:
    data = bytearray(64)
    data[0:7] = b"\x7fELF\x02\x01\x01"
    put_u16(data, 16, 2)  # ET_EXEC
    put_u16(data, 18, 62)  # EM_X86_64
    put_u32(data, 20, 1)  # EV_CURRENT
    put_u64(data, 24, 0x401000)
    put_u16(data, 52, 64)
    put_u16(data, 54, 56)
    put_u16(data, 58, 64)
    return data


def elf_with_tables() -> bytearray:
    file_size = 356
    program_offset = 64
    section_offset = 128
    string_offset = 320
    text_offset = 352
    names = b"\x00.shstrtab\x00.text\x00"

    data = minimal_elf()
    data.extend(bytes(file_size - len(data)))
    put_u64(data, 32, program_offset)
    put_u64(data, 40, section_offset)
    put_u16(data, 56, 1)
    put_u16(data, 60, 3)
    put_u16(data, 62, 1)

    put_u32(data, program_offset, 1)  # PT_LOAD
    put_u32(data, program_offset + 4, 5)  # R-E
    put_u64(data, program_offset + 8, 0)
    put_u64(data, program_offset + 16, 0x400000)
    put_u64(data, program_offset + 24, 0x400000)
    put_u64(data, program_offset + 32, file_size)
    put_u64(data, program_offset + 40, file_size + 4)
    put_u64(data, program_offset + 48, 0x1000)

    string_header = section_offset + 64
    put_u32(data, string_header, 1)
    put_u32(data, string_header + 4, 3)  # SHT_STRTAB
    put_u64(data, string_header + 24, string_offset)
    put_u64(data, string_header + 32, len(names))
    put_u64(data, string_header + 48, 1)

    text_header = section_offset + 128
    put_u32(data, text_header, 11)
    put_u32(data, text_header + 4, 1)  # SHT_PROGBITS
    put_u64(data, text_header + 8, 6)
    put_u64(data, text_header + 16, 0x401000)
    put_u64(data, text_header + 24, text_offset)
    put_u64(data, text_header + 32, 4)
    put_u64(data, text_header + 48, 16)

    data[string_offset : string_offset + len(names)] = names
    data[text_offset : text_offset + 4] = b"\x90\x90\x90\xc3"
    return data


def changed(source: bytearray, change) -> bytes:
    result = bytearray(source)
    change(result)
    return bytes(result)


def make_cases() -> list[FileCase]:
    minimal = minimal_elf()
    complete = elf_with_tables()
    cases: list[FileCase] = [
        FileCase("normal", "minimal_elf64", bytes(minimal), 0, "Program Headers (0)"),
        FileCase("normal", "complete_tables", bytes(complete), 0, "[2] .text"),
    ]

    exact_program_table = bytearray(minimal)
    exact_program_table.extend(bytes(56))
    put_u64(exact_program_table, 32, 64)
    put_u16(exact_program_table, 56, 1)
    cases.append(
        FileCase(
            "boundary",
            "program_table_ends_at_eof",
            bytes(exact_program_table),
            0,
            "Program Headers (1)",
        )
    )

    extended = bytearray(complete)
    put_u16(extended, 56, 0xFFFF)
    put_u16(extended, 60, 0)
    put_u16(extended, 62, 0xFFFF)
    put_u64(extended, 128 + 32, 3)
    put_u32(extended, 128 + 40, 1)
    put_u32(extended, 128 + 44, 1)
    cases.append(
        FileCase("normal", "extended_numbering", bytes(extended), 0, "[2] .text")
    )

    no_bits = bytearray(complete)
    put_u32(no_bits, 128 + 128 + 4, 8)
    put_u64(no_bits, 128 + 128 + 24, (1 << 64) - 1)
    put_u64(no_bits, 128 + 128 + 32, (1 << 64) - 1)
    cases.append(
        FileCase("boundary", "nobits_outside_file", bytes(no_bits), 0, "NOBITS")
    )

    cases.extend(
        [
            FileCase("boundary", "empty", b"", 1, "too small"),
            FileCase("boundary", "one_byte", b"\x7f", 1, "too small"),
            FileCase("boundary", "magic_only", b"\x7fELF", 1, "identification bytes are truncated"),
            FileCase("boundary", "identification_15_bytes", bytes(minimal[:15]), 1, "identification bytes are truncated"),
            FileCase("boundary", "header_16_bytes", bytes(minimal[:16]), 1, "ELF64 header is truncated"),
            FileCase("boundary", "header_63_bytes", bytes(minimal[:63]), 1, "ELF64 header is truncated"),
            FileCase("malformed", "plain_text", b"not an ELF file\n", 1, "ELF signature is missing"),
            FileCase("malformed", "elf32", changed(minimal, lambda d: d.__setitem__(4, 1)), 3, "only ELF64"),
            FileCase("malformed", "big_endian", changed(minimal, lambda d: d.__setitem__(5, 2)), 3, "only little-endian"),
            FileCase("malformed", "bad_ident_version", changed(minimal, lambda d: d.__setitem__(6, 0)), 1, "invalid version"),
            FileCase("malformed", "bad_machine", changed(minimal, lambda d: put_u16(d, 18, 3)), 3, "only the x86-64"),
            FileCase("malformed", "bad_object_version", changed(minimal, lambda d: put_u32(d, 20, 2)), 1, "invalid object-file version"),
            FileCase("malformed", "bad_header_size", changed(minimal, lambda d: put_u16(d, 52, 63)), 1, "header size"),
            FileCase("malformed", "program_count_without_offset", changed(minimal, lambda d: put_u16(d, 56, 1)), 1, "table offset is zero"),
            FileCase("malformed", "bad_program_entry_size", changed(complete, lambda d: put_u16(d, 54, 55)), 1, "program-header entry size"),
            FileCase("malformed", "truncated_program_table", changed(minimal, lambda d: (put_u64(d, 32, 64), put_u16(d, 56, 1))), 1, "program-header table extends"),
            FileCase("boundary", "maximum_program_offset", changed(minimal, lambda d: (put_u64(d, 32, (1 << 64) - 1), put_u16(d, 56, 1))), 1, "program-header table extends"),
            FileCase("malformed", "load_file_larger_than_memory", changed(complete, lambda d: put_u64(d, 64 + 40, 1)), 1, "file size larger"),
            FileCase("malformed", "segment_bytes_out_of_range", changed(complete, lambda d: put_u64(d, 64 + 32, 1000)), 1, "describes bytes beyond"),
            FileCase("malformed", "section_count_without_offset", changed(minimal, lambda d: put_u16(d, 60, 1)), 1, "table offset is zero"),
            FileCase("malformed", "bad_section_entry_size", changed(complete, lambda d: put_u16(d, 58, 63)), 1, "section-header entry size"),
            FileCase("malformed", "section_name_index_out_of_range", changed(complete, lambda d: put_u16(d, 62, 3)), 1, "string table index is out of range"),
            FileCase("malformed", "section_bytes_out_of_range", changed(complete, lambda d: put_u64(d, 128 + 128 + 32, 1000)), 1, "describes bytes beyond"),
            FileCase("malformed", "section_zero_not_null", changed(complete, lambda d: put_u32(d, 128 + 4, 1)), 1, "entry 0 is not"),
            FileCase("malformed", "name_table_wrong_type", changed(complete, lambda d: put_u32(d, 128 + 64 + 4, 1)), 1, "does not reference a string-table"),
            FileCase("malformed", "name_offset_out_of_range", changed(complete, lambda d: put_u32(d, 128 + 128, 30)), 1, "invalid or unterminated name"),
            FileCase("malformed", "unterminated_section_name", changed(complete, lambda d: d.__setitem__(336, ord("X"))), 1, "invalid or unterminated name"),
            FileCase("malformed", "name_index_without_sections", changed(minimal, lambda d: put_u16(d, 62, 1)), 1, "when no sections exist"),
            FileCase("malformed", "extended_count_without_section_zero", changed(minimal, lambda d: put_u16(d, 56, 0xFFFF)), 1, "requires section-header entry 0"),
        ]
    )

    enormous_section_count = bytearray(minimal)
    enormous_section_count.extend(bytes(64))
    put_u64(enormous_section_count, 40, 64)
    put_u64(enormous_section_count, 64 + 32, (1 << 64) - 1)
    cases.append(
        FileCase(
            "boundary",
            "section_count_multiplication_overflow",
            bytes(enormous_section_count),
            1,
            "section-header table extends",
        )
    )
    return cases


ASAN_MARKERS = (
    "ERROR: AddressSanitizer",
    "AddressSanitizer:DEADLYSIGNAL",
    "ERROR: LeakSanitizer",
)


def save_process_output(log_dir: Path, name: str, result: subprocess.CompletedProcess[str]) -> None:
    (log_dir / f"{name}.stdout.txt").write_text(result.stdout, encoding="utf-8")
    (log_dir / f"{name}.stderr.txt").write_text(result.stderr, encoding="utf-8")


def validate_result(
    name: str,
    result: subprocess.CompletedProcess[str],
    expected_code: int,
    expected_text: str,
) -> str | None:
    combined = result.stdout + result.stderr
    if any(marker in combined for marker in ASAN_MARKERS):
        return "AddressSanitizer/LeakSanitizer diagnostic detected"
    if result.returncode != expected_code:
        return f"expected exit {expected_code}, got {result.returncode}"
    if expected_text not in combined:
        return f"expected text not found: {expected_text!r}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    executable = args.executable.resolve()
    output_dir = args.output_dir.resolve()
    input_dir = output_dir / "inputs"
    log_dir = output_dir / "case-logs"
    input_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    if not executable.is_file():
        print(f"Executable not found: {executable}", file=sys.stderr)
        return 1

    rows: list[tuple[str, str, str, int]] = []
    failures: list[str] = []

    def record(category: str, name: str, result: subprocess.CompletedProcess[str], error: str | None) -> None:
        status = "PASS" if error is None else "FAIL"
        rows.append((category, name, status, result.returncode))
        print(f"[{status}] {category:9s} {name} (exit {result.returncode})")
        if error is not None:
            failures.append(f"{name}: {error}")

    for case in make_cases():
        path = input_dir / f"{case.name}.bin"
        path.write_bytes(case.data)
        result = subprocess.run(
            [str(executable), str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        save_process_output(log_dir, case.name, result)
        record(
            case.category,
            case.name,
            result,
            validate_result(case.name, result, case.return_code, case.expected_text),
        )

    command_cases = [
        ("failure", "missing_argument", [str(executable)], 2, "Usage:"),
        ("failure", "extra_argument", [str(executable), "one", "two"], 2, "Usage:"),
        ("failure", "missing_file", [str(executable), str(input_dir / "does-not-exist")], 1, "unable to open"),
        ("failure", "directory_input", [str(executable), str(input_dir)], 1, "Error:"),
        ("normal", "instrumented_executable", [str(executable), str(executable)], 0, "ELF Header:"),
    ]
    for category, name, command, expected_code, expected_text in command_cases:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        save_process_output(log_dir, name, result)
        record(category, name, result, validate_result(name, result, expected_code, expected_text))

    # A FIFO is a realistic non-seekable input. It must be rejected before a
    # blocking open or size/allocation attempt.
    fifo_path = output_dir / "nonseekable.fifo"
    os.mkfifo(fifo_path)
    fifo_result = subprocess.run(
        [str(executable), str(fifo_path)],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    save_process_output(log_dir, "nonseekable_input", fifo_result)
    record(
        "failure",
        "nonseekable_input",
        fifo_result,
        validate_result("nonseekable_input", fifo_result, 1, "Error:"),
    )
    fifo_path.unlink()

    # Exercise external interruption during acquisition of a large regular
    # input. The file is sparse, so it consumes little disk space. The expected
    # SIGTERM status is negative on POSIX; OS teardown releases resources.
    interrupt_input = output_dir / "interrupted-large-input.bin"
    with interrupt_input.open("wb") as stream:
        stream.truncate(256 * 1024 * 1024)
    interrupted = subprocess.Popen(
        [str(executable), str(interrupt_input)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.005)
    interrupted.send_signal(signal.SIGTERM)
    stdout, stderr = interrupted.communicate(timeout=5)
    interrupt_result = subprocess.CompletedProcess(
        [str(executable), str(interrupt_input)], interrupted.returncode, stdout, stderr
    )
    save_process_output(log_dir, "interrupted_open", interrupt_result)
    interrupt_error = validate_result(
        "interrupted_open", interrupt_result, -signal.SIGTERM, ""
    )
    record("failure", "interrupted_open", interrupt_result, interrupt_error)
    interrupt_input.unlink()

    results_path = output_dir / "case_results.tsv"
    with results_path.open("w", encoding="utf-8") as stream:
        stream.write("category\tcase\tstatus\texit_code\n")
        for category, name, status, return_code in rows:
            stream.write(f"{category}\t{name}\t{status}\t{return_code}\n")

    print(f"Executed {len(rows)} command-line scenarios; results: {results_path}")
    if failures:
        print("Dynamic test failures:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
