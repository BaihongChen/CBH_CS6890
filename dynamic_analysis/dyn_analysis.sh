#!/usr/bin/env bash

set -euo pipefail

readonly project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly tests_dir="${project_dir}/dynamic_analysis/tests"

for tool in clang++ cmake ctest python3; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "Required tool not found: ${tool}" >&2
        exit 1
    fi
done

readonly cxx="$(command -v clang++)"
if ! "${cxx}" --version 2>&1 | head -n 1 | grep -q "clang"; then
    echo "clang++ is required to run the AddressSanitizer analysis" >&2
    exit 1
fi

# A fresh directory prevents an earlier, non-instrumented CMake cache or object
# file from being reused. Results are retained beneath the ignored build tree.
mkdir -p "${project_dir}/build/dynamic_analysis"
run_dir="$(mktemp -d "${project_dir}/build/dynamic_analysis/run-XXXXXX")"
readonly run_dir
readonly build_dir="${run_dir}/build"
readonly test_output_dir="${run_dir}/test-output"

# Some Linux installations expose a newer, incomplete GCC directory to Clang.
# If Clang cannot locate libstdc++, use the complete installation selected by
# g++. This branch is inactive on normally configured toolchains.
gcc_install_flag=""
if [[ "$("${cxx}" -print-file-name=libstdc++.so)" == "libstdc++.so" ]] &&
   command -v g++ >/dev/null 2>&1; then
    gxx_libstdcpp="$(g++ -print-file-name=libstdc++.so)"
    if [[ "${gxx_libstdcpp}" != "libstdc++.so" && -f "${gxx_libstdcpp}" ]]; then
        gcc_install_flag="--gcc-install-dir=$(dirname "${gxx_libstdcpp}")"
    fi
fi
readonly gcc_install_flag

compile_flags=(
    -O1
    -g
    -fsanitize=address
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
)
if [[ -n "${gcc_install_flag}" ]]; then
    compile_flags+=("${gcc_install_flag}")
fi
readonly compile_flags_string="${compile_flags[*]}"

# Linux enables LeakSanitizer through ASan. Explicit settings make failures
# stop immediately and exercise stack-use-after-return detection as well.
export ASAN_OPTIONS="halt_on_error=1:abort_on_error=1:detect_leaks=1:detect_stack_use_after_return=1"
if command -v llvm-symbolizer >/dev/null 2>&1; then
    export ASAN_SYMBOLIZER_PATH="$(command -v llvm-symbolizer)"
fi

echo "Dynamic-analysis output: ${run_dir}"
{
    "${cxx}" --version
    cmake --version
    python3 --version
    echo "ASAN_OPTIONS=${ASAN_OPTIONS}"
    echo "CXX flags: ${compile_flags_string}"

    cmake \
        -S "${project_dir}" \
        -B "${build_dir}" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_CXX_COMPILER="${cxx}" \
        -DCMAKE_CXX_FLAGS="${compile_flags_string}" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
        -DBUILD_TESTING=ON
    cmake --build "${build_dir}" --verbose --parallel 1

    # This includes the in-process parser suite (including every truncated
    # prefix of a valid ELF) and inspection of the newly built executable.
    ctest --test-dir "${build_dir}" --verbose

    # These tests drive the public command-line interface with generated files
    # and failure scenarios. Per-case stdout/stderr is retained in run_dir.
    python3 "${tests_dir}/run_test_cases.py" \
        --executable "${build_dir}/elf_binary_inspector" \
        --output-dir "${test_output_dir}"
} 2>&1 | tee "${run_dir}/analysis.log"

echo "ASan analysis completed successfully."
echo "Log: ${run_dir}/analysis.log"
echo "Case results: ${test_output_dir}/case_results.tsv"
