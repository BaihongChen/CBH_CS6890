#!/usr/bin/env bash

set -euo pipefail

readonly project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for tool in scan-build clang clang++ cmake make ctest; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "Required tool not found: ${tool}" >&2
        exit 1
    fi
done

# A new directory on every invocation prevents cached objects from skipping analysis.
mkdir -p "${project_dir}/build/static_analysis"
run_dir="$(mktemp -d "${project_dir}/build/static_analysis/run-XXXXXX")"
readonly run_dir
readonly build_dir="${run_dir}/build"
readonly scan_options=(
    --use-analyzer "$(command -v clang)"
    --use-c++ "$(command -v clang++)"
    --keep-empty -plist-html -v -v
)

echo "Analysis output: ${run_dir}"
(
    clang --version
    cmake --version

    # Configure through scan-build so CMake caches its compiler wrapper.
    scan-build "${scan_options[@]}" -o "${run_dir}/configure-reports" \
        cmake -S "${project_dir}" -B "${build_dir}" \
        -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON

    scan-build "${scan_options[@]}" -o "${run_dir}/reports" \
        cmake --build "${build_dir}" --verbose --parallel 1

    cd "${build_dir}"
    ctest --output-on-failure
) 2>&1 | tee "${run_dir}/analysis.log"
