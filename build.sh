#!/usr/bin/env bash

set -euo pipefail

readonly project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly build_dir="${project_dir}/build"

cmake \
    -S "${project_dir}" \
    -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
    -DBUILD_TESTING=ON
cmake --build "${build_dir}"

(
    cd "${build_dir}"
    ctest --output-on-failure
)
