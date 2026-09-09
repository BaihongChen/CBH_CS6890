cmake_minimum_required(VERSION 3.16)

project(
    elf_binary_inspector
    VERSION 0.1.0
    DESCRIPTION "A command-line inspector for ELF binaries"
    LANGUAGES CXX
)

add_executable(elf_binary_inspector src/main.cpp)

target_compile_features(elf_binary_inspector PRIVATE cxx_std_17)
target_compile_options(
    elf_binary_inspector
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)
