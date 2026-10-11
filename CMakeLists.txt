cmake_minimum_required(VERSION 3.16)

project(
    elf_binary_inspector
    VERSION 1.0.0
    DESCRIPTION "A command-line inspector for ELF binaries"
    LANGUAGES CXX
)

function(enable_project_warnings target)
    target_compile_options(
        ${target}
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )
endfunction()

add_library(elf_parser STATIC src/elf_parser.cpp)
target_include_directories(elf_parser PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_features(elf_parser PUBLIC cxx_std_17)
enable_project_warnings(elf_parser)

add_executable(elf_binary_inspector src/main.cpp)
target_link_libraries(elf_binary_inspector PRIVATE elf_parser)
target_compile_features(elf_binary_inspector PRIVATE cxx_std_17)
enable_project_warnings(elf_binary_inspector)

include(CTest)
if(BUILD_TESTING)
    add_executable(elf_parser_tests tests/elf_parser_tests.cpp)
    target_link_libraries(elf_parser_tests PRIVATE elf_parser)
    target_compile_features(elf_parser_tests PRIVATE cxx_std_17)
    enable_project_warnings(elf_parser_tests)

    add_test(NAME elf_parser_unit_tests COMMAND elf_parser_tests)
    add_test(
        NAME inspect_built_executable
        COMMAND elf_binary_inspector $<TARGET_FILE:elf_binary_inspector>
    )
endif()
