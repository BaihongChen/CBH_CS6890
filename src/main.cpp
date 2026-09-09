#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

namespace {

constexpr std::array<std::uint8_t, 4> elf_magic{0x7f, 'E', 'L', 'F'};

bool has_elf_magic(const std::array<std::uint8_t, 4>& bytes) {
    return bytes == elf_magic;
}

void print_bytes(const std::array<std::uint8_t, 4>& bytes) {
    std::cout << "File signature:";
    for (const auto byte : bytes) {
        std::cout << " 0x" << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(byte);
    }
    std::cout << std::dec << '\n';
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file>\n";
        return 2;
    }

    const std::string path{argv[1]};
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        std::cerr << "Error: unable to open '" << path << "'.\n";
        return 1;
    }

    std::array<std::uint8_t, 4> bytes{};
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    if (input.gcount() != static_cast<std::streamsize>(bytes.size())) {
        std::cerr << "Error: '" << path << "' is too small to be an ELF file.\n";
        return 1;
    }

    print_bytes(bytes);
    if (has_elf_magic(bytes)) {
        std::cout << "Result: '" << path << "' is an ELF file.\n";
        return 0;
    }

    std::cout << "Result: '" << path << "' is not an ELF file.\n";
    return 1;
}
