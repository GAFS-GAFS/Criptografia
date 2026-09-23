#ifndef SECUREBRIDGE_FILE_UTILS_HPP
#define SECUREBRIDGE_FILE_UTILS_HPP

#include "types.hpp"

#include <cstddef>
#include <filesystem>
#include <string>

namespace securebridge {

// Le e grava arquivos sem modificar seus bytes, inclusive arquivos binarios.
Bytes read_binary_file(const std::filesystem::path& path);
void write_binary_file(const std::filesystem::path& path, const Bytes& data);

// Converte apenas o inicio do vetor para uma amostra hexadecimal legivel.
std::string bytes_to_hex(const Bytes& data, std::size_t limit = 32);

}  // namespace securebridge

#endif
