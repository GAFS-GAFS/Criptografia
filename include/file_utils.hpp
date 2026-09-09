#ifndef SECUREBRIDGE_FILE_UTILS_HPP
#define SECUREBRIDGE_FILE_UTILS_HPP

#include "types.hpp"

#include <cstddef>
#include <filesystem>
#include <string>

namespace securebridge {

Bytes read_binary_file(const std::filesystem::path& path);
void write_binary_file(const std::filesystem::path& path, const Bytes& data);
std::string bytes_to_hex(const Bytes& data, std::size_t limit = 32);

}  // namespace securebridge

#endif
