#ifndef SECUREBRIDGE_SHA256_HPP
#define SECUREBRIDGE_SHA256_HPP

#include "types.hpp"

#include <string>

namespace securebridge {

Bytes sha256(const Bytes& data);
std::string sha256_hex(const Bytes& data);

}  // namespace securebridge

#endif
