#ifndef SECUREBRIDGE_AFFINETRANS_HPP
#define SECUREBRIDGE_AFFINETRANS_HPP

#include "types.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace securebridge {

struct AffineTransKey {
    Byte multiplier{};
    Byte offset{};
    std::vector<std::size_t> transposition;
};

AffineTransKey derive_affinetrans_key(
    const std::string& passphrase,
    std::size_t block_size = 16
);

Bytes affinetrans_encrypt(const Bytes& plaintext, const AffineTransKey& key);
Bytes affinetrans_decrypt(const Bytes& ciphertext, const AffineTransKey& key);

}  // namespace securebridge

#endif
