#ifndef SECUREBRIDGE_AES_CIPHER_HPP
#define SECUREBRIDGE_AES_CIPHER_HPP

#include "types.hpp"

#include <string>

namespace securebridge {

Bytes derive_aes256_key(const std::string& passphrase);
Bytes aes256_gcm_encrypt(const Bytes& plaintext, const Bytes& key);
Bytes aes256_gcm_decrypt(const Bytes& encrypted_file, const Bytes& key);

}  // namespace securebridge

#endif
