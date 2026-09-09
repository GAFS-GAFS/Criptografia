#ifndef SECUREBRIDGE_RSA_CIPHER_HPP
#define SECUREBRIDGE_RSA_CIPHER_HPP

#include "types.hpp"

#include <openssl/evp.h>

#include <cstddef>
#include <filesystem>
#include <memory>

namespace securebridge {

using RsaKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

void generate_rsa_keypair(
    const std::filesystem::path& private_key_path,
    const std::filesystem::path& public_key_path,
    int bits = 2048
);

RsaKeyPtr load_rsa_public_key(const std::filesystem::path& path);
RsaKeyPtr load_rsa_private_key(const std::filesystem::path& path);

std::size_t rsa_oaep_max_plaintext_size(EVP_PKEY* key);
Bytes rsa_oaep_encrypt_blocks(const Bytes& plaintext, EVP_PKEY* public_key);
Bytes rsa_oaep_decrypt_blocks(const Bytes& encrypted_file, EVP_PKEY* private_key);

}  // namespace securebridge

#endif
