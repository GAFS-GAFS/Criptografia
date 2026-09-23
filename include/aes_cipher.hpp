#ifndef SECUREBRIDGE_AES_CIPHER_HPP
#define SECUREBRIDGE_AES_CIPHER_HPP

#include "types.hpp"

#include <string>

namespace securebridge {

// Gera uma chave AES-256 de 32 bytes a partir de uma frase-chave.
Bytes derive_aes256_key(const std::string& passphrase);

// O arquivo cifrado inclui cabecalho, nonce e tag de autenticacao GCM.
Bytes aes256_gcm_encrypt(const Bytes& plaintext, const Bytes& key);
Bytes aes256_gcm_decrypt(const Bytes& encrypted_file, const Bytes& key);

}  // namespace securebridge

#endif
