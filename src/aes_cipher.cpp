#include "aes_cipher.hpp"

#include "openssl_utils.hpp"
#include "sha256.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <memory>
#include <stdexcept>

namespace securebridge {
namespace {

// Formato do arquivo AES:
// [assinatura de 8 bytes][nonce de 12 bytes][tag de 16 bytes][dados cifrados]
constexpr std::array<Byte, 8> kMagic = {'S', 'B', 'R', 'A', 'E', 'S', '1', 0};
constexpr std::size_t kKeySize = 32;
constexpr std::size_t kIvSize = 12;
constexpr std::size_t kTagSize = 16;
constexpr std::size_t kHeaderSize = kMagic.size() + kIvSize + kTagSize;

using CipherContextPtr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

void validate_key(const Bytes& key) {
    if (key.size() != kKeySize) {
        throw std::invalid_argument("A chave AES-256 deve possuir exatamente 32 bytes");
    }
}

void validate_input_size(std::size_t size) {
    if (size > static_cast<std::size_t>(INT_MAX)) {
        throw std::invalid_argument("Arquivo grande demais para esta versao do experimento AES");
    }
}

}  // namespace

Bytes derive_aes256_key(const std::string& passphrase) {
    if (passphrase.empty()) {
        throw std::invalid_argument("A frase-chave AES nao pode ser vazia");
    }

    // SHA-256 sempre produz os 32 bytes exigidos pelo AES-256.
    const Bytes passphrase_bytes(passphrase.begin(), passphrase.end());
    return sha256(passphrase_bytes);
}

Bytes aes256_gcm_encrypt(const Bytes& plaintext, const Bytes& key) {
    validate_key(key);
    validate_input_size(plaintext.size());

    // Cada cifragem recebe um nonce aleatorio novo. O nonce nao precisa ser secreto.
    std::array<Byte, kIvSize> iv{};
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        throw std::runtime_error(openssl_error("Falha ao gerar o nonce AES-GCM"));
    }

    CipherContextPtr context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) {
        throw std::runtime_error(openssl_error("Falha ao criar o contexto AES"));
    }

    if (EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr
        ) != 1 ||
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw std::runtime_error(openssl_error("Falha ao inicializar AES-256-GCM"));
    }

    Bytes ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int written = 0;
    int total = 0;

    if (!plaintext.empty() &&
        EVP_EncryptUpdate(
            context.get(),
            ciphertext.data(),
            &written,
            plaintext.data(),
            static_cast<int>(plaintext.size())
        ) != 1) {
        throw std::runtime_error(openssl_error("Falha ao cifrar com AES-256-GCM"));
    }
    total += written;

    if (EVP_EncryptFinal_ex(context.get(), ciphertext.data() + total, &written) != 1) {
        throw std::runtime_error(openssl_error("Falha ao finalizar AES-256-GCM"));
    }
    total += written;
    ciphertext.resize(static_cast<std::size_t>(total));

    // A tag permite detectar chave incorreta ou qualquer alteracao no arquivo.
    std::array<Byte, kTagSize> tag{};
    if (EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()
        ) != 1) {
        throw std::runtime_error(openssl_error("Falha ao obter a tag AES-GCM"));
    }

    Bytes result;
    result.reserve(kHeaderSize + ciphertext.size());
    result.insert(result.end(), kMagic.begin(), kMagic.end());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), tag.begin(), tag.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    return result;
}

Bytes aes256_gcm_decrypt(const Bytes& encrypted_file, const Bytes& key) {
    validate_key(key);
    if (encrypted_file.size() < kHeaderSize ||
        !std::equal(kMagic.begin(), kMagic.end(), encrypted_file.begin())) {
        throw std::invalid_argument("Arquivo invalido: cabecalho AES-GCM ausente");
    }

    // Separa o cabecalho dos bytes cifrados antes de chamar a OpenSSL.
    const Byte* iv = encrypted_file.data() + kMagic.size();
    std::array<Byte, kTagSize> tag{};
    std::copy_n(iv + kIvSize, kTagSize, tag.begin());
    const Byte* ciphertext = encrypted_file.data() + kHeaderSize;
    const std::size_t ciphertext_size = encrypted_file.size() - kHeaderSize;
    validate_input_size(ciphertext_size);

    CipherContextPtr context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) {
        throw std::runtime_error(openssl_error("Falha ao criar o contexto AES"));
    }

    if (EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kIvSize), nullptr
        ) != 1 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv) != 1) {
        throw std::runtime_error(openssl_error("Falha ao inicializar AES-256-GCM"));
    }

    Bytes plaintext(ciphertext_size + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int written = 0;
    int total = 0;

    if (ciphertext_size > 0 &&
        EVP_DecryptUpdate(
            context.get(),
            plaintext.data(),
            &written,
            ciphertext,
            static_cast<int>(ciphertext_size)
        ) != 1) {
        throw std::runtime_error(openssl_error("Falha ao decifrar com AES-256-GCM"));
    }
    total += written;

    if (EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()
        ) != 1) {
        throw std::runtime_error(openssl_error("Falha ao configurar a tag AES-GCM"));
    }

    // EVP_DecryptFinal_ex tambem verifica a autenticidade da tag GCM.
    if (EVP_DecryptFinal_ex(context.get(), plaintext.data() + total, &written) != 1) {
        throw std::runtime_error(
            "Falha de autenticacao AES-GCM: chave incorreta ou arquivo alterado"
        );
    }

    total += written;
    plaintext.resize(static_cast<std::size_t>(total));
    return plaintext;
}

}  // namespace securebridge
