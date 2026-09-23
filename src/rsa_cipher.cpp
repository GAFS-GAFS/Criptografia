#include "rsa_cipher.hpp"

#include "openssl_utils.hpp"

#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>

namespace securebridge {
namespace {

// Formato do arquivo RSA:
// [assinatura de 8 bytes][tamanho do bloco em 4 bytes]
// [tamanho original em 8 bytes][blocos RSA-OAEP]
constexpr std::array<Byte, 8> kMagic = {'S', 'B', 'R', 'R', 'S', 'A', '1', 0};
constexpr std::size_t kHeaderSize = kMagic.size() + 4 + 8;
constexpr std::size_t kSha256Size = 32;

using PkeyContextPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

void append_u32(Bytes& output, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        output.push_back(static_cast<Byte>((value >> shift) & 0xFFU));
    }
}

void append_u64(Bytes& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<Byte>((value >> shift) & 0xFFU));
    }
}

std::uint32_t read_u32(const Byte* input) {
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
        value = (value << 8U) | input[i];
    }
    return value;
}

std::uint64_t read_u64(const Byte* input) {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8U) | input[i];
    }
    return value;
}

void validate_rsa_key(EVP_PKEY* key) {
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
        throw std::invalid_argument("A chave informada nao e uma chave RSA valida");
    }
}

PkeyContextPtr create_oaep_context(EVP_PKEY* key, bool encrypt) {
    validate_rsa_key(key);
    PkeyContextPtr context(EVP_PKEY_CTX_new(key, nullptr), EVP_PKEY_CTX_free);
    if (!context) {
        throw std::runtime_error(openssl_error("Falha ao criar o contexto RSA"));
    }

    const int initialization_result =
        encrypt ? EVP_PKEY_encrypt_init(context.get()) : EVP_PKEY_decrypt_init(context.get());

    // OAEP e MGF1 usam SHA-256 nos dois sentidos da operacao.
    if (initialization_result <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(context.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(context.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(context.get(), EVP_sha256()) <= 0) {
        throw std::runtime_error(openssl_error("Falha ao configurar RSA-OAEP com SHA-256"));
    }

    return context;
}

}  // namespace

void generate_rsa_keypair(
    const std::filesystem::path& private_key_path,
    const std::filesystem::path& public_key_path,
    int bits
) {
    if (bits < 2048) {
        throw std::invalid_argument("O tamanho minimo permitido para a chave RSA e 2048 bits");
    }

    PkeyContextPtr context(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if (!context || EVP_PKEY_keygen_init(context.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), bits) <= 0) {
        throw std::runtime_error(openssl_error("Falha ao inicializar a geracao da chave RSA"));
    }

    EVP_PKEY* raw_key = nullptr;
    if (EVP_PKEY_keygen(context.get(), &raw_key) <= 0) {
        throw std::runtime_error(openssl_error("Falha ao gerar a chave RSA"));
    }
    RsaKeyPtr key(raw_key, EVP_PKEY_free);

    // As pastas sao criadas apenas quando fazem parte do caminho recebido.
    if (private_key_path.has_parent_path()) {
        std::filesystem::create_directories(private_key_path.parent_path());
    }
    if (public_key_path.has_parent_path()) {
        std::filesystem::create_directories(public_key_path.parent_path());
    }

    BioPtr private_file(
        BIO_new_file(private_key_path.string().c_str(), "w"),
        BIO_free
    );
    if (!private_file ||
        PEM_write_bio_PrivateKey(
            private_file.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr
        ) != 1) {
        throw std::runtime_error(openssl_error("Falha ao gravar a chave privada RSA"));
    }

    BioPtr public_file(BIO_new_file(public_key_path.string().c_str(), "w"), BIO_free);
    if (!public_file || PEM_write_bio_PUBKEY(public_file.get(), key.get()) != 1) {
        throw std::runtime_error(openssl_error("Falha ao gravar a chave publica RSA"));
    }
}

RsaKeyPtr load_rsa_public_key(const std::filesystem::path& path) {
    BioPtr file(BIO_new_file(path.string().c_str(), "r"), BIO_free);
    if (!file) {
        throw std::runtime_error(openssl_error("Nao foi possivel abrir a chave publica RSA"));
    }

    EVP_PKEY* raw_key = PEM_read_bio_PUBKEY(file.get(), nullptr, nullptr, nullptr);
    if (!raw_key) {
        throw std::runtime_error(openssl_error("Nao foi possivel ler a chave publica RSA"));
    }

    RsaKeyPtr key(raw_key, EVP_PKEY_free);
    validate_rsa_key(key.get());
    return key;
}

RsaKeyPtr load_rsa_private_key(const std::filesystem::path& path) {
    BioPtr file(BIO_new_file(path.string().c_str(), "r"), BIO_free);
    if (!file) {
        throw std::runtime_error(openssl_error("Nao foi possivel abrir a chave privada RSA"));
    }

    EVP_PKEY* raw_key = PEM_read_bio_PrivateKey(file.get(), nullptr, nullptr, nullptr);
    if (!raw_key) {
        throw std::runtime_error(openssl_error("Nao foi possivel ler a chave privada RSA"));
    }

    RsaKeyPtr key(raw_key, EVP_PKEY_free);
    validate_rsa_key(key.get());
    return key;
}

std::size_t rsa_oaep_max_plaintext_size(EVP_PKEY* key) {
    validate_rsa_key(key);
    const int rsa_size = EVP_PKEY_get_size(key);

    // Limite OAEP: tamanho da chave - 2*tamanho_do_hash - 2.
    const int overhead = static_cast<int>(2 * kSha256Size + 2);
    if (rsa_size <= overhead) {
        throw std::invalid_argument("Chave RSA pequena demais para OAEP com SHA-256");
    }
    return static_cast<std::size_t>(rsa_size - overhead);
}

Bytes rsa_oaep_encrypt_blocks(const Bytes& plaintext, EVP_PKEY* public_key) {
    validate_rsa_key(public_key);
    const std::size_t rsa_size = static_cast<std::size_t>(EVP_PKEY_get_size(public_key));
    const std::size_t chunk_size = rsa_oaep_max_plaintext_size(public_key);
    const std::size_t block_count =
        plaintext.empty() ? 0 : (plaintext.size() + chunk_size - 1) / chunk_size;

    if (block_count > (std::numeric_limits<std::size_t>::max() - kHeaderSize) / rsa_size) {
        throw std::overflow_error("Arquivo grande demais para o formato RSA do experimento");
    }

    PkeyContextPtr context = create_oaep_context(public_key, true);
    Bytes result;
    result.reserve(kHeaderSize + block_count * rsa_size);
    result.insert(result.end(), kMagic.begin(), kMagic.end());
    append_u32(result, static_cast<std::uint32_t>(rsa_size));
    append_u64(result, static_cast<std::uint64_t>(plaintext.size()));

    // Cada trecho de texto gera exatamente um bloco do tamanho da chave RSA.
    for (std::size_t offset = 0; offset < plaintext.size(); offset += chunk_size) {
        const std::size_t current_size = std::min(chunk_size, plaintext.size() - offset);
        std::size_t encrypted_size = rsa_size;
        Bytes encrypted_block(encrypted_size);

        if (EVP_PKEY_encrypt(
                context.get(),
                encrypted_block.data(),
                &encrypted_size,
                plaintext.data() + offset,
                current_size
            ) <= 0) {
            throw std::runtime_error(openssl_error("Falha ao cifrar um bloco RSA-OAEP"));
        }

        encrypted_block.resize(encrypted_size);
        if (encrypted_block.size() != rsa_size) {
            throw std::runtime_error("A OpenSSL retornou um bloco RSA com tamanho inesperado");
        }
        result.insert(result.end(), encrypted_block.begin(), encrypted_block.end());
    }

    return result;
}

Bytes rsa_oaep_decrypt_blocks(const Bytes& encrypted_file, EVP_PKEY* private_key) {
    validate_rsa_key(private_key);
    if (encrypted_file.size() < kHeaderSize ||
        !std::equal(kMagic.begin(), kMagic.end(), encrypted_file.begin())) {
        throw std::invalid_argument("Arquivo invalido: cabecalho RSA-OAEP ausente");
    }

    const std::size_t stored_rsa_size = read_u32(encrypted_file.data() + kMagic.size());
    const std::uint64_t original_size =
        read_u64(encrypted_file.data() + kMagic.size() + 4);
    const std::size_t rsa_size = static_cast<std::size_t>(EVP_PKEY_get_size(private_key));

    if (stored_rsa_size != rsa_size || rsa_size == 0) {
        throw std::invalid_argument("O arquivo RSA nao corresponde ao tamanho da chave privada");
    }

    const std::size_t payload_size = encrypted_file.size() - kHeaderSize;
    if (payload_size % rsa_size != 0) {
        throw std::invalid_argument("Arquivo RSA truncado: existe um bloco incompleto");
    }

    // O cabecalho e a quantidade de blocos precisam descrever o mesmo arquivo.
    const std::size_t block_count = payload_size / rsa_size;
    const std::size_t max_chunk = rsa_oaep_max_plaintext_size(private_key);
    if (original_size > static_cast<std::uint64_t>(block_count * max_chunk) ||
        (original_size == 0 && block_count != 0) ||
        (original_size != 0 && block_count == 0)) {
        throw std::invalid_argument("Cabecalho RSA inconsistente com a quantidade de blocos");
    }

    PkeyContextPtr context = create_oaep_context(private_key, false);
    Bytes plaintext;
    plaintext.reserve(static_cast<std::size_t>(original_size));

    // Decifra os blocos em ordem e recompõe o arquivo original.
    for (std::size_t offset = kHeaderSize;
         offset < encrypted_file.size();
         offset += rsa_size) {
        std::size_t decrypted_size = rsa_size;
        Bytes decrypted_block(decrypted_size);

        if (EVP_PKEY_decrypt(
                context.get(),
                decrypted_block.data(),
                &decrypted_size,
                encrypted_file.data() + offset,
                rsa_size
            ) <= 0) {
            throw std::runtime_error(
                openssl_error("Falha ao decifrar RSA-OAEP: chave incorreta ou bloco alterado")
            );
        }

        decrypted_block.resize(decrypted_size);
        plaintext.insert(plaintext.end(), decrypted_block.begin(), decrypted_block.end());
    }

    if (plaintext.size() != original_size) {
        throw std::runtime_error("O tamanho recuperado por RSA difere do cabecalho do arquivo");
    }
    return plaintext;
}

}  // namespace securebridge
