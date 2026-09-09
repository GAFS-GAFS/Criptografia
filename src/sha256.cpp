#include "sha256.hpp"

#include <openssl/evp.h>

#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace securebridge {

Bytes sha256(const Bytes& data) {
    using ContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    ContextPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!context) {
        throw std::runtime_error("OpenSSL nao conseguiu criar o contexto SHA-256");
    }

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("Falha ao inicializar SHA-256");
    }

    if (!data.empty() && EVP_DigestUpdate(context.get(), data.data(), data.size()) != 1) {
        throw std::runtime_error("Falha ao processar SHA-256");
    }

    Bytes digest(EVP_MAX_MD_SIZE);
    unsigned int digest_size = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1) {
        throw std::runtime_error("Falha ao finalizar SHA-256");
    }

    digest.resize(digest_size);
    return digest;
}

std::string sha256_hex(const Bytes& data) {
    const Bytes digest = sha256(data);
    std::ostringstream result;
    result << std::hex << std::setfill('0');
    for (const Byte value : digest) {
        result << std::setw(2) << static_cast<unsigned int>(value);
    }
    return result.str();
}

}  // namespace securebridge
