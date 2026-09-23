#include "affinetrans.hpp"

#include "sha256.hpp"

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <stdexcept>

namespace securebridge {
namespace {

constexpr std::uint16_t kByteModulus = 256;

// Calcula o inverso de "value" no modulo 256 pelo algoritmo de Euclides.
Byte modular_inverse(Byte value) {
    int old_r = value;
    int r = kByteModulus;
    int old_s = 1;
    int s = 0;

    while (r != 0) {
        const int quotient = old_r / r;

        const int next_r = old_r - quotient * r;
        old_r = r;
        r = next_r;

        const int next_s = old_s - quotient * s;
        old_s = s;
        s = next_s;
    }

    if (old_r != 1) {
        throw std::invalid_argument(
            "O multiplicador da AffineTrans deve ser coprimo com 256"
        );
    }

    const int normalized = (old_s % kByteModulus + kByteModulus) % kByteModulus;
    return static_cast<Byte>(normalized);
}

void validate_key(const AffineTransKey& key) {
    const std::size_t block_size = key.transposition.size();

    if (block_size < 2 || block_size > 255) {
        throw std::invalid_argument("O tamanho do bloco deve estar entre 2 e 255");
    }

    if ((key.multiplier & 1U) == 0U) {
        throw std::invalid_argument("O multiplicador da AffineTrans deve ser impar");
    }

    std::vector<bool> seen(block_size, false);
    for (const std::size_t position : key.transposition) {
        if (position >= block_size || seen[position]) {
            throw std::invalid_argument("A transposicao da chave nao e uma permutacao valida");
        }
        seen[position] = true;
    }
}

std::uint64_t seed_from_digest(const Bytes& digest) {
    std::uint64_t seed = 0;
    for (std::size_t i = 0; i < sizeof(seed); ++i) {
        seed = (seed << 8U) | digest[i];
    }
    return seed == 0 ? 0x9E3779B97F4A7C15ULL : seed;
}

std::uint64_t xorshift64(std::uint64_t& state) {
    state ^= state << 13U;
    state ^= state >> 7U;
    state ^= state << 17U;
    return state;
}

Bytes add_padding(const Bytes& input, std::size_t block_size) {
    // Preenchimento no estilo PKCS#7: cada byte guarda o tamanho adicionado.
    const std::size_t padding_size = block_size - (input.size() % block_size);
    Bytes padded = input;
    padded.insert(
        padded.end(),
        padding_size,
        static_cast<Byte>(padding_size)
    );
    return padded;
}

void remove_padding(Bytes& data, std::size_t block_size) {
    if (data.empty()) {
        throw std::runtime_error("Dados decifrados vazios ou corrompidos");
    }

    const std::size_t padding_size = data.back();
    if (padding_size == 0 || padding_size > block_size || padding_size > data.size()) {
        throw std::runtime_error("Preenchimento invalido: chave incorreta ou arquivo corrompido");
    }

    const auto padding_begin = data.end() - static_cast<std::ptrdiff_t>(padding_size);
    if (!std::all_of(padding_begin, data.end(), [padding_size](Byte value) {
            return value == static_cast<Byte>(padding_size);
        })) {
        throw std::runtime_error("Preenchimento invalido: chave incorreta ou arquivo corrompido");
    }

    data.erase(padding_begin, data.end());
}

}  // namespace

AffineTransKey derive_affinetrans_key(
    const std::string& passphrase,
    std::size_t block_size
) {
    if (passphrase.empty()) {
        throw std::invalid_argument("A frase-chave nao pode ser vazia");
    }
    if (block_size < 2 || block_size > 255) {
        throw std::invalid_argument("O tamanho do bloco deve estar entre 2 e 255");
    }

    const Bytes passphrase_bytes(passphrase.begin(), passphrase.end());
    const Bytes digest = sha256(passphrase_bytes);

    AffineTransKey key;
    key.multiplier = static_cast<Byte>(digest[0] | 1U);
    if (key.multiplier == 1U) {
        key.multiplier = 3U;
    }
    key.offset = digest[1];

    // Comeca com a ordem natural e a embaralha de forma deterministica.
    key.transposition.resize(block_size);
    std::iota(key.transposition.begin(), key.transposition.end(), 0);

    std::uint64_t state = seed_from_digest(digest);
    for (std::size_t i = block_size - 1; i > 0; --i) {
        const std::size_t selected = xorshift64(state) % (i + 1);
        std::swap(key.transposition[i], key.transposition[selected]);
    }

    validate_key(key);
    return key;
}

Bytes affinetrans_encrypt(const Bytes& plaintext, const AffineTransKey& key) {
    validate_key(key);
    const std::size_t block_size = key.transposition.size();
    Bytes substituted = add_padding(plaintext, block_size);

    // Etapa 1: substituicao afim de cada byte: (a*x + b) mod 256.
    for (Byte& value : substituted) {
        const std::uint16_t transformed =
            static_cast<std::uint16_t>(key.multiplier) * value + key.offset;
        value = static_cast<Byte>(transformed % kByteModulus);
    }

    // Etapa 2: reorganizacao das posicoes dentro de cada bloco.
    Bytes ciphertext(substituted.size());
    for (std::size_t block = 0; block < substituted.size(); block += block_size) {
        for (std::size_t output_position = 0;
             output_position < block_size;
             ++output_position) {
            const std::size_t input_position = key.transposition[output_position];
            ciphertext[block + output_position] = substituted[block + input_position];
        }
    }

    return ciphertext;
}

Bytes affinetrans_decrypt(const Bytes& ciphertext, const AffineTransKey& key) {
    validate_key(key);
    const std::size_t block_size = key.transposition.size();

    if (ciphertext.empty() || ciphertext.size() % block_size != 0) {
        throw std::invalid_argument(
            "O arquivo cifrado deve possuir blocos completos da AffineTrans"
        );
    }

    // Desfaz primeiro a transposicao, recolocando cada byte em sua posicao.
    Bytes substituted(ciphertext.size());
    for (std::size_t block = 0; block < ciphertext.size(); block += block_size) {
        for (std::size_t input_position = 0;
             input_position < block_size;
             ++input_position) {
            const std::size_t original_position = key.transposition[input_position];
            substituted[block + original_position] = ciphertext[block + input_position];
        }
    }

    const Byte inverse = modular_inverse(key.multiplier);
    Bytes plaintext(substituted.size());

    // Aplica a operacao inversa: a^-1 * (y - b) mod 256.
    for (std::size_t i = 0; i < substituted.size(); ++i) {
        const int difference = static_cast<int>(substituted[i]) - key.offset;
        const int normalized = (difference % kByteModulus + kByteModulus) % kByteModulus;
        plaintext[i] = static_cast<Byte>(
            (static_cast<std::uint16_t>(inverse) * normalized) % kByteModulus
        );
    }

    remove_padding(plaintext, block_size);
    return plaintext;
}

}  // namespace securebridge
