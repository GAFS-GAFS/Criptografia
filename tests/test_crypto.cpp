#include "aes_cipher.hpp"
#include "rsa_cipher.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

securebridge::Bytes make_data(std::size_t size) {
    securebridge::Bytes data(size);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<securebridge::Byte>((i * 37U + 11U) % 256U);
    }
    return data;
}

void test_aes() {
    const auto key = securebridge::derive_aes256_key("AES-teste-2026");

    for (const std::size_t size : {0U, 1U, 15U, 16U, 17U, 255U, 4097U}) {
        const auto original = make_data(size);
        const auto encrypted = securebridge::aes256_gcm_encrypt(original, key);
        const auto recovered = securebridge::aes256_gcm_decrypt(encrypted, key);
        require(recovered == original, "AES nao recuperou os dados originais");
    }

    auto altered = securebridge::aes256_gcm_encrypt(make_data(128), key);
    altered.back() ^= 0x01U;
    bool rejected = false;
    try {
        static_cast<void>(securebridge::aes256_gcm_decrypt(altered, key));
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    require(rejected, "AES-GCM nao rejeitou um arquivo alterado");
}

void test_rsa() {
    const auto unique_id = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto temporary_directory = std::filesystem::temp_directory_path() /
        ("securebridge-test-" + std::to_string(unique_id));
    const auto private_key_path = temporary_directory / "private.pem";
    const auto public_key_path = temporary_directory / "public.pem";

    std::filesystem::create_directories(temporary_directory);
    try {
        securebridge::generate_rsa_keypair(private_key_path, public_key_path, 2048);
        auto public_key = securebridge::load_rsa_public_key(public_key_path);
        auto private_key = securebridge::load_rsa_private_key(private_key_path);

        require(
            securebridge::rsa_oaep_max_plaintext_size(public_key.get()) == 190,
            "O limite RSA-2048/OAEP-SHA256 deveria ser 190 bytes"
        );

        for (const std::size_t size : {0U, 1U, 189U, 190U, 191U, 500U, 4097U}) {
            const auto original = make_data(size);
            const auto encrypted =
                securebridge::rsa_oaep_encrypt_blocks(original, public_key.get());
            const auto recovered =
                securebridge::rsa_oaep_decrypt_blocks(encrypted, private_key.get());
            require(recovered == original, "RSA nao recuperou os dados originais");
        }

        auto altered = securebridge::rsa_oaep_encrypt_blocks(make_data(256), public_key.get());
        altered.back() ^= 0x01U;
        bool rejected = false;
        try {
            static_cast<void>(
                securebridge::rsa_oaep_decrypt_blocks(altered, private_key.get())
            );
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        require(rejected, "RSA-OAEP nao rejeitou um bloco alterado");
    } catch (...) {
        std::filesystem::remove_all(temporary_directory);
        throw;
    }

    std::filesystem::remove_all(temporary_directory);
}

}  // namespace

int main() {
    test_aes();
    test_rsa();
    std::cout << "Todos os testes AES e RSA passaram.\n";
    return 0;
}
