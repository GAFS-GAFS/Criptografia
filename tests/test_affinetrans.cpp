#include "affinetrans.hpp"

#include <cassert>
#include <cstddef>
#include <iostream>
#include <string>

namespace {

void check_round_trip(const securebridge::Bytes& original, const std::string& passphrase) {
    const auto key = securebridge::derive_affinetrans_key(passphrase);
    const auto encrypted = securebridge::affinetrans_encrypt(original, key);
    const auto recovered = securebridge::affinetrans_decrypt(encrypted, key);

    assert(encrypted.size() % key.transposition.size() == 0);
    assert(recovered == original);
}

}  // namespace

int main() {
    check_round_trip({}, "chave-vazia");
    check_round_trip({0x41}, "chave-um-byte");

    for (const std::size_t size : {15U, 16U, 17U, 255U, 256U, 257U, 4097U}) {
        securebridge::Bytes data(size);
        for (std::size_t i = 0; i < data.size(); ++i) {
            data[i] = static_cast<securebridge::Byte>(i % 256U);
        }
        check_round_trip(data, "SecureBridge-2026");
    }

    std::cout << "Todos os testes AffineTrans passaram.\n";
    return 0;
}
