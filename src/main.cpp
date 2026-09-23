#include "aes_cipher.hpp"
#include "affinetrans.hpp"
#include "file_utils.hpp"
#include "rsa_cipher.hpp"
#include "sha256.hpp"

#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

using Clock = std::chrono::steady_clock;
using securebridge::Bytes;

enum class Algorithm {
    AffineTrans,
    Aes,
    Rsa
};

// Mantem juntos o resultado de uma operacao e o tempo gasto por ela.
struct TimedResult {
    Bytes data;
    double milliseconds{};
};

double elapsed_ms(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

Algorithm parse_algorithm(const std::string& value) {
    if (value == "affinetrans") {
        return Algorithm::AffineTrans;
    } else if (value == "aes") {
        return Algorithm::Aes;
    } else if (value == "rsa") {
        return Algorithm::Rsa;
    } else {
        throw std::invalid_argument("Algoritmo desconhecido: " + value);
    }
}

const char* algorithm_name(Algorithm algorithm) {
    switch (algorithm) {
        case Algorithm::AffineTrans:
            return "AffineTrans";
        case Algorithm::Aes:
            return "AES-256-GCM";
        case Algorithm::Rsa:
            return "RSA-2048-OAEP-SHA256";
    }

    return "Desconhecido";
}

std::filesystem::path normalized_absolute(const std::filesystem::path& path) {
    return std::filesystem::absolute(path).lexically_normal();
}

void require_distinct_paths(
    const std::filesystem::path& first,
    const std::filesystem::path& second
) {
    if (normalized_absolute(first) == normalized_absolute(second)) {
        throw std::invalid_argument("Os arquivos de entrada e saida devem ser diferentes");
    }
}

void print_usage(const char* program) {
    std::cerr
        << "Uso:\n"
        << "  " << program << " keygen-rsa <privada.pem> <publica.pem> [bits]\n\n"
        << "  " << program
        << " encrypt <affinetrans|aes|rsa> <entrada> <saida> --key <chave>\n"
        << "  " << program
        << " decrypt <affinetrans|aes|rsa> <entrada> <saida> --key <chave>\n\n"
        << "Para AffineTrans/AES, <chave> e uma frase-chave.\n"
        << "Para RSA, <chave> e o caminho da chave publica ao cifrar\n"
        << "e da chave privada ao decifrar.\n\n"
        << "  " << program
        << " simulate <affinetrans|aes> <entrada> <cifrado> <recuperado>"
           " --key <frase-chave>\n"
        << "  " << program
        << " simulate rsa <entrada> <cifrado> <recuperado>"
           " --public <publica.pem> --private <privada.pem>\n";
}

TimedResult encrypt_data(
    Algorithm algorithm,
    const Bytes& plaintext,
    const std::string& key_argument
) {
    if (algorithm == Algorithm::AffineTrans) {
        // A derivacao da chave fica fora da medicao para comparar apenas a cifra.
        const auto key = securebridge::derive_affinetrans_key(key_argument);
        const auto start = Clock::now();
        Bytes output = securebridge::affinetrans_encrypt(plaintext, key);
        const auto end = Clock::now();
        return {std::move(output), elapsed_ms(start, end)};
    }

    if (algorithm == Algorithm::Aes) {
        // A frase-chave e convertida em 256 bits por SHA-256.
        const Bytes key = securebridge::derive_aes256_key(key_argument);
        const auto start = Clock::now();
        Bytes output = securebridge::aes256_gcm_encrypt(plaintext, key);
        const auto end = Clock::now();
        return {std::move(output), elapsed_ms(start, end)};
    }

    // Para RSA, key_argument indica o arquivo da chave publica.
    auto key = securebridge::load_rsa_public_key(key_argument);
    const auto start = Clock::now();
    Bytes output = securebridge::rsa_oaep_encrypt_blocks(plaintext, key.get());
    const auto end = Clock::now();
    return {std::move(output), elapsed_ms(start, end)};
}

TimedResult decrypt_data(
    Algorithm algorithm,
    const Bytes& ciphertext,
    const std::string& key_argument
) {
    if (algorithm == Algorithm::AffineTrans) {
        const auto key = securebridge::derive_affinetrans_key(key_argument);
        const auto start = Clock::now();
        Bytes output = securebridge::affinetrans_decrypt(ciphertext, key);
        const auto end = Clock::now();
        return {std::move(output), elapsed_ms(start, end)};
    }

    if (algorithm == Algorithm::Aes) {
        const Bytes key = securebridge::derive_aes256_key(key_argument);
        const auto start = Clock::now();
        Bytes output = securebridge::aes256_gcm_decrypt(ciphertext, key);
        const auto end = Clock::now();
        return {std::move(output), elapsed_ms(start, end)};
    }

    // Para RSA, key_argument indica o arquivo da chave privada.
    auto key = securebridge::load_rsa_private_key(key_argument);
    const auto start = Clock::now();
    Bytes output = securebridge::rsa_oaep_decrypt_blocks(ciphertext, key.get());
    const auto end = Clock::now();
    return {std::move(output), elapsed_ms(start, end)};
}

void run_file_operation(
    bool encrypt,
    Algorithm algorithm,
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_path,
    const std::string& key_argument
) {
    require_distinct_paths(input_path, output_path);
    const Bytes input = securebridge::read_binary_file(input_path);

    TimedResult result;
    if (encrypt) {
        result = encrypt_data(algorithm, input, key_argument);
    } else {
        result = decrypt_data(algorithm, input, key_argument);
    }

    securebridge::write_binary_file(output_path, result.data);
    std::cout << (encrypt ? "Cifragem" : "Decifragem") << " concluida\n"
              << "Algoritmo: " << algorithm_name(algorithm) << '\n'
              << "Entrada:   " << input.size() << " bytes\n"
              << "Saida:     " << result.data.size() << " bytes\n"
              << std::fixed << std::setprecision(6)
              << "Tempo:     " << result.milliseconds << " ms\n";
}

void print_simulation_result(
    Algorithm algorithm,
    const std::filesystem::path& input_path,
    const Bytes& original,
    const Bytes& encrypted,
    const Bytes& recovered,
    double encryption_ms,
    double decryption_ms
) {
    const std::string original_hash = securebridge::sha256_hex(original);
    const std::string recovered_hash = securebridge::sha256_hex(recovered);

    // A comparacao direta e o SHA-256 confirmam que o arquivo foi recuperado.
    const bool valid = original == recovered && original_hash == recovered_hash;

    std::cout << "==============================================\n"
              << " SECUREBRIDGE - SIMULACAO DE TRANSMISSAO\n"
              << "==============================================\n"
              << "Arquivo original:  " << input_path << '\n'
              << "Tamanho original:  " << original.size() << " bytes\n"
              << "Algoritmo:         " << algorithm_name(algorithm) << "\n\n"
              << "Amostra interceptada:\n"
              << securebridge::bytes_to_hex(encrypted) << "\n\n"
              << std::fixed << std::setprecision(6)
              << "Tempo de cifragem:   " << encryption_ms << " ms\n"
              << "Tempo de decifragem: " << decryption_ms << " ms\n\n"
              << "SHA-256 original:   " << original_hash << '\n'
              << "SHA-256 recuperado: " << recovered_hash << '\n'
              << "Integridade:        " << (valid ? "VALIDA" : "FALHOU") << '\n';

    if (!valid) {
        throw std::runtime_error("O arquivo recuperado difere do original");
    }
}

void simulate_symmetric(
    Algorithm algorithm,
    const std::filesystem::path& input_path,
    const std::filesystem::path& encrypted_path,
    const std::filesystem::path& recovered_path,
    const std::string& passphrase
) {
    require_distinct_paths(input_path, encrypted_path);
    require_distinct_paths(input_path, recovered_path);
    require_distinct_paths(encrypted_path, recovered_path);

    const Bytes original = securebridge::read_binary_file(input_path);
    const TimedResult encrypted = encrypt_data(algorithm, original, passphrase);
    const TimedResult recovered = decrypt_data(algorithm, encrypted.data, passphrase);

    securebridge::write_binary_file(encrypted_path, encrypted.data);
    securebridge::write_binary_file(recovered_path, recovered.data);
    print_simulation_result(
        algorithm,
        input_path,
        original,
        encrypted.data,
        recovered.data,
        encrypted.milliseconds,
        recovered.milliseconds
    );
}

void simulate_rsa(
    const std::filesystem::path& input_path,
    const std::filesystem::path& encrypted_path,
    const std::filesystem::path& recovered_path,
    const std::filesystem::path& public_key_path,
    const std::filesystem::path& private_key_path
) {
    require_distinct_paths(input_path, encrypted_path);
    require_distinct_paths(input_path, recovered_path);
    require_distinct_paths(encrypted_path, recovered_path);

    const Bytes original = securebridge::read_binary_file(input_path);
    auto public_key = securebridge::load_rsa_public_key(public_key_path);
    auto private_key = securebridge::load_rsa_private_key(private_key_path);

    const auto encryption_start = Clock::now();
    Bytes encrypted = securebridge::rsa_oaep_encrypt_blocks(original, public_key.get());
    const auto encryption_end = Clock::now();

    const auto decryption_start = Clock::now();
    Bytes recovered = securebridge::rsa_oaep_decrypt_blocks(encrypted, private_key.get());
    const auto decryption_end = Clock::now();

    securebridge::write_binary_file(encrypted_path, encrypted);
    securebridge::write_binary_file(recovered_path, recovered);
    print_simulation_result(
        Algorithm::Rsa,
        input_path,
        original,
        encrypted,
        recovered,
        elapsed_ms(encryption_start, encryption_end),
        elapsed_ms(decryption_start, decryption_end)
    );
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            print_usage(argv[0]);
            return 1;
        }

        const std::string command = argv[1];

        // Gera o par de chaves usado pelos comandos RSA.
        if (command == "keygen-rsa" && (argc == 4 || argc == 5)) {
            const int bits = argc == 5 ? std::stoi(argv[4]) : 2048;
            securebridge::generate_rsa_keypair(argv[2], argv[3], bits);
            std::cout << "Par de chaves RSA gerado com " << bits << " bits.\n"
                      << "Privada: " << argv[2] << '\n'
                      << "Publica: " << argv[3] << '\n';
            return 0;
        }

        // Executa apenas uma operacao de cifragem ou decifragem.
        if ((command == "encrypt" || command == "decrypt") &&
            argc == 7 &&
            std::string(argv[5]) == "--key") {
            run_file_operation(
                command == "encrypt",
                parse_algorithm(argv[2]),
                argv[3],
                argv[4],
                argv[6]
            );
            return 0;
        }

        // Simula o ciclo completo para as cifras baseadas em frase-chave.
        if (command == "simulate" && argc == 8 &&
            std::string(argv[6]) == "--key") {
            const Algorithm algorithm = parse_algorithm(argv[2]);
            if (algorithm == Algorithm::Rsa) {
                throw std::invalid_argument("A simulacao RSA exige --public e --private");
            }
            simulate_symmetric(algorithm, argv[3], argv[4], argv[5], argv[7]);
            return 0;
        }

        // RSA usa arquivos diferentes para a chave publica e a privada.
        if (command == "simulate" && argc == 10 &&
            std::string(argv[2]) == "rsa" &&
            std::string(argv[6]) == "--public" &&
            std::string(argv[8]) == "--private") {
            simulate_rsa(argv[3], argv[4], argv[5], argv[7], argv[9]);
            return 0;
        }

        print_usage(argv[0]);
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "Erro: " << error.what() << '\n';
        return 2;
    }
}
