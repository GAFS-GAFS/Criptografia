#include "file_utils.hpp"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace securebridge {

Bytes read_binary_file(const std::filesystem::path& path) {
    // Abrir no fim permite descobrir o tamanho antes de alocar o vetor.
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw std::runtime_error("Nao foi possivel abrir o arquivo: " + path.string());
    }

    const std::streamsize size = input.tellg();
    if (size < 0) {
        throw std::runtime_error("Nao foi possivel determinar o tamanho: " + path.string());
    }

    input.seekg(0, std::ios::beg);
    Bytes data(static_cast<std::size_t>(size));
    if (size > 0 && !input.read(reinterpret_cast<char*>(data.data()), size)) {
        throw std::runtime_error("Falha ao ler o arquivo: " + path.string());
    }

    return data;
}

void write_binary_file(const std::filesystem::path& path, const Bytes& data) {
    // Cria a arvore de diretorios somente quando ela foi informada no caminho.
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }

    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("Nao foi possivel criar o arquivo: " + path.string());
    }

    if (!data.empty()) {
        output.write(
            reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size())
        );
    }

    if (!output) {
        throw std::runtime_error("Falha ao escrever o arquivo: " + path.string());
    }
}

std::string bytes_to_hex(const Bytes& data, std::size_t limit) {
    std::ostringstream result;
    result << std::hex << std::uppercase << std::setfill('0');

    const std::size_t count = std::min(data.size(), limit);
    for (std::size_t i = 0; i < count; ++i) {
        if (i != 0) {
            result << ' ';
        }
        result << std::setw(2) << static_cast<unsigned int>(data[i]);
    }

    if (data.size() > count) {
        result << " ...";
    }
    return result.str();
}

}  // namespace securebridge
