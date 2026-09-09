#include "openssl_utils.hpp"

#include <openssl/err.h>

#include <array>
#include <sstream>

namespace securebridge {

std::string openssl_error(const std::string& context) {
    std::ostringstream message;
    message << context;

    bool has_error = false;
    unsigned long code = 0;
    while ((code = ERR_get_error()) != 0) {
        std::array<char, 256> buffer{};
        ERR_error_string_n(code, buffer.data(), buffer.size());
        message << (has_error ? " | " : ": ") << buffer.data();
        has_error = true;
    }

    return message.str();
}

}  // namespace securebridge
