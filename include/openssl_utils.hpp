#ifndef SECUREBRIDGE_OPENSSL_UTILS_HPP
#define SECUREBRIDGE_OPENSSL_UTILS_HPP

#include <string>

namespace securebridge {

std::string openssl_error(const std::string& context);

}  // namespace securebridge

#endif
