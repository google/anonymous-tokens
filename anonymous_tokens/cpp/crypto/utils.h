#ifndef ANONYMOUS_TOKENS_CPP_CRYPTO_UTILS_H_
#define ANONYMOUS_TOKENS_CPP_CRYPTO_UTILS_H_

#include <string>

#include "absl/strings/string_view.h"


namespace anonymous_tokens {

// Mask message using protocol at
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-blind-signatures/
std::string MaskMessageConcat(absl::string_view mask,
                              absl::string_view message);

}  // namespace anonymous_tokens


#endif  // ANONYMOUS_TOKENS_CPP_CRYPTO_UTILS_H_
