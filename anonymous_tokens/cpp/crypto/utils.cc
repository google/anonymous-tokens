#include "anonymous_tokens/cpp/crypto/utils.h"

#include <string>

#include "absl/strings/str_cat.h"


namespace anonymous_tokens {

std::string MaskMessageConcat(absl::string_view mask,
                              absl::string_view message) {
  return absl::StrCat(mask, message);
}

}  // namespace anonymous_tokens

