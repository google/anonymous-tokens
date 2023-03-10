#ifndef ANONYMOUS_TOKENS_CPP_CRYPTO_BLINDER_H_
#define ANONYMOUS_TOKENS_CPP_CRYPTO_BLINDER_H_

#include <string>

#include "absl/status/statusor.h"


namespace anonymous_tokens {

class Blinder {
 public:
  enum class BlinderState { kCreated = 0, kBlinded, kUnblinded };
  virtual absl::StatusOr<std::string> Blind(absl::string_view message) = 0;

  virtual absl::StatusOr<std::string> Unblind(
      absl::string_view blind_signature) = 0;

  virtual ~Blinder() = default;
};

}  // namespace anonymous_tokens

#endif  // ANONYMOUS_TOKENS_CPP_CRYPTO_BLINDER_H_
