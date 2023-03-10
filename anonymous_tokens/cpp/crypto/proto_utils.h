#ifndef ANONYMOUS_TOKENS_CPP_CRYPTO_PROTO_UTILS_H_
#define ANONYMOUS_TOKENS_CPP_CRYPTO_PROTO_UTILS_H_


#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "anonymous_tokens/proto/anonymous_tokens.pb.h"


namespace anonymous_tokens {

absl::StatusOr<AnonymousTokensUseCase> ParseUseCase(
    absl::string_view use_case);

// Timestamp is defined here:
// https://developers.google.com/protocol-buffers/docs/reference/google.protobuf#timestamp
absl::StatusOr<absl::Time> TimeFromProto(
    const Timestamp& proto);

// Timestamp is defined here:
// https://developers.google.com/protocol-buffers/docs/reference/google.protobuf#timestamp
absl::StatusOr<Timestamp> TimeToProto(absl::Time time);

}  // namespace anonymous_tokens


#endif  // ANONYMOUS_TOKENS_CPP_CRYPTO_PROTO_UTILS_H_
