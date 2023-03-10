#include "anonymous_tokens/cpp/crypto/proto_utils.h"


namespace anonymous_tokens {

absl::StatusOr<AnonymousTokensUseCase> ParseUseCase(
    absl::string_view use_case) {
  AnonymousTokensUseCase parsed_use_case;
  if (!AnonymousTokensUseCase_Parse(std::string(use_case), &parsed_use_case) ||
      parsed_use_case == ANONYMOUS_TOKENS_USE_CASE_UNDEFINED) {
    return absl::InvalidArgumentError(
        "Invalid / undefined use case cannot be parsed.");
  }
  return parsed_use_case;
}

absl::StatusOr<absl::Time> TimeFromProto(
    const Timestamp& proto) {
  const auto sec = proto.seconds();
  const auto ns = proto.nanos();
  // sec must be [0001-01-01T00:00:00Z, 9999-12-31T23:59:59.999999999Z]
  if (sec < -62135596800 || sec > 253402300799) {
    return absl::InvalidArgumentError(absl::StrCat("seconds=", sec));
  }
  if (ns < 0 || ns > 999999999) {
    return absl::InvalidArgumentError(absl::StrCat("nanos=", ns));
  }
  return absl::FromUnixSeconds(proto.seconds()) +
         absl::Nanoseconds(proto.nanos());
}

absl::StatusOr<Timestamp> TimeToProto(absl::Time time) {
  Timestamp proto;
  const int64_t seconds = absl::ToUnixSeconds(time);
  proto.set_seconds(seconds);
  proto.set_nanos((time - absl::FromUnixSeconds(seconds)) /
                  absl::Nanoseconds(1));
  // seconds must be [0001-01-01T00:00:00Z, 9999-12-31T23:59:59.999999999Z]
  if (seconds < -62135596800 || seconds > 253402300799) {
    return absl::InvalidArgumentError(absl::StrCat("seconds=", seconds));
  }
  const int64_t ns = proto.nanos();
  if (ns < 0 || ns > 999999999) {
    return absl::InvalidArgumentError(absl::StrCat("nanos=", ns));
  }
  return proto;
}

}  // namespace anonymous_tokens

