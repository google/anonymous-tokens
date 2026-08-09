// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "anonymous_tokens/cpp/privacy_pass/athm_token_encodings.h"

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "anonymous_tokens/cpp/privacy_pass/athm_token_encodings_utils.h"
#include "anonymous_tokens/cpp/shared/status_utils.h"

namespace anonymous_tokens {

absl::StatusOr<std::string> MarshalAthmToken(const AthmToken& token) {
  std::string encoded_token;
  ANON_TOKENS_RETURN_IF_ERROR(MarshalAthmToken(token, &encoded_token));
  return encoded_token;
}

absl::StatusOr<AthmToken> UnmarshalAthmToken(absl::string_view athm_token_str) {
  AthmToken out;
  ANON_TOKENS_RETURN_IF_ERROR(UnmarshalAthmToken(athm_token_str, &out));
  return out;
}

absl::StatusOr<std::string> MarshalAthmTokenRequest(
    const AthmTokenRequest& athm_token_request) {
  std::string encoded_token_request;
  ANON_TOKENS_RETURN_IF_ERROR(
      MarshalAthmTokenRequest(athm_token_request, &encoded_token_request));
  return encoded_token_request;
}

absl::StatusOr<AthmTokenRequest> UnmarshalAthmTokenRequest(
    absl::string_view athm_token_request_str) {
  AthmTokenRequest out;
  ANON_TOKENS_RETURN_IF_ERROR(
      UnmarshalAthmTokenRequest(athm_token_request_str, &out));
  return out;
}

}  // namespace anonymous_tokens
