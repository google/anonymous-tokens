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

#ifndef ANONYMOUS_TOKENS_CPP_PRIVACY_PASS_ATHM_TOKEN_ENCODINGS_H_
#define ANONYMOUS_TOKENS_CPP_PRIVACY_PASS_ATHM_TOKEN_ENCODINGS_H_

#include <stdint.h>

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace anonymous_tokens {

// The structs and constants are defined using the following specification:
// https://github.com/cathieyun/draft-athm/blob/main/draft-yun-privacypass-athm.md

constexpr int kAthmEncodedRequestSizeInBytes33 = 33;

constexpr int kAthmTokenSizeInBytes98 = 98;

constexpr int kAthmTokenTypeSizeInBytes2 = 2;

constexpr int kAthmTruncatedIssuerKeyIdSizeInBytes1 = 1;

constexpr int kAthmIssuerKeyIdSizeInBytes32 = 32;

struct AthmTokenRequest {
  uint16_t token_type{0xC07E}; /* Type ATHM(P-256) */
  uint8_t truncated_issuer_key_id;
  std::string encoded_request;
};

struct AthmToken {
  uint16_t token_type{0xC07E}; /* Type ATHM(P-256) */
  std::string issuer_key_id;
  std::string token;
};

// This methods takes in a AthmToken structure and encodes it into a string.
absl::StatusOr<std::string> MarshalAthmToken(const AthmToken& athm_token);

// This methods takes in an encoded AthmToken and decodes it into a AthmToken
// struct.
absl::StatusOr<AthmToken> UnmarshalAthmToken(absl::string_view athm_token_str);

// This method takes in a AthmTokenRequest structure and encodes it into a
// string.
absl::StatusOr<std::string> MarshalAthmTokenRequest(
    const AthmTokenRequest& athm_token_request);

// This methods takes in an encoded AthmTokenRequest and decodes it into a
// AthmTokenRequest struct.
absl::StatusOr<AthmTokenRequest> UnmarshalAthmTokenRequest(
    absl::string_view athm_token_request_str);

}  // namespace anonymous_tokens

#endif  // ANONYMOUS_TOKENS_CPP_PRIVACY_PASS_TOKEN_ENCODINGS_H_
