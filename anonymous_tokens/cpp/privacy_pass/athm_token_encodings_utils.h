// Copyright 2026 Google LLC
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

#ifndef ANONYMOUS_TOKENS_CPP_PRIVACY_PASS_ATHM_TOKEN_ENCODINGS_UTILS_H_
#define ANONYMOUS_TOKENS_CPP_PRIVACY_PASS_ATHM_TOKEN_ENCODINGS_UTILS_H_

#include <stdint.h>

#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "anonymous_tokens/cpp/shared/status_utils.h"

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

// Encodes an AthmToken structure into a string `encoded_token`.
absl::Status MarshalAthmToken(const AthmToken& token,
                              std::string* encoded_token);

// Decodes an encoded AthmToken string into an AthmToken struct `out`.
absl::Status UnmarshalAthmToken(absl::string_view athm_token_str,
                                AthmToken* out);

// Encodes an AthmTokenRequest structure into a string `encoded_token_request`.
absl::Status MarshalAthmTokenRequest(const AthmTokenRequest& athm_token_request,
                                     std::string* encoded_token_request);

// Decodes an encoded AthmTokenRequest string into an AthmTokenRequest struct
// `out`.
absl::Status UnmarshalAthmTokenRequest(absl::string_view athm_token_request_str,
                                       AthmTokenRequest* out);

}  // namespace anonymous_tokens

#endif  // ANONYMOUS_TOKENS_CPP_PRIVACY_PASS_ATHM_TOKEN_ENCODINGS_UTILS_H_
