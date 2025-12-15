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

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include <openssl/base.h>
#include <openssl/bytestring.h>
#include <openssl/mem.h>

namespace anonymous_tokens {

absl::StatusOr<std::string> MarshalAthmToken(const AthmToken& token) {
  // Main CryptoByteBuilder object cbb which will be passed to CBB_finish to
  // finalize the output string.
  bssl::ScopedCBB cbb;
  // initial_capacity only serves as a hint.
  if (!CBB_init(cbb.get(), /*initial_capacity=*/kAthmTokenTypeSizeInBytes2 +
                               kAthmIssuerKeyIdSizeInBytes32 +
                               kAthmTokenSizeInBytes98)) {
    return absl::InternalError("CBB_init() failed.");
  }
  // Add token_type to cbb.
  if (!CBB_add_u16(cbb.get(), token.token_type) ||
      // Add issuer_key_id to cbb.
      !CBB_add_bytes(
          cbb.get(),
          reinterpret_cast<const uint8_t*>(token.issuer_key_id.data()),
          token.issuer_key_id.size()) ||
      // Add token to cbb.
      !CBB_add_bytes(cbb.get(),
                     reinterpret_cast<const uint8_t*>(token.token.data()),
                     token.token.size())) {
    return absl::InvalidArgumentError(
        "Could not construct cbb with given inputs.");
  }
  uint8_t* encoded_output;
  size_t encoded_output_len;
  if (!CBB_finish(cbb.get(), &encoded_output, &encoded_output_len)) {
    return absl::InvalidArgumentError(
        "Failed to generate token / token input encoding");
  }
  std::string encoded_output_str(reinterpret_cast<const char*>(encoded_output),
                                 encoded_output_len);
  // Free memory.
  OPENSSL_free(encoded_output);
  return encoded_output_str;
}

absl::StatusOr<AthmToken> UnmarshalAthmToken(absl::string_view athm_token_str) {
  AthmToken out;
  out.issuer_key_id.resize(kAthmIssuerKeyIdSizeInBytes32);
  out.token.resize(kAthmTokenSizeInBytes98);

  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(athm_token_str.data()),
           athm_token_str.size());
  if (!CBS_get_u16(&cbs, &out.token_type)) {
    return absl::InvalidArgumentError("failed to read token type");
  }
  if (out.token_type != 0xC07E) {
    return absl::InvalidArgumentError("unsupported token type");
  }
  if (!CBS_copy_bytes(&cbs,
                      reinterpret_cast<uint8_t*>(out.issuer_key_id.data()),
                      out.issuer_key_id.size())) {
    return absl::InvalidArgumentError("failed to read issuer_key_id");
  }
  if (!CBS_copy_bytes(&cbs, reinterpret_cast<uint8_t*>(out.token.data()),
                      out.token.size())) {
    return absl::InvalidArgumentError("failed to read token");
  }
  if (CBS_len(&cbs) != 0) {
    return absl::InvalidArgumentError("token had extra bytes");
  }
  return out;
}

absl::StatusOr<std::string> MarshalAthmTokenRequest(
    const AthmTokenRequest& athm_token_request) {
  // Main CryptoByteBuilder object cbb which will be passed to CBB_finish to
  // finalize the output string.
  bssl::ScopedCBB cbb;
  // initial_capacity only serves as a hint.
  if (!CBB_init(cbb.get(),
                /*initial_capacity=*/kAthmTokenTypeSizeInBytes2 +
                    kAthmTruncatedIssuerKeyIdSizeInBytes1 +
                    kAthmEncodedRequestSizeInBytes33)) {
    return absl::InternalError("CBB_init() failed.");
  }
  // Add token_type to cbb.
  if (!CBB_add_u16(cbb.get(), athm_token_request.token_type) ||
      // Add truncated_token_key_id to cbb.
      !CBB_add_u8(cbb.get(), athm_token_request.truncated_issuer_key_id) ||
      // Add blinded_token_request string to cbb.
      !CBB_add_bytes(cbb.get(),
                     reinterpret_cast<const uint8_t*>(
                         athm_token_request.encoded_request.data()),
                     athm_token_request.encoded_request.size())) {
    return absl::InvalidArgumentError(
        "Could not construct cbb with given inputs.");
  }

  uint8_t* encoded_output;
  size_t encoded_output_len;
  if (!CBB_finish(cbb.get(), &encoded_output, &encoded_output_len)) {
    return absl::InvalidArgumentError(
        "Failed to generate token request encoding");
  }
  std::string encoded_output_str(reinterpret_cast<const char*>(encoded_output),
                                 encoded_output_len);
  // Free memory.
  OPENSSL_free(encoded_output);
  return encoded_output_str;
}

absl::StatusOr<AthmTokenRequest> UnmarshalAthmTokenRequest(
    absl::string_view athm_token_request_str) {
  AthmTokenRequest out;
  out.encoded_request.resize(kAthmEncodedRequestSizeInBytes33);
  CBS cbs;
  CBS_init(&cbs,
           reinterpret_cast<const uint8_t*>(athm_token_request_str.data()),
           athm_token_request_str.size());
  if (!CBS_get_u16(&cbs, &out.token_type)) {
    return absl::InvalidArgumentError("failed to read token type");
  }
  if (out.token_type != 0xC07E) {
    return absl::InvalidArgumentError("unsupported token type");
  }
  if (!CBS_get_u8(&cbs, &out.truncated_issuer_key_id)) {
    return absl::InvalidArgumentError("failed to read truncated_issuer_key_id");
  }
  if (!CBS_copy_bytes(&cbs,
                      reinterpret_cast<uint8_t*>(out.encoded_request.data()),
                      out.encoded_request.size())) {
    return absl::InvalidArgumentError(
        "failed to read athm_token_request.encoded_request");
  }
  if (CBS_len(&cbs) != 0) {
    return absl::InvalidArgumentError("token request had extra bytes");
  }
  return out;
}

}  // namespace anonymous_tokens
