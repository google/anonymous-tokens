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

#include "anonymous_tokens/cpp/privacy_pass/token_encodings.h"

#include <sys/types.h>

#include <cstdint>
#include <ios>
#include <limits>
#include <optional>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "anonymous_tokens/cpp/shared/status_utils.h"
#include <openssl/base.h>
#include <openssl/bytestring.h>
#include <openssl/mem.h>


namespace anonymous_tokens {

namespace {

absl::StatusOr<std::string> EncodeTokenStructHelper(
    const uint16_t& token_type, const std::string& token_key_id,
    const std::string& nonce, const std::string& context,
    const std::optional<std::string> authenticator) {
  // Main CryptoByteBuilder object cbb which will be passed to CBB_finish to
  // finalize the output string.
  bssl::ScopedCBB cbb;
  // initial_capacity only serves as a hint.
  if (!CBB_init(cbb.get(), /*initial_capacity=*/98)) {
    return absl::InternalError("CBB_init() failed.");
  }
  // Add token_type to cbb.
  if (!CBB_add_u16(cbb.get(), token_type) ||
      // Add nonce to cbb.
      !CBB_add_bytes(cbb.get(), reinterpret_cast<const uint8_t*>(nonce.data()),
                     nonce.size()) ||
      // Add context string to cbb.
      !CBB_add_bytes(cbb.get(),
                     reinterpret_cast<const uint8_t*>(context.data()),
                     context.size()) ||
      // Add token_key_id to cbb.
      !CBB_add_bytes(cbb.get(),
                     reinterpret_cast<const uint8_t*>(token_key_id.data()),
                     token_key_id.size())) {
    return absl::InvalidArgumentError(
        "Could not construct cbb with given inputs.");
  }
  // Add authenticator to cbb.
  if (authenticator.has_value() &&
      !CBB_add_bytes(cbb.get(),
                     reinterpret_cast<const uint8_t*>(authenticator->data()),
                     authenticator->size())) {
    return absl::InvalidArgumentError("Could not add authenticator to cbb.");
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

// `extensions_cbs` may contain one or more encoded extensions in a row.
// This function only decodes the first extension from `extensions_cbs`. After
// this function is called `extensions_cbs` will point to the next extension
// after the one returned by decodeExtensions. If an error is returned,
// `extensions_cbs` may be in a partially read state - do not rely on it to
// parse more extensions.
absl::StatusOr<Extension> decodeExtension(CBS* extensions_cbs) {
  Extension ext;
  if (!CBS_get_u16(extensions_cbs, &ext.extension_type)) {
    return absl::InvalidArgumentError("failed to read next type.");
  }
  CBS extension_cbs;
  if (!CBS_get_u16_length_prefixed(extensions_cbs, &extension_cbs)) {
    return absl::InvalidArgumentError("failed to read extension value.");
  }
  ext.extension_value.resize(CBS_len(&extension_cbs));
  if (!CBS_copy_bytes(&extension_cbs,
                      reinterpret_cast<uint8_t*>(ext.extension_value.data()),
                      CBS_len(&extension_cbs))) {
    return absl::InvalidArgumentError("failed to read Extension value.");
  }
  return ext;
}

}  // namespace

absl::StatusOr<std::string> AuthenticatorInput(const Token& token) {
  return EncodeTokenStructHelper(token.token_type, token.token_key_id,
                                 token.nonce, token.context, std::nullopt);
}

absl::StatusOr<std::string> MarshalToken(const Token& token) {
  return EncodeTokenStructHelper(token.token_type, token.token_key_id,
                                 token.nonce, token.context,
                                 token.authenticator);
}

absl::StatusOr<Token>  UnmarshalToken(std::string token) {
  Token out;
  out.nonce.resize(32);
  out.context.resize(32);
  out.token_key_id.resize(32);
  out.authenticator.resize(256);
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(token.data()), token.size());
  if (!CBS_get_u16(&cbs, &out.token_type)) {
    return absl::InvalidArgumentError("failed to read token type");
  }
  if (out.token_type != 0xDA7A) {
    return absl::InvalidArgumentError("unsupported token type");
  }
  if (!CBS_copy_bytes(&cbs, reinterpret_cast<uint8_t*>(out.nonce.data()),
                      out.nonce.size())) {
    return absl::InvalidArgumentError("failed to read nonce");
  }
  if (!CBS_copy_bytes(&cbs, reinterpret_cast<uint8_t*>(out.context.data()),
                      out.context.size())) {
    return absl::InvalidArgumentError("failed to read context");
  }
  if (!CBS_copy_bytes(&cbs, reinterpret_cast<uint8_t*>(out.token_key_id.data()),
                      out.token_key_id.size())) {
    return absl::InvalidArgumentError("failed to read token_key_id");
  }
  if (!CBS_copy_bytes(&cbs,
                      reinterpret_cast<uint8_t*>(out.authenticator.data()),
                      out.authenticator.size())) {
    return absl::InvalidArgumentError("failed to read authenticator");
  }
  if (CBS_len(&cbs) != 0) {
    return absl::InvalidArgumentError("token had extra bytes");
  }
  return out;
}

absl::StatusOr<std::string> EncodeExtension(const Extension& extension) {
  // Main CryptoByteBuilder object cbb which will be passed to CBB_finish to
  // finalize the output string.
  bssl::ScopedCBB cbb;
  // Temporary cbb struct object to fill with value bytes.
  CBB extension_value;
  // initial_capacity only serves as a hint.
  if (!CBB_init(cbb.get(), /*initial_capacity=*/4)) {
    return absl::InternalError("CBB_init() failed.");
  }
  // Add extension type using only 2 bytes.
  if (!CBB_add_u16(cbb.get(), extension.extension_type) ||
      // Add extension value but prefix it with its length which should fit in 2
      // bytes.
      !CBB_add_u16_length_prefixed(cbb.get(), &extension_value) ||
      !CBB_add_bytes(
          &extension_value,
          reinterpret_cast<const uint8_t*>(extension.extension_value.data()),
          extension.extension_value.size())) {
    return absl::InvalidArgumentError("Failed to populate cbb.");
  }

  uint8_t* encoded_ext;
  size_t encoded_ext_len;
  if (!CBB_finish(cbb.get(), &encoded_ext, &encoded_ext_len)) {
    return absl::InvalidArgumentError("Failed to generate extension encoding");
  }
  std::string encoded_ext_str(reinterpret_cast<const char*>(encoded_ext),
                              encoded_ext_len);
  // Free memory.
  OPENSSL_free(encoded_ext);
  return encoded_ext_str;
}

absl::StatusOr<std::string> EncodeExtensions(const Extensions& extensions) {
  // Main CryptoByteBuilder object cbb which will be passed to CBB_finish to
  // finalize the output string.
  bssl::ScopedCBB cbb;
  // Temporary cbb struct object to fill with encoded extensions bytes.
  CBB extensions_list;
  // initial_capacity only serves as a hint.
  if (!CBB_init(cbb.get(), /*initial_capacity=*/6)) {
    return absl::InternalError("CBB_init() failed.");
  }
  // Size in bytes for the extensions list must fit in 2 bytes.
  if (!CBB_add_u16_length_prefixed(cbb.get(), &extensions_list)) {
    return absl::InvalidArgumentError(
        "Call to CBB_add_u16_length_prefixed erred.");
  }
  // Add all encoded extensions to the temporary cbb.
  for (const Extension& ext : extensions.extensions) {
    ANON_TOKENS_ASSIGN_OR_RETURN(std::string encoded_ext, EncodeExtension(ext));
    if (!CBB_add_bytes(&extensions_list,
                       reinterpret_cast<const uint8_t*>(encoded_ext.data()),
                       encoded_ext.size())) {
      return absl::InvalidArgumentError(
          "Could not add encoded extension to cbb.");
    }
  }

  uint8_t* encoded_extensions;
  size_t encoded_extensions_len;
  if (!CBB_finish(cbb.get(), &encoded_extensions, &encoded_extensions_len)) {
    return absl::InvalidArgumentError(
        "Failed to generate encoded extensions list.");
  }
  std::string encoded_extensions_str(
      reinterpret_cast<const char*>(encoded_extensions),
      encoded_extensions_len);
  // Free memory.
  OPENSSL_free(encoded_extensions);
  return encoded_extensions_str;
}

absl::StatusOr<ExpirationTimestamp> ExpirationTimestamp::FromExtension(
    const Extension& ext) {
  if (ext.extension_type != 0x0001) {
    return absl::InvalidArgumentError(
        absl::StrCat("Extension of wrong type: ", ext.extension_type));
  }
  ExpirationTimestamp ts;
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(ext.extension_value.data()),
           ext.extension_value.size());
  if (!CBS_get_u64(&cbs, &ts.timestamp_precision)) {
    return absl::InvalidArgumentError("failed to read timestamp_precision");
  }
  if (!CBS_get_u64(&cbs, &ts.timestamp)) {
    return absl::InvalidArgumentError("failed to read timestamp");
  }
  return ts;
}

absl::StatusOr<Extension> ExpirationTimestamp::AsExtension() const {
  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), sizeof(ExpirationTimestamp))) {
    return absl::InternalError("CBB_init() failed.");
  }
  if (!CBB_add_u64(cbb.get(), timestamp_precision)) {
    return absl::InternalError("Failed to add timestamp_precision to cbb.");
  }
  if (!CBB_add_u64(cbb.get(), timestamp)) {
    return absl::InternalError("Failed to add timestamp to cbb.");
  }
  uint8_t* wire_format;
  size_t wire_format_len;
  if (!CBB_finish(cbb.get(), &wire_format, &wire_format_len)) {
    return absl::InternalError("Failed to generate wire format.");
  }
  std::string wire_format_str(reinterpret_cast<const char*>(wire_format),
                              wire_format_len);
  OPENSSL_free(wire_format);
  return Extension{
      .extension_type = 0x0001,
      .extension_value = wire_format_str,
  };
}

absl::StatusOr<Extension> GeoHint::AsExtension() const {
  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), sizeof(uint16_t) + geo_hint.size())) {
    return absl::InternalError("CBB_init() failed.");
  }
  // Temporary cbb struct object to fill with geo_hint bytes.
  CBB geo_hint_cbb;
  if (!CBB_add_u16_length_prefixed(cbb.get(), &geo_hint_cbb) ||
      !CBB_add_bytes(&geo_hint_cbb,
                     reinterpret_cast<const uint8_t*>(geo_hint.data()),
                     geo_hint.size())) {
    return absl::InternalError("Failed to add geohint to cbb.");
  }
  uint8_t* wire_format;
  size_t wire_format_len;
  if (!CBB_finish(cbb.get(), &wire_format, &wire_format_len)) {
    return absl::InternalError("Failed to generate wire format.");
  }
  std::string wire_format_str(reinterpret_cast<const char*>(wire_format),
                              wire_format_len);
  OPENSSL_free(wire_format);
  return Extension{
      .extension_type = 0x0002,
      .extension_value = wire_format_str,
  };
}

absl::StatusOr<GeoHint> GeoHint::FromExtension(const Extension& ext) {
  if (ext.extension_type != 0x0002) {
    return absl::InvalidArgumentError(absl::StrCat(
        "[GeoHint] Extension of wrong type: ", ext.extension_type));
  }
  GeoHint gh;
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(ext.extension_value.data()),
           ext.extension_value.size());
  CBS geohint_cbs;
  if (!CBS_get_u16_length_prefixed(&cbs, &geohint_cbs)) {
    return absl::InvalidArgumentError(
        "[GeoHint] failed to read geohint length");
  }
  gh.geo_hint.resize(CBS_len(&geohint_cbs));
  if (!CBS_copy_bytes(&geohint_cbs,
                      reinterpret_cast<uint8_t*>(gh.geo_hint.data()),
                      gh.geo_hint.size())) {
    return absl::InvalidArgumentError("[GeoHint] failed to read geohint data");
  }

  const std::vector<std::string_view> split = absl::StrSplit(gh.geo_hint, ',');
  if (split.size() != 3) {
    return absl::InvalidArgumentError(
        "[GeoHint] geo_hint must be exactly 3 parts.");
  }
  for (const std::string_view part : split) {
    if (absl::AsciiStrToUpper(part) != part) {
      return absl::InvalidArgumentError(
          "[GeoHint] all geo_hint parts must be UPPERCASE.");
    }
  }
  gh.country_code = split[0];
  gh.region = split[1];
  gh.city = split[2];
  return gh;
}

absl::StatusOr<Extension> ServiceType::AsExtension() const {
  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), sizeof(uint8_t))) {
    return absl::InternalError("CBB_init() failed.");
  }
  if (!CBB_add_u8(cbb.get(), service_type_id)) {
    return absl::InternalError("Failed to add service_type_id to cbb.");
  }
  uint8_t* wire_format;
  size_t wire_format_len;
  if (!CBB_finish(cbb.get(), &wire_format, &wire_format_len)) {
    return absl::InternalError("Failed to generate wire format.");
  }
  std::string wire_format_str(reinterpret_cast<const char*>(wire_format),
                              wire_format_len);
  OPENSSL_free(wire_format);
  return Extension{.extension_type = 0xF001,
                   .extension_value = wire_format_str};
}

absl::StatusOr<ServiceType> ServiceType::FromExtension(const Extension& ext) {
  if (ext.extension_type != 0xF001) {
    return absl::InvalidArgumentError(absl::StrCat(
        "[ServiceType] extension of wrong type: ", ext.extension_type));
  }
  ServiceType st;
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(ext.extension_value.data()),
           ext.extension_value.size());
  if (!CBS_get_u8(&cbs, &st.service_type_id)) {
    return absl::InvalidArgumentError(
        "[ServiceType] failed to read len from extension");
  }
  switch (st.service_type_id) {
    case kChromeIpBlinding:
      st.service_type = "chromeipblinding";
      break;
    default:
      return absl::InvalidArgumentError(
          "[ServiceType] unknown service_type_id");
  }
  return st;
}

absl::StatusOr<Extension> DebugMode::AsExtension() const {
  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), sizeof(uint8_t))) {
    return absl::InternalError("CBB_init() failed.");
  }
  if (!CBB_add_u8(cbb.get(), mode)) {
    return absl::InternalError("Failed to add mode to cbb.");
  }
  uint8_t* wire_format;
  size_t wire_format_len;
  if (!CBB_finish(cbb.get(), &wire_format, &wire_format_len)) {
    return absl::InternalError("Failed to generate wire format.");
  }
  std::string wire_format_str(reinterpret_cast<const char*>(wire_format),
                              wire_format_len);
  OPENSSL_free(wire_format);
  return Extension{.extension_type = 0xF002,
                   .extension_value = wire_format_str};
}

absl::StatusOr<DebugMode> DebugMode::FromExtension(const Extension& ext) {
  if (ext.extension_type != 0xF002) {
    return absl::InvalidArgumentError(absl::StrCat(
        "[DebugMode] extension of wrong type: ", ext.extension_type));
  }
  DebugMode dm;
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(ext.extension_value.data()),
           ext.extension_value.size());
  if (!CBS_get_u8(&cbs, &dm.mode)) {
    return absl::InvalidArgumentError(
        "[DebugMode] failed to read len from extension");
  }
  if (dm.mode != kProd && dm.mode != kDebug) {
    return absl::InvalidArgumentError(
        absl::StrCat("[DebugMode] invalid mode: ", dm.mode));
  }
  return dm;
}

absl::StatusOr<Extensions>  DecodeExtensions(
    absl::string_view encoded_extensions) {
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(encoded_extensions.data()),
           encoded_extensions.size());
  CBS extensions_cbs;
  if (!CBS_get_u16_length_prefixed(&cbs, &extensions_cbs)) {
    return absl::InvalidArgumentError("failed to read extensions.");
  }
  if (CBS_len(&extensions_cbs) == 0) {
    return absl::InvalidArgumentError("At least one extension is required.");
  }
  if (CBS_len(&cbs) != 0) {
    return absl::InvalidArgumentError("no data after extensions is allowed.");
  }
  Extensions extensions;
  while (CBS_len(&extensions_cbs) > 0) {
    ANON_TOKENS_ASSIGN_OR_RETURN(const Extension ext,
                                 decodeExtension(&extensions_cbs));
    extensions.extensions.push_back(ext);
  }
  return extensions;
}

absl::StatusOr<std::string> MarshalTokenChallenge(
    const TokenChallenge& token_challenge) {
  // Main CryptoByteBuilder object cbb which will be passed to CBB_finish to
  // finalize the output string.
  bssl::ScopedCBB cbb;
  // initial_capacity only serves as a hint.
  if (!CBB_init(cbb.get(), /*initial_capacity=*/98)) {
    return absl::InternalError("CBB_init() failed.");
  }
  // Add token_type to cbb.
  if (!CBB_add_u16(cbb.get(), token_challenge.token_type)) {
    return absl::InvalidArgumentError("Could not add token_type to cbb.");
  }
  // Add issuer_name to cbb using temporary cbb struct object issuer_name_cbb.
  CBB issuer_name_cbb;
  if (!CBB_add_u16_length_prefixed(cbb.get(), &issuer_name_cbb) ||
      !CBB_add_bytes(
          &issuer_name_cbb,
          reinterpret_cast<const uint8_t*>(token_challenge.issuer_name.data()),
          token_challenge.issuer_name.size())) {
    return absl::InvalidArgumentError("Could not add issuer_name to cbb.");
  }
  uint8_t* marshaled_challenge;
  size_t marshaled_challenge_len;
  if (!CBB_finish(cbb.get(), &marshaled_challenge, &marshaled_challenge_len)) {
    return absl::InvalidArgumentError("Failed to marshal token challenge");
  }
  std::string marshaled_challenge_str(
      reinterpret_cast<const char*>(marshaled_challenge),
      marshaled_challenge_len);
  // Free memory.
  OPENSSL_free(marshaled_challenge);
  return marshaled_challenge_str;
}

}  // namespace anonymous_tokens

