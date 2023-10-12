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

#ifndef ANONYMOUS_TOKENS_CPP_PRIVACY_PASS_TOKEN_ENCODINGS_H_
#define ANONYMOUS_TOKENS_CPP_PRIVACY_PASS_TOKEN_ENCODINGS_H_

#include <stdint.h>

#include <optional>
#include <string>

#include "absl/status/statusor.h"



namespace anonymous_tokens {

// TokenRequest contains the blinded_token_request along with the token type
// represented using two bytes and the truncated_token_key_id which is the last
// byte of the the key identifier computed as SHA256(encoded_key), where
// encoded_key is a DER-encoded object carrying the public key as described
// here:
// https://smhendrickson.github.io/draft-hendrickson-privacypass-public-metadata-issuance/draft-hendrickson-privacypass-public-metadata.html#section-6.5
//
// The token_type is initialized to a default value of 0xDA7A which represents
// RSA Blind Signatures with Public Metadata.
struct  TokenRequest {
  uint16_t token_type{0XDA7A};
  uint8_t truncated_token_key_id;
  std::string blinded_token_request;
};

// Extension id a type-value structure whose semantics are determined by the
// type. The extension_type as well as length (size in bytes) of an
// extension_value must be a 2-octet integer.
struct  Extension {
  uint16_t extension_type{0X0001};
  std::string extension_value;
};

// Represents the extension defined in Privacy Pass Token Expiration Extension
// See
// https://chris-wood.github.io/draft-hendrickson-privacypass-expiration-extension/draft-hendrickson-privacypass-expiration-extension.html
// for the editors copy.
struct  ExpirationTimestamp {
  uint64_t timestamp_precision;
  uint64_t timestamp;

  absl::StatusOr<Extension> AsExtension() const;

  static absl::StatusOr<ExpirationTimestamp> FromExtension(
      const Extension& ext);
};

// Represents the extension defined in  Privacy Pass Geolocation Hint Extension
// See
// https://chris-wood.github.io/draft-hendrickson-privacypass-geolocation-extension/draft-hendrickson-privacypass-geolocation-extension.txt
// for the editors copy.
struct  GeoHint {
  std::string geo_hint;

  // Derived in FromExtension from geo_hint.
  std::string country_code;
  std::string region;
  std::string city;

  absl::StatusOr<Extension> AsExtension() const;

  static absl::StatusOr<GeoHint> FromExtension(const Extension& ext);
};

// ServiceType allows verifiers to differentiate and apply service specific
// policies at verification time. Only a single ID representing the Chrome
// IP Protection project is supported at this time.
// This struct and its implementation should be considered the registry of
// service type identifier mappings.
// Represents a private extension using id 0xF001.
struct  ServiceType {
  typedef uint8_t ServiceTypeId;
  static constexpr ServiceTypeId kChromeIpBlinding = 0x01;
  ServiceTypeId service_type_id;

  // Derived in FromExtension from service_type_id.
  std::string service_type;

  absl::StatusOr<Extension> AsExtension() const;

  static absl::StatusOr<ServiceType> FromExtension(const Extension& ext);
};

// DebugMode allows verifiers to apply service specific policies at verification
// time. The mode field is a boolean.
//  - 0x00 is production.
//  - 0x01 is debug.
//  - Any other mode value is invalid.
// Production clients MUST never set 0x01, and attesters should refuse to grant
// 0x01 to production clients.
// Represents a private extension using id 0xF002.
struct  DebugMode {
  // Mode values
  // We don't use an enum here because SWIG doesn't support c++11 typed enums,
  // and we need enum to be exactly uint8
  typedef uint8_t Mode;
  static constexpr Mode kProd = 0x00;
  static constexpr Mode kDebug = 0x01;
  Mode mode;

  absl::StatusOr<Extension> AsExtension() const;

  static absl::StatusOr<DebugMode> FromExtension(const Extension& ext);
};

// The contents of Extensions is a list of Extension values. The length (size in
// bytes) of this list should be a 2-octet integer.
struct  Extensions {
  std::vector<Extension> extensions;
};

// ExtendedTokenRequest is simply a TokenRequest-Extensions structure. Public
// Metadata will be encoded as Extensions.
struct  ExtendedTokenRequest {
  TokenRequest request;
  Extensions extensions;
};

// Token is a structure that contains the actual signature / token i.e. the
// authenticator along with the token_type represented using two bytes, the
// token_key_id which the key identifier computed as SHA256(encoded_key) where
// encoded_key is a DER-encoded object carrying the public key, the nonce which
// is a random 32 byte value, and the context which is a SHA256 digest of an
// input challenge. All of these are described here:
// https://smhendrickson.github.io/draft-hendrickson-privacypass-public-metadata-issuance/draft-hendrickson-privacypass-public-metadata.html#section-6.5
//
// The token_type is initialized to a default value of 0xDA7A which represents
// RSA Blind Signatures with Public Metadata.
struct  Token {
  uint16_t token_type{0XDA7A};
  std::string token_key_id;
  std::string nonce;
  std::string context;
  std::string authenticator;
};

// TokenChallenge is a structure that is sent from origins to the client. It
// contains information used to generate the token.
// Fields are described here:
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-14#challenge
// However, we will not use the redemption_context and origin_info fields.
// Our scheme combines the origin and issuer so they are superfluous.
//
// The token_type is initialized to a default value of 0xDA7A which represents
// RSA Blind Signatures with Public Metadata.
struct TokenChallenge {
  uint16_t token_type{0XDA7A};
  std::string issuer_name;
};

// This methods takes in a Token and outputs the authenticator input /
// token_input, defined in the specification:
// https://smhendrickson.github.io/draft-hendrickson-privacypass-public-metadata-issuance/draft-hendrickson-privacypass-public-metadata.html
// This will be used to create the token request as well as to verify the final
// signature.
//
// It does not require the authenticator field to be populated.
absl::StatusOr<std::string>  AuthenticatorInput(
    const Token& token);

// This methods takes in a Token structure and encodes it into a string.
absl::StatusOr<std::string>  MarshalToken(
    const Token& token);

// This methods takes in an encoded Token and decodes it into a Token struct.
absl::StatusOr<Token>  UnmarshalToken(std::string token);

// This methods takes in an Extension struct and encodes it into a string.
absl::StatusOr<std::string>  EncodeExtension(
    const Extension& extension);

// This methods takes in an Extensions struct and encodes it into a string.
absl::StatusOr<std::string>  EncodeExtensions(
    const Extensions& extensions);

// This methods takes a string of encoded extensions and decodes it to an
// Extensions struct.
absl::StatusOr<Extensions>  DecodeExtensions(
    absl::string_view encoded_extensions);

// This method takes in a TokenChallenge structure and encodes it into a string.
absl::StatusOr<std::string>  MarshalTokenChallenge(
    const TokenChallenge& token_challenge);

}  // namespace anonymous_tokens


#endif  // ANONYMOUS_TOKENS_CPP_PRIVACY_PASS_TOKEN_ENCODINGS_H_
