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

#ifndef ANONYMOUS_TOKENS_CPP_CRYPTO_CONSTANTS_H_
#define ANONYMOUS_TOKENS_CPP_CRYPTO_CONSTANTS_H_

#include <cstdint>

#include "absl/strings/string_view.h"

namespace anonymous_tokens {

// Returned integer on successful execution of BoringSSL methods
constexpr int kBsslSuccess = 1;

// RSA modulus size, 4096 bits
//
// Our recommended size.
constexpr int kRsaModulusSizeInBits4096 = 4096;

// RSA modulus size, 512 bytes
constexpr int kRsaModulusSizeInBytes512 = 512;

// RSA modulus size, 2048 bits
//
// Recommended size for RSA Blind Signatures without Public Metadata.
//
// https://www.ietf.org/archive/id/draft-ietf-privacypass-protocol-08.html#name-token-type-blind-rsa-2048-b.
constexpr int kRsaModulusSizeInBits2048 = 2048;

// RSA modulus size, 256 bytes
constexpr int kRsaModulusSizeInBytes256 = 256;

// Salt length, 48 bytes
//
// Recommended size. The convention is to use hLen, the length of the output of
// the hash function in bytes. A salt length of zero will result in a
// deterministic signature value.
//
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-blind-signatures/
constexpr int kSaltLengthInBytes48 = 48;

// Length of message mask, 32 bytes.
//
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-blind-signatures/
constexpr size_t kRsaMessageMaskSizeInBytes32 = 32;

// Info used in HKDF for Public Metadata Hash.
constexpr absl::string_view kHkdfPublicMetadataInfo = "PBRSA";

constexpr int kHkdfPublicMetadataInfoSizeInBytes = 5;

// Object identifier for Rivest, Shamir, Adleman (RSA) Signature Scheme with
// Appendix - Probabilistic Signature Scheme (RSASSA-PSS) defined here:
// https://oidref.com/1.2.840.113549.1.1.10
constexpr char kRsaSsaPssOid[] = "1.2.840.113549.1.1.10";

// Object identifier for SHA384 defined here:
// https://oidref.com/2.16.840.1.101.3.4.2.2
constexpr char kSha384Oid[] = "2.16.840.1.101.3.4.2.2";

// Object identifier for RSA algorithm that uses the Mask Generator Function 1
// (MGF1) defined here:
// https://oidref.com/1.2.840.113549.1.1.8
constexpr char kRsaSsaPssMgf1Oid[] = "1.2.840.113549.1.1.8";

}  // namespace anonymous_tokens

#endif  // ANONYMOUS_TOKENS_CPP_CRYPTO_CONSTANTS_H_
