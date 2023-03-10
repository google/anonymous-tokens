#ifndef ANONYMOUS_TOKENS_CPP_CRYPTO_PUBLIC_METADATA_CRYPTO_UTILS_H_
#define ANONYMOUS_TOKENS_CPP_CRYPTO_PUBLIC_METADATA_CRYPTO_UTILS_H_

#include "absl/status/statusor.h"
#include "anonymous_tokens/proto/anonymous_tokens.pb.h"
#include <openssl/base.h>


namespace anonymous_tokens {

// Internal functions only exposed for testing.
namespace public_metadata_crypto_utils_internal {

absl::StatusOr<bssl::UniquePtr<BIGNUM>> PublicMetadataHashWithHKDF(
    absl::string_view input, absl::string_view rsa_modulus_str,
    size_t out_len_bytes);

}  // namespace public_metadata_crypto_utils_internal

// Compute exponent based only on the public metadata. Assumes that n is a safe
// modulus i.e. it produces a strong RSA key pair. If not, the exponent may be
// invalid.
absl::StatusOr<bssl::UniquePtr<BIGNUM>> PublicMetadataExponent(
    const BIGNUM& n, absl::string_view public_metadata);

// Computes final exponent by multiplying the public exponent e with the
// exponent derived from public metadata. Assumes that n is a safe modulus i.e.
// it produces a strong RSA key pair. If not, the exponent may be invalid.
absl::StatusOr<bssl::UniquePtr<BIGNUM>> ComputeFinalExponentUnderPublicMetadata(
    const BIGNUM& n, const BIGNUM& e, absl::string_view public_metadata);

// Converts AnonymousTokens RSAPublicKey to RSA under a fixed public_metadata.
//
// If the public_metadata is empty, this method doesn't modify the public
// exponent but instead simply outputs the RSA for the unmodified RSAPublicKey.
//
absl::StatusOr<bssl::UniquePtr<RSA>> RSAPublicKeyToRSAUnderPublicMetadata(
    const RSAPublicKey& public_key, absl::string_view public_metadata);

}  // namespace anonymous_tokens


#endif  // ANONYMOUS_TOKENS_CPP_CRYPTO_PUBLIC_METADATA_CRYPTO_UTILS_H_
