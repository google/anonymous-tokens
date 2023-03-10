#ifndef ANONYMOUS_TOKENS_CPP_CRYPTO_CRYPTO_UTILS_H_
#define ANONYMOUS_TOKENS_CPP_CRYPTO_CRYPTO_UTILS_H_

#include <memory>
#include <string>

#include "absl/status/statusor.h"
#include <openssl/base.h>
#include <openssl/bn.h>
#include <openssl/evp.h>


namespace anonymous_tokens {

// Deletes a BN_CTX.
class BnCtxDeleter {
 public:
  void operator()(BN_CTX* ctx) { BN_CTX_free(ctx); }
};
typedef std::unique_ptr<BN_CTX, BnCtxDeleter> BnCtxPtr;

// Deletes a BN_MONT_CTX.
class BnMontCtxDeleter {
 public:
  void operator()(BN_MONT_CTX* mont_ctx) { BN_MONT_CTX_free(mont_ctx); }
};
typedef std::unique_ptr<BN_MONT_CTX, BnMontCtxDeleter> BnMontCtxPtr;

// Deletes an EVP_MD_CTX.
class EvpMdCtxDeleter {
 public:
  void operator()(EVP_MD_CTX* ctx) { EVP_MD_CTX_destroy(ctx); }
};
typedef std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter> EvpMdCtxPtr;

// Creates and starts a BIGNUM context.
absl::StatusOr<BnCtxPtr> GetAndStartBigNumCtx();

// Creates a new BIGNUM.
absl::StatusOr<bssl::UniquePtr<BIGNUM>> NewBigNum();

// Converts a BIGNUM to string.
absl::StatusOr<std::string> BignumToString(const BIGNUM& big_num,
                                           size_t output_len);

// Converts a string to BIGNUM.
absl::StatusOr<bssl::UniquePtr<BIGNUM>> StringToBignum(
    absl::string_view input_str);

// Retrieve error messages from OpenSSL.
std::string GetSslErrors();

// Compute 2^(x - 1/2).
absl::StatusOr<bssl::UniquePtr<BIGNUM>> GetRsaSqrtTwo(int x);

// Compute compute 2^x.
absl::StatusOr<bssl::UniquePtr<BIGNUM>> ComputePowerOfTwo(int x);

// ComputeHash sub-routine used druing blindness and verification of RSA PSS
// AnonymousTokens.
absl::StatusOr<std::string> ComputeHash(absl::string_view input,
                                        const EVP_MD& hasher);

}  // namespace anonymous_tokens


#endif  // ANONYMOUS_TOKENS_CPP_CRYPTO_CRYPTO_UTILS_H_
