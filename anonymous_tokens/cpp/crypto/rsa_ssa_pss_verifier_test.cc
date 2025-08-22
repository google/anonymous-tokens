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

#include "anonymous_tokens/cpp/crypto/rsa_ssa_pss_verifier.h"

#include <memory>
#include <string>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "anonymous_tokens/cpp/crypto/anonymous_tokens_pb_openssl_converters.h"
#include "anonymous_tokens/cpp/crypto/constants.h"
#include "anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "anonymous_tokens/cpp/testing/proto_utils.h"
#include "anonymous_tokens/cpp/testing/utils.h"
#include "anonymous_tokens/proto/anonymous_tokens.pb.h"
#include <openssl/rsa.h>

namespace anonymous_tokens {
namespace {

TEST(RsaSsaPssVerifier, SuccessfulVerification) {
  const IetfStandardRsaBlindSignatureTestVector test_vec =
      GetIetfStandardRsaBlindSignatureTestVector();
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const auto test_keys,
                                   GetIetfStandardRsaBlindSignatureTestKeys());
  const EVP_MD *sig_hash = EVP_sha384();   // Owned by BoringSSL
  const EVP_MD *mgf1_hash = EVP_sha384();  // Owned by BoringSSL
  const int salt_length = kSaltLengthInBytes48;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto verifier,
      RsaSsaPssVerifier::New(salt_length, sig_hash, mgf1_hash, test_keys.first,
                             /*use_rsa_public_exponent=*/true));
  EXPECT_TRUE(verifier->Verify(test_vec.signature, test_vec.message).ok());
}

TEST(RsaSsaPssVerifier, InvalidSignature) {
  const IetfStandardRsaBlindSignatureTestVector test_vec =
      GetIetfStandardRsaBlindSignatureTestVector();
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const auto test_keys,
                                   GetIetfStandardRsaBlindSignatureTestKeys());
  const EVP_MD *sig_hash = EVP_sha384();   // Owned by BoringSSL
  const EVP_MD *mgf1_hash = EVP_sha384();  // Owned by BoringSSL
  const int salt_length = kSaltLengthInBytes48;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto verifier,
      RsaSsaPssVerifier::New(salt_length, sig_hash, mgf1_hash, test_keys.first,
                             /*use_rsa_public_exponent=*/true));
  // corrupt signature
  std::string wrong_sig = test_vec.signature;
  wrong_sig.replace(10, 1, "x");

  absl::Status verification_result =
      verifier->Verify(wrong_sig, test_vec.message);
  EXPECT_EQ(verification_result.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(verification_result.message(),
              testing::HasSubstr("verification failed"));
}

TEST(RsaSsaPssVerifier, InvalidVerificationKey) {
  const IetfStandardRsaBlindSignatureTestVector test_vec =
      GetIetfStandardRsaBlindSignatureTestVector();
  const EVP_MD *sig_hash = EVP_sha384();   // Owned by BoringSSL
  const EVP_MD *mgf1_hash = EVP_sha384();  // Owned by BoringSSL
  const int salt_length = kSaltLengthInBytes48;
  // wrong key
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto new_keys_pair, GetStandardRsaKeyPair());
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto verifier,
      RsaSsaPssVerifier::New(salt_length, sig_hash, mgf1_hash,
                             new_keys_pair.first,
                             /*use_rsa_public_exponent=*/true));

  absl::Status verification_result =
      verifier->Verify(test_vec.signature, test_vec.message);
  EXPECT_EQ(verification_result.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(verification_result.message(),
              testing::HasSubstr("verification failed"));
}

TEST(RsaSsaPssVerifierTestWithPublicMetadata,
     EmptyMessageStandardVerificationSuccess) {
  absl::string_view message = "";
  const EVP_MD *sig_hash = EVP_sha384();   // Owned by BoringSSL
  const EVP_MD *mgf1_hash = EVP_sha384();  // Owned by BoringSSL
  const int salt_length = kSaltLengthInBytes48;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const auto test_key,
                                   GetStandardRsaKeyPair());
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto private_key, AnonymousTokensRSAPrivateKeyToRSA(test_key.second));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(message, test_key.first, sig_hash, mgf1_hash,
                            salt_length));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string potentially_insecure_signature,
      TestSign(encoded_message, private_key.get()));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length, sig_hash, mgf1_hash, test_key.first,
                             /*use_rsa_public_exponent=*/true));
  EXPECT_TRUE(verifier->Verify(potentially_insecure_signature, message).ok());
}

TEST(RsaSsaPssVerifierTestWithPublicMetadata,
     IetfRsaBlindSignaturesWithPublicMetadataTestVectorsSuccess) {
  auto test_vectors = GetIetfRsaBlindSignatureWithPublicMetadataTestVectors();
  const EVP_MD *sig_hash = EVP_sha384();   // Owned by BoringSSL
  const EVP_MD *mgf1_hash = EVP_sha384();  // Owned by BoringSSL
  const int salt_length = kSaltLengthInBytes48;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto test_key,
      GetIetfRsaBlindSignatureWithPublicMetadataTestKeys());
  for (const auto &test_vector : test_vectors) {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        auto verifier,
        RsaSsaPssVerifier::New(salt_length, sig_hash, mgf1_hash, test_key.first,
                               /*use_rsa_public_exponent=*/true,
                               test_vector.public_metadata));
    EXPECT_TRUE(verifier
                    ->Verify(test_vector.signature,
                             MaskMessageConcat(test_vector.message_mask,
                                               test_vector.message))
                    .ok());
  }
}

TEST(RsaSsaPssVerifierTestWithPublicMetadata,
     IetfRsaBlindSignaturesWithPublicMetadataNoPublicExponentSuccess) {
  auto test_vectors =
      GetIetfPartiallyBlindRSASignatureNoPublicExponentTestVectors();
  const EVP_MD *sig_hash = EVP_sha384();   // Owned by BoringSSL
  const EVP_MD *mgf1_hash = EVP_sha384();  // Owned by BoringSSL
  const int salt_length = kSaltLengthInBytes48;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto test_key,
      GetIetfRsaBlindSignatureWithPublicMetadataTestKeys());
  for (const auto &test_vector : test_vectors) {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        auto verifier,
        RsaSsaPssVerifier::New(salt_length, sig_hash, mgf1_hash, test_key.first,
                               /*use_rsa_public_exponent=*/false,
                               test_vector.public_metadata));
    EXPECT_TRUE(
        verifier->Verify(test_vector.signature, test_vector.message).ok());
  }
}

using CreateTestKeyPairFunction =
    absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>>();

using RsaSsaPssVerifierPublicMetadataTestParams =
    std::tuple<CreateTestKeyPairFunction *,
               /*use_rsa_public_exponent*/ bool>;

class RsaSsaPssVerifierTestWithPublicMetadata
    : public ::testing::TestWithParam<
          RsaSsaPssVerifierPublicMetadataTestParams> {
 protected:
  void SetUp() override {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto keys_pair, std::get<0>(GetParam())());
    use_rsa_public_exponent_ = std::get<1>(GetParam());
    public_key_ = std::move(keys_pair.first);
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        private_key_, AnonymousTokensRSAPrivateKeyToRSA(keys_pair.second));
    // NOTE: using recommended RsaSsaPssParams
    sig_hash_ = EVP_sha384();
    mgf1_hash_ = EVP_sha384();
    salt_length_ = kSaltLengthInBytes48;
  }

  RSAPublicKey public_key_;
  bssl::UniquePtr<RSA> private_key_;
  const EVP_MD *sig_hash_;   // Owned by BoringSSL.
  const EVP_MD *mgf1_hash_;  // Owned by BoringSSL.
  int salt_length_;
  bool use_rsa_public_exponent_;
};

// This test only tests whether the implemented verfier 'verifies' properly
// under some public metadata. The outline of method calls in this test should
// not be assumed a secure signature scheme (and used in other places) as the
// security has not been proven/analyzed.
TEST_P(RsaSsaPssVerifierTestWithPublicMetadata,
       VerifierWorksWithPublicMetadata) {
  absl::string_view message = "Hello World!";
  absl::string_view public_metadata = "pubmd!";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string potentially_insecure_signature,
      TestSignWithPublicMetadata(encoded_message, public_metadata,
                                 *private_key_, use_rsa_public_exponent_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_,
                             use_rsa_public_exponent_, public_metadata));
  EXPECT_TRUE(verifier->Verify(potentially_insecure_signature, message).ok());
}

TEST_P(RsaSsaPssVerifierTestWithPublicMetadata,
       VerifierFailsToVerifyWithWrongPublicMetadata) {
  absl::string_view message = "Hello World!";
  absl::string_view public_metadata = "pubmd!";
  absl::string_view public_metadata_2 = "pubmd2";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string potentially_insecure_signature,
      TestSignWithPublicMetadata(encoded_message, public_metadata,
                                 *private_key_, use_rsa_public_exponent_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_,
                             use_rsa_public_exponent_, public_metadata_2));
  absl::Status verification_result =
      verifier->Verify(potentially_insecure_signature, message);
  EXPECT_EQ(verification_result.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(verification_result.message(),
              testing::HasSubstr("verification failed"));
}

TEST_P(RsaSsaPssVerifierTestWithPublicMetadata,
       VerifierFailsToVerifyWithEmptyPublicMetadata) {
  absl::string_view message = "Hello World!";
  absl::string_view public_metadata = "pubmd!";
  absl::string_view empty_public_metadata = "";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string potentially_insecure_signature,
      TestSignWithPublicMetadata(encoded_message, public_metadata,
                                 *private_key_, use_rsa_public_exponent_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_,
                             use_rsa_public_exponent_, empty_public_metadata));
  absl::Status verification_result =
      verifier->Verify(potentially_insecure_signature, message);
  EXPECT_EQ(verification_result.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(verification_result.message(),
              testing::HasSubstr("verification failed"));
}

TEST_P(RsaSsaPssVerifierTestWithPublicMetadata,
       VerifierFailsToVerifyWithoutPublicMetadataSupport) {
  absl::string_view message = "Hello World!";
  absl::string_view public_metadata = "pubmd!";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string potentially_insecure_signature,
      TestSignWithPublicMetadata(encoded_message, public_metadata,
                                 *private_key_, use_rsa_public_exponent_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_,
                             use_rsa_public_exponent_));
  absl::Status verification_result =
      verifier->Verify(potentially_insecure_signature, message);
  EXPECT_EQ(verification_result.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(verification_result.message(),
              testing::HasSubstr("verification failed"));
}

TEST_P(RsaSsaPssVerifierTestWithPublicMetadata,
       EmptyMessageEmptyPublicMetadataVerificationSuccess) {
  absl::string_view message = "";
  absl::string_view public_metadata = "";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string potentially_insecure_signature,
      TestSignWithPublicMetadata(encoded_message, public_metadata,
                                 *private_key_.get(),
                                 use_rsa_public_exponent_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_,
                             use_rsa_public_exponent_, public_metadata));
  EXPECT_TRUE(verifier->Verify(potentially_insecure_signature, message).ok());
}

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPssVerifierTestWithPublicMetadata,
    RsaSsaPssVerifierTestWithPublicMetadata,
    ::testing::Combine(
        ::testing::Values(&GetStrongRsaKeys2048, &GetAnotherStrongRsaKeys2048,
                          &GetStrongRsaKeys3072, &GetStrongRsaKeys4096),
        /*use_rsa_public_exponent*/ ::testing::Values(true, false)));

}  // namespace
}  // namespace anonymous_tokens
