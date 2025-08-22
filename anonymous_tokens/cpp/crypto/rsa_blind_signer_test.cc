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

#include "anonymous_tokens/cpp/crypto/rsa_blind_signer.h"

#include <memory>
#include <random>
#include <string>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "anonymous_tokens/cpp/crypto/constants.h"
#include "anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "anonymous_tokens/cpp/crypto/rsa_ssa_pss_verifier.h"
#include "anonymous_tokens/cpp/testing/proto_utils.h"
#include "anonymous_tokens/cpp/testing/utils.h"
#include "anonymous_tokens/proto/anonymous_tokens.pb.h"
#include <openssl/digest.h>
#include <openssl/rsa.h>

namespace anonymous_tokens {
namespace {

using CreateTestKeyPairFunction =
    absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>>();

class RsaBlindSignerTest
    : public ::testing::TestWithParam<CreateTestKeyPairFunction *> {
 protected:
  void SetUp() override {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto keys_pair, (*GetParam())());
    public_key_ = std::move(keys_pair.first);
    private_key_ = std::move(keys_pair.second);
    generator_.seed(0);
    // NOTE: using recommended RsaSsaPssParams
    sig_hash_ = EVP_sha384();
    mgf1_hash_ = EVP_sha384();
    salt_length_ = kSaltLengthInBytes48;
  }

  RSAPrivateKey private_key_;
  RSAPublicKey public_key_;
  std::mt19937_64 generator_;
  const EVP_MD *sig_hash_;   // Owned by BoringSSL.
  const EVP_MD *mgf1_hash_;  // Owned by BoringSSL.
  int salt_length_;
  std::uniform_int_distribution<int> distr_u8_ =
      std::uniform_int_distribution<int>{0, 255};
};

// This test only tests whether the implemented signer 'signs' properly. The
// outline of method calls in this test should not be assumed a secure signature
// scheme (and used in other places) as the security has not been
// proven/analyzed.
//
// Test for the standard signer does not take public metadata as a parameter
// which means public metadata is set to std::nullopt.
TEST_P(RsaBlindSignerTest, StandardSignerWorks) {
  absl::string_view message = "Hello World!";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(message, public_key_, sig_hash_, mgf1_hash_,
                            salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlindSigner> signer,
      RsaBlindSigner::New(private_key_, /*use_rsa_public_exponent=*/true));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string potentially_insecure_signature,
                                   signer->Sign(encoded_message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_,
                             /*use_rsa_public_exponent=*/true));
  EXPECT_TRUE(verifier->Verify(potentially_insecure_signature, message).ok());
}

TEST_P(RsaBlindSignerTest, SignerFails) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlindSigner> signer,
      RsaBlindSigner::New(private_key_, /*use_rsa_public_exponent=*/true));
  absl::string_view message = "Hello World!";

  absl::StatusOr<std::string> signature = signer->Sign(message);
  EXPECT_EQ(signature.status().code(), absl::StatusCode::kInternal);
  EXPECT_THAT(signature.status().message(),
              ::testing::HasSubstr("Expected blind data size"));

  int sig_size = public_key_.n().size();
  std::string message2 = RandomString(sig_size, &distr_u8_, &generator_);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string insecure_sig,
                                   signer->Sign(message2));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_,
                             /*use_rsa_public_exponent=*/true));
  absl::Status verification_result = verifier->Verify(insecure_sig, message2);
  EXPECT_EQ(verification_result.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(verification_result.message(),
              ::testing::HasSubstr("verification failed"));
}

INSTANTIATE_TEST_SUITE_P(RsaBlindSignerTest, RsaBlindSignerTest,
                         ::testing::Values(&GetStrongRsaKeys2048,
                                           &GetAnotherStrongRsaKeys2048,
                                           &GetStrongRsaKeys3072,
                                           &GetStrongRsaKeys4096));

using CreateTestKeyPairFunction =
    absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>>();

using RsaBlindSignerPublicMetadataTestParams =
    std::tuple<CreateTestKeyPairFunction *,
               /*use_rsa_public_exponent*/ bool>;

class RsaBlindSignerTestWithPublicMetadata
    : public ::testing::TestWithParam<RsaBlindSignerPublicMetadataTestParams> {
 protected:
  void SetUp() override {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto keys_pair, std::get<0>(GetParam())());
    use_rsa_public_exponent_ = std::get<1>(GetParam());
    public_key_ = std::move(keys_pair.first);
    private_key_ = std::move(keys_pair.second);
    // NOTE: using recommended RsaSsaPssParams
    sig_hash_ = EVP_sha384();
    mgf1_hash_ = EVP_sha384();
    salt_length_ = kSaltLengthInBytes48;
  }

  RSAPrivateKey private_key_;
  RSAPublicKey public_key_;
  const EVP_MD *sig_hash_;   // Owned by BoringSSL.
  const EVP_MD *mgf1_hash_;  // Owned by BoringSSL.
  int salt_length_;
  bool use_rsa_public_exponent_;
};

// This test only tests whether the implemented signer 'signs' properly under
// some public metadata. The outline of method calls in this test should not
// be assumed a secure signature scheme (and used in other places) as the
// security has not been proven/analyzed.
TEST_P(RsaBlindSignerTestWithPublicMetadata, SignerWorksWithPublicMetadata) {
  absl::string_view message = "Hello World!";
  absl::string_view public_metadata = "pubmd!";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlindSigner> signer,
      RsaBlindSigner::New(private_key_, use_rsa_public_exponent_,
                          public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string potentially_insecure_signature,
                                   signer->Sign(encoded_message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_,
                             use_rsa_public_exponent_, public_metadata));
  EXPECT_TRUE(verifier->Verify(potentially_insecure_signature, message).ok());
}

TEST_P(RsaBlindSignerTestWithPublicMetadata,
       SignerWorksWithEmptyPublicMetadata) {
  absl::string_view message = "Hello World!";
  absl::string_view empty_public_metadata = "";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, empty_public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlindSigner> signer,
      RsaBlindSigner::New(private_key_, use_rsa_public_exponent_,
                          empty_public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string potentially_insecure_signature,
                                   signer->Sign(encoded_message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_,
                             use_rsa_public_exponent_, empty_public_metadata));
  EXPECT_TRUE(verifier->Verify(potentially_insecure_signature, message).ok());
}

TEST_P(RsaBlindSignerTestWithPublicMetadata,
       SignatureFailstoVerifyWithWrongPublicMetadata) {
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
      std::unique_ptr<RsaBlindSigner> signer,
      RsaBlindSigner::New(private_key_, use_rsa_public_exponent_,
                          public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string potentially_insecure_signature,
                                   signer->Sign(encoded_message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_,
                             use_rsa_public_exponent_, public_metadata_2));
  absl::Status verification_result =
      verifier->Verify(potentially_insecure_signature, message);
  EXPECT_EQ(verification_result.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(verification_result.message(),
              ::testing::HasSubstr("verification failed"));
}

TEST_P(RsaBlindSignerTestWithPublicMetadata,
       SignatureFailsToVerifyWithNoPublicMetadata) {
  absl::string_view message = "Hello World!";
  absl::string_view public_metadata = "pubmd!";
  absl::string_view public_metadata_2 = "";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlindSigner> signer,
      RsaBlindSigner::New(private_key_, use_rsa_public_exponent_,
                          public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string potentially_insecure_signature,
                                   signer->Sign(encoded_message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_,
                             use_rsa_public_exponent_, public_metadata_2));
  absl::Status verification_result =
      verifier->Verify(potentially_insecure_signature, message);
  EXPECT_EQ(verification_result.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(verification_result.message(),
              ::testing::HasSubstr("verification failed"));
}

INSTANTIATE_TEST_SUITE_P(
    RsaBlindSignerTestWithPublicMetadata, RsaBlindSignerTestWithPublicMetadata,
    ::testing::Combine(
        ::testing::Values(&GetStrongRsaKeys2048, &GetAnotherStrongRsaKeys2048,
                          &GetStrongRsaKeys3072, &GetStrongRsaKeys4096),
        /*use_rsa_public_exponent*/ ::testing::Values(true, false)));

TEST(IetfRsaBlindSignerTest,
     IetfRsaBlindSignaturesWithPublicMetadataTestVectorsSuccess) {
  auto test_vectors = GetIetfRsaBlindSignatureWithPublicMetadataTestVectors();
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto test_key,
      GetIetfRsaBlindSignatureWithPublicMetadataTestKeys());
  for (const auto &test_vector : test_vectors) {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        std::unique_ptr<RsaBlindSigner> signer,
        RsaBlindSigner::New(test_key.second, /*use_rsa_public_exponent=*/true,
                            test_vector.public_metadata));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blind_signature,
                                     signer->Sign(test_vector.blinded_message));
    EXPECT_EQ(blind_signature, test_vector.blinded_signature);
  }
}

TEST(IetfRsaBlindSignerTest,
     IetfPartiallyBlindRsaSignaturesNoPublicExponentTestVectorsSuccess) {
  auto test_vectors =
      GetIetfPartiallyBlindRSASignatureNoPublicExponentTestVectors();
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto test_key,
      GetIetfRsaBlindSignatureWithPublicMetadataTestKeys());
  for (const auto &test_vector : test_vectors) {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        std::unique_ptr<RsaBlindSigner> signer,
        RsaBlindSigner::New(test_key.second, /*use_rsa_public_exponent=*/false,
                            test_vector.public_metadata));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blind_signature,
                                     signer->Sign(test_vector.blinded_message));
    EXPECT_EQ(blind_signature, test_vector.blinded_signature);
  }
}

}  // namespace
}  // namespace anonymous_tokens
