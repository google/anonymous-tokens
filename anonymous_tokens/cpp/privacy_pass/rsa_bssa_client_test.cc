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

#include "anonymous_tokens/cpp/privacy_pass/rsa_bssa_client.h"

#include <cstdint>
#include <memory>
#include <random>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/statusor.h"
#include "anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "anonymous_tokens/cpp/privacy_pass/token_encodings.h"
#include "anonymous_tokens/cpp/testing/utils.h"
#include <openssl/digest.h>

namespace anonymous_tokens {
namespace {

class PrivacyPassRsaBssaClientTest : public testing::Test {
 protected:
  void SetUp() override {
    // Seed the random string generator.
    generator_.seed(GTEST_FLAG_GET(random_seed));

    // Create RSA public and private key structs.
    auto [test_rsa_public_key, test_rsa_private_key] =
        GetStrongTestRsaKeyPair2048();
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        rsa_public_key_,
        CreatePublicKeyRSA(test_rsa_public_key.n, test_rsa_public_key.e));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        rsa_private_key_,
        CreatePrivateKeyRSA(test_rsa_private_key.n, test_rsa_private_key.e,
                            test_rsa_private_key.d, test_rsa_private_key.p,
                            test_rsa_private_key.q, test_rsa_private_key.dp,
                            test_rsa_private_key.dq, test_rsa_private_key.crt));
    // Compute RSA BSSA Public Key Token ID.
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        std::string public_key_der,
        RsaSsaPssPublicKeyToDerEncoding(rsa_public_key_.get()));
    const EVP_MD* sha256 = EVP_sha256();
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(token_key_id_,
                                     ComputeHash(public_key_der, *sha256));

    // Create a client using the rsa_public_key_.
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        client_, PrivacyPassRsaBssaClient::Create(*rsa_public_key_.get()));

    // Challenge for the purposes of this test is a random 80 bytes string.
    challenge_encoding_ = GetRandomString(/*string_length=*/80);
    // Nonce is a random string of 32 bytes.
    nonce_ = GetRandomString(/*string_length=*/32);
  }

  // Generates a random string of size string_length.
  std::string GetRandomString(int string_length) {
    std::string rand(string_length, 0);
    for (int i = 0; i < string_length; ++i) {
      rand[i] = static_cast<uint8_t>((distr_u8_)(generator_));
    }
    return rand;
  }

  bssl::UniquePtr<RSA> rsa_public_key_;
  bssl::UniquePtr<RSA> rsa_private_key_;
  std::string token_key_id_;

  std::unique_ptr<PrivacyPassRsaBssaClient> client_;
  std::string challenge_encoding_;
  std::string nonce_;

  std::mt19937_64 generator_;
  std::uniform_int_distribution<int> distr_u8_ =
      std::uniform_int_distribution<int>{0, 255};
};

TEST_F(PrivacyPassRsaBssaClientTest, WrongKeySize) {
  auto [test_rsa_public_key, _] = GetStrongTestRsaKeyPair3072();
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<RSA> wrong_rsa_public_key,
      CreatePublicKeyRSA(test_rsa_public_key.n, test_rsa_public_key.e));

  // Passing wrong key.
  absl::StatusOr<std::unique_ptr<PrivacyPassRsaBssaClient>> client =
      PrivacyPassRsaBssaClient::Create(*wrong_rsa_public_key.get());

  EXPECT_FALSE(client.status().ok());
  EXPECT_EQ(client.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(client.status().message(),
              ::testing::HasSubstr("Token type 0002 must use RSA key with the "
                                   "modulus of size 256 bytes"));
}

TEST_F(PrivacyPassRsaBssaClientTest, WrongSizeOfTokenKeyID) {
  // Token key ID of invalid size 0.
  absl::StatusOr<TokenRequest> token_req = client_->CreateTokenRequest(
      /*challenge=*/"", /*nonce=*/"", /*token_key_id=*/"");

  EXPECT_FALSE(token_req.status().ok());
  EXPECT_EQ(token_req.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(token_req.status().message(),
              ::testing::HasSubstr("token_key_id must be of size 32 bytes"));
}

TEST_F(PrivacyPassRsaBssaClientTest, CreateRequestTwice) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      TokenRequest _, client_->CreateTokenRequest(/*challenge=*/"",
                                                  /*nonce=*/"", token_key_id_));
  // 2nd request.
  absl::StatusOr<TokenRequest> token_req_2 = client_->CreateTokenRequest(
      /*challenge=*/"", /*nonce=*/"", token_key_id_);

  EXPECT_FALSE(token_req_2.status().ok());
  EXPECT_EQ(token_req_2.status().code(), absl::StatusCode::kFailedPrecondition);
  EXPECT_THAT(
      token_req_2.status().message(),
      ::testing::HasSubstr("CreateTokenRequest has already been called"));
}

TEST_F(PrivacyPassRsaBssaClientTest, FinalizeTokenWihtoutCreatingRequest) {
  const std::string dummy_signature = GetRandomString(/*string_length=*/256);
  absl::StatusOr<Token> token = client_->FinalizeToken(dummy_signature);

  EXPECT_FALSE(token.status().ok());
  EXPECT_EQ(token.status().code(), absl::StatusCode::kFailedPrecondition);
  EXPECT_THAT(token.status().message(),
              ::testing::HasSubstr(
                  "CreateRequest must be called before FinalizeToken"));
}

TEST_F(PrivacyPassRsaBssaClientTest, FinalizeTokenWithEmptySignature) {
  // Create token request.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      TokenRequest token_req,
      client_->CreateTokenRequest(challenge_encoding_, nonce_, token_key_id_));
  // Finalize the token with empty signature.
  absl::StatusOr<Token> token = client_->FinalizeToken("");

  EXPECT_FALSE(token.status().ok());
  EXPECT_EQ(token.status().code(), absl::StatusCode::kInternal);
  EXPECT_THAT(token.status().message(),
              ::testing::HasSubstr("Expected blind signature size = 256"));
}

TEST_F(PrivacyPassRsaBssaClientTest, FinalizeWrongToken) {
  // Create token request.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      TokenRequest token_req,
      client_->CreateTokenRequest(challenge_encoding_, nonce_, token_key_id_));
  const std::string dummy_signature = GetRandomString(256);
  // Finalize token with wrong signature.
  absl::StatusOr<Token> token = client_->FinalizeToken(dummy_signature);

  EXPECT_FALSE(token.status().ok());
  EXPECT_EQ(token.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(token.status().message(),
              ::testing::HasSubstr("PSS padding verification failed"));
}

TEST_F(PrivacyPassRsaBssaClientTest, FinalizeTokenTwice) {
  // Create token request.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      TokenRequest token_req,
      client_->CreateTokenRequest(challenge_encoding_, nonce_, token_key_id_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const std::string signature,
      TestSign(token_req.blinded_token_request, rsa_private_key_.get()));
  // Finalize the token.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Token _,
                                   client_->FinalizeToken(signature));
  // Finalize the token again.
  absl::StatusOr<Token> token_2 = client_->FinalizeToken(signature);

  EXPECT_FALSE(token_2.status().ok());
  EXPECT_EQ(token_2.status().code(), absl::StatusCode::kFailedPrecondition);
  EXPECT_THAT(token_2.status().message(),
              ::testing::HasSubstr(
                  "RsaBlinder is in wrong state to unblind signature"));
}

TEST_F(PrivacyPassRsaBssaClientTest, FinalizeTokenWithWrongClient) {
  // Create token request.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      TokenRequest token_req_1,
      client_->CreateTokenRequest(challenge_encoding_, nonce_, token_key_id_));
  // Create a request with client_2.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<PrivacyPassRsaBssaClient> client_2,
      PrivacyPassRsaBssaClient::Create(*rsa_public_key_.get()));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      TokenRequest _,
      client_2->CreateTokenRequest(challenge_encoding_, nonce_, token_key_id_));
  // Compute correct signature for client_, given token_req_1.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const std::string signature,
      TestSign(token_req_1.blinded_token_request, rsa_private_key_.get()));
  // Finalize the token with wrong client_2.
  absl::StatusOr<Token> token = client_2->FinalizeToken(signature);

  EXPECT_FALSE(token.status().ok());
  EXPECT_EQ(token.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(token.status().message(),
              ::testing::HasSubstr("PSS padding verification failed"));
}

TEST_F(PrivacyPassRsaBssaClientTest, VerifyWithWrongPublicKey) {
  // Create token request.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      TokenRequest token_req,
      client_->CreateTokenRequest(challenge_encoding_, nonce_, token_key_id_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const std::string signature,
      TestSign(token_req.blinded_token_request, rsa_private_key_.get()));
  // Finalize the token.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Token token,
                                   client_->FinalizeToken(signature));
  // Run public key verification using a new key.
  auto [test_rsa_public_key, _] = GetAnotherStrongTestRsaKeyPair2048();
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<RSA> wrong_rsa_public_key,
      CreatePublicKeyRSA(test_rsa_public_key.n, test_rsa_public_key.e));
  absl::Status verification =
      PrivacyPassRsaBssaClient::Verify(token, *wrong_rsa_public_key.get());

  EXPECT_FALSE(verification.ok());
  EXPECT_EQ(verification.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(verification.message(),
              ::testing::HasSubstr("PSS padding verification failed"));
}

TEST_F(PrivacyPassRsaBssaClientTest, TokenCreationAndVerificationSuccess) {
  // Create token request.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      TokenRequest token_req,
      client_->CreateTokenRequest(challenge_encoding_, nonce_, token_key_id_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const std::string signature,
      TestSign(token_req.blinded_token_request, rsa_private_key_.get()));
  // Finalize the token.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Token token,
                                   client_->FinalizeToken(signature));
  // Run public key verification successfully.
  EXPECT_TRUE(
      PrivacyPassRsaBssaClient::Verify(token, *rsa_public_key_.get()).ok());
}

}  // namespace
}  // namespace anonymous_tokens
