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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "anonymous_tokens/cpp/testing/utils.h"

namespace anonymous_tokens {
namespace {

TEST(AnonymousTokensAthmTokenEncodingsTest, EmptyMarshalAthmTokenTest) {
  AthmToken token;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string encoded_token,
                                   MarshalAthmToken(token));
  std::string expected_token_encoding;
  ASSERT_TRUE(absl::HexStringToBytes("C07E", &expected_token_encoding));

  EXPECT_EQ(encoded_token, expected_token_encoding);
}

TEST(AnonymousTokensAthmTokenEncodingsTest, MarshalAndUnmarshalAthmTokenTest) {
  std::string issuer_key_id;
  ASSERT_TRUE(absl::HexStringToBytes(
      "ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708",
      &issuer_key_id));
  std::string token_str;
  ASSERT_TRUE(absl::HexStringToBytes(
      "4ed3f2a25ec528543d9a83c850d12b3036b518fafec080df3efcd9693b944d0560568620"
      "0d6500f249475737ea9246a70c3c2a1ff280663e46c792a8ae0d9a6877d1b427bbae7129"
      "b88c92ad61c08a9fe41629a642263e4857e428a706ba87659361",
      &token_str));
  AthmToken token = {/*token_type=*/0XC07E, std::move(issuer_key_id),
                     std::move(token_str)};

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string encoded_token,
                                   MarshalAthmToken(token));

  std::string expected_token_encoding;
  ASSERT_TRUE(absl::HexStringToBytes(
      "C07Eca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd27084ed3"
      "f2a25ec528543d9a83c850d12b3036b518fafec080df3efcd9693b944d05605686200d65"
      "00f249475737ea9246a70c3c2a1ff280663e46c792a8ae0d9a6877d1b427bbae7129b88c"
      "92ad61c08a9fe41629a642263e4857e428a706ba87659361",
      &expected_token_encoding));
  EXPECT_EQ(encoded_token, expected_token_encoding);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const AthmToken token2,
                                   UnmarshalAthmToken(encoded_token));
  EXPECT_EQ(token.token_type, token2.token_type);
  EXPECT_EQ(token.issuer_key_id, token2.issuer_key_id);
  EXPECT_EQ(token.token, token2.token);
}

TEST(AnonymousTokensAthmTokenEncodingsTest, UnmarshalAthmTokenTooShort) {
  std::string short_token;
  ASSERT_TRUE(absl::HexStringToBytes("C07E5f5e466042", &short_token));
  EXPECT_FALSE(UnmarshalAthmToken(short_token).ok());
}

TEST(AnonymousTokensAthmTokenEncodingsTest, UnmarshalAthmTokenTooLong) {
  std::string long_token;
  ASSERT_TRUE(absl::HexStringToBytes(
      "C07Eca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd27084ed3"
      "f2a25ec528543d9a83c850d12b3036b518fafec080df3efcd9693b944d05605686200d65"
      "00f249475737ea9246a70c3c2a1ff280663e46c792a8ae0d9a6877d1b427bbae7129b88c"
      "92ad61c08a9fe41629a642263e4857e428a706ba876593618888",
      &long_token));
  EXPECT_FALSE(UnmarshalAthmToken(long_token).ok());
}

TEST(AnonymousTokensAthmTokenEncodingsTest, UnmarshalAthmTokenWrongType) {
  std::string token;
  ASSERT_TRUE(absl::HexStringToBytes(
      "DA7Aca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd27084ed3"
      "f2a25ec528543d9a83c850d12b3036b518fafec080df3efcd9693b944d05605686200d65"
      "00f249475737ea9246a70c3c2a1ff280663e46c792a8ae0d9a6877d1b427bbae7129b88c"
      "92ad61c08a9fe41629a642263e4857e428a706ba87659361",
      &token));
  EXPECT_FALSE(UnmarshalAthmToken(token).ok());
}

TEST(AnonymousTokensAthmTokenEncodingsTest,
     MarshalAndUnmarshalAthmTokenRequest) {
  std::string athm_token_request;
  ASSERT_TRUE(absl::HexStringToBytes(
      "4ed3f2a25ec528543d9a83c850d12b3036b518fafec080df3efcd9693b944d0560",
      &athm_token_request));
  AthmTokenRequest token_request{
      .token_type = 0xC07E,
      .truncated_issuer_key_id = 0x12,
      .encoded_request = std::move(athm_token_request)};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string encoded_token_request,
                                   MarshalAthmTokenRequest(token_request));

  std::string expected_token_request_encoding;
  ASSERT_TRUE(
      absl::HexStringToBytes("C07E124ed3f2a25ec528543d9a83c850d12b3036b518fafec"
                             "080df3efcd9693b944d0560",
                             &expected_token_request_encoding));

  EXPECT_EQ(encoded_token_request, expected_token_request_encoding);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AthmTokenRequest decoded_token_request,
      UnmarshalAthmTokenRequest(encoded_token_request));

  EXPECT_EQ(decoded_token_request.token_type, token_request.token_type);
  EXPECT_EQ(decoded_token_request.truncated_issuer_key_id,
            token_request.truncated_issuer_key_id);
  EXPECT_EQ(decoded_token_request.encoded_request,
            token_request.encoded_request);
}

TEST(AnonymousTokensAthmTokenEncodingsTest,
     UnmarshalAthmTokenRequestWrongTokenType) {
  std::string token_request_encoding;
  ASSERT_TRUE(
      absl::HexStringToBytes("DA7A124ed3f2a25ec528543d9a83c850d12b3036b518fafec"
                             "080df3efcd9693b944d0560",
                             &token_request_encoding));
  absl::StatusOr<AthmTokenRequest> token_request =
      UnmarshalAthmTokenRequest(token_request_encoding);

  EXPECT_EQ(token_request.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(token_request.status().message(),
              ::testing::HasSubstr("unsupported token type"));
}

TEST(AnonymousTokensAthmTokenEncodingsTest, UnmarshalAthmTokenRequestTooShort) {
  std::string token_request_encoding;
  ASSERT_TRUE(
      absl::HexStringToBytes("C07E124ed3f2a25ec528543d9a83c850d12b3036b518fafec"
                             "080df3efcd9693b944d05",
                             &token_request_encoding));
  absl::StatusOr<AthmTokenRequest> token_request =
      UnmarshalAthmTokenRequest(token_request_encoding);

  EXPECT_EQ(token_request.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(token_request.status().message(),
              ::testing::HasSubstr(
                  "failed to read athm_token_request.encoded_request"));
}

TEST(AnonymousTokensAthmTokenEncodingsTest, UnmarshalAthmTokenRequestTooLong) {
  std::string token_request_encoding;
  ASSERT_TRUE(
      absl::HexStringToBytes("C07E124ed3f2a25ec528543d9a83c850d12b3036b518fafec"
                             "080df3efcd9693b944d056088",
                             &token_request_encoding));
  absl::StatusOr<AthmTokenRequest> token_request =
      UnmarshalAthmTokenRequest(token_request_encoding);

  EXPECT_EQ(token_request.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(token_request.status().message(),
              ::testing::HasSubstr("token request had extra bytes"));
}

}  // namespace
}  // namespace anonymous_tokens
