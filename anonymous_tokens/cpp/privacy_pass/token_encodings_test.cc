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

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "anonymous_tokens/cpp/testing/utils.h"


namespace anonymous_tokens {
namespace {

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest,
     EmptyAuthenticatorInputTest) {
  Token token;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string authenticator_input,
                                   AuthenticatorInput(token));

  std::string expected_authenticator_input_encoding =
      absl::HexStringToBytes("DA7A");

  EXPECT_EQ(authenticator_input, expected_authenticator_input_encoding);
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, AuthenticatorInputTest) {
  Token token = {
      /*token_type=*/0XDA7A, /*token_key_id=*/
      absl::HexStringToBytes(
          "ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708"),
      /*nonce=*/
      absl::HexStringToBytes(
          "5f5e46604255ac6a8ae0820f5b20c236118d97d917509ccbc96b5a82ae40ebeb"),
      /*context=*/
      absl::HexStringToBytes(
          "11e15c91a7c2ad02abd66645802373db1d823bea80f08d452541fb2b62b5898b")};

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string authenticator_input,
                                   AuthenticatorInput(token));

  std::string expected_authenticator_input_encoding = absl::HexStringToBytes(
      "DA7A5f5e46604255ac6a8ae0820f5b20c236118d97d917509ccbc96b5a82ae40ebeb11e1"
      "5c91a7c2ad02abd66645802373db1d823bea80f08d452541fb2b62b5898bca572f8982a9"
      "ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708");
  EXPECT_EQ(authenticator_input, expected_authenticator_input_encoding);
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, EmptyMarshalTokenTest) {
  Token token;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string encoded_token,
                                   MarshalToken(token));
  std::string expected_token_encoding = absl::HexStringToBytes("DA7A");

  EXPECT_EQ(encoded_token, expected_token_encoding);
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, MarshalTokenTest) {
  Token token = {
      /*token_type=*/0XDA7A, /*token_key_id=*/
      absl::HexStringToBytes(
          "ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708"),
      /*nonce=*/
      absl::HexStringToBytes(
          "5f5e46604255ac6a8ae0820f5b20c236118d97d917509ccbc96b5a82ae40ebeb"),
      /*context=*/
      absl::HexStringToBytes(
          "11e15c91a7c2ad02abd66645802373db1d823bea80f08d452541fb2b62b5898b"),
      /*authenticator=*/
      absl::HexStringToBytes(
          "4ed3f2a25ec528543d9a83c850d12b3036b518fafec080df3efcd9693b944d056056"
          "86200d6500f249475737ea9246a70c3c2a1ff280663e46c792a8ae0d9a6877d1b427"
          "bbae7129b88c92ad61c08a9fe41629a642263e4857e428a706ba87659361fed38087"
          "c0e881f5e15668e0701d7edd63be98fcc7415819d466c61341de03d7e2a24181d7b9"
          "321b0826d59402a87e08514f36cc45b0f7aac0e9a6578ddb0534c8ebe528c693b6ef"
          "b54e76a5a8056f5c27d01ad42119953c5987b05c9ae2ca04b12838e641b4b1aac21e"
          "36f18573f603735fac1f8f611029e4cb76c8a5cc6f2c4143474e458c8d2ca8e9a71f"
          "01d90e0d2d784874ff000ae105483941652e")};

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string encoded_token,
                                   MarshalToken(token));

  std::string expected_token_encoding = absl::HexStringToBytes(
      "DA7A5f5e46604255ac6a8ae0820f5b20c236118d97d917509ccbc96b5a82ae40ebeb11e1"
      "5c91a7c2ad02abd66645802373db1d823bea80f08d452541fb2b62b5898bca572f8982a9"
      "ca248a3056186322d93ca147266121ddeb5632c07f1f71cd27084ed3f2a25ec528543d9a"
      "83c850d12b3036b518fafec080df3efcd9693b944d05605686200d6500f249475737ea92"
      "46a70c3c2a1ff280663e46c792a8ae0d9a6877d1b427bbae7129b88c92ad61c08a9fe416"
      "29a642263e4857e428a706ba87659361fed38087c0e881f5e15668e0701d7edd63be98fc"
      "c7415819d466c61341de03d7e2a24181d7b9321b0826d59402a87e08514f36cc45b0f7aa"
      "c0e9a6578ddb0534c8ebe528c693b6efb54e76a5a8056f5c27d01ad42119953c5987b05c"
      "9ae2ca04b12838e641b4b1aac21e36f18573f603735fac1f8f611029e4cb76c8a5cc6f2c"
      "4143474e458c8d2ca8e9a71f01d90e0d2d784874ff000ae105483941652e");
  EXPECT_EQ(encoded_token, expected_token_encoding);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Token token2,
                                   UnmarshalToken(encoded_token));
  EXPECT_EQ(token.token_type, token2.token_type);
  EXPECT_EQ(token.token_key_id, token2.token_key_id);
  EXPECT_EQ(token.context, token2.context);
  EXPECT_EQ(token.nonce, token2.nonce);
  EXPECT_EQ(token.authenticator, token2.authenticator);
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, UnmarshalTooShort) {
  const std::string short_token = absl::HexStringToBytes("DA7A5f5e466042");
  EXPECT_FALSE(UnmarshalToken(short_token).ok());
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, UnmarshalTooLong) {
  std::string long_token = absl::HexStringToBytes(
      "DA7A5f5e46604255ac6a8ae0820f5b20c236118d97d917509ccbc96b5a82ae40ebeb11e1"
      "5c91a7c2ad02abd66645802373db1d823bea80f08d452541fb2b62b5898bca572f8982a9"
      "ca248a3056186322d93ca147266121ddeb5632c07f1f71cd27084ed3f2a25ec528543d9a"
      "83c850d12b3036b518fafec080df3efcd9693b944d05605686200d6500f249475737ea92"
      "46a70c3c2a1ff280663e46c792a8ae0d9a6877d1b427bbae7129b88c92ad61c08a9fe416"
      "29a642263e4857e428a706ba87659361fed38087c0e881f5e15668e0701d7edd63be98fc"
      "c7415819d466c61341de03d7e2a24181d7b9321b0826d59402a87e08514f36cc45b0f7aa"
      "c0e9a6578ddb0534c8ebe528c693b6efb54e76a5a8056f5c27d01ad42119953c5987b05c"
      "9ae2ca04b12838e641b4b1aac21e36f18573f603735fac1f8f611029e4cb76c8a5cc6f2c"
      "4143474e458c8d2ca8e9a71f01d90e0d2d784874ff000ae105483941652eXXXXXXXXX");
  EXPECT_FALSE(UnmarshalToken(long_token).ok());
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, UnmarshalWrongType) {
  std::string token = absl::HexStringToBytes(
      "DA7B5f5e46604255ac6a8ae0820f5b20c236118d97d917509ccbc96b5a82ae40ebeb11e1"
      "5c91a7c2ad02abd66645802373db1d823bea80f08d452541fb2b62b5898bca572f8982a9"
      "ca248a3056186322d93ca147266121ddeb5632c07f1f71cd27084ed3f2a25ec528543d9a"
      "83c850d12b3036b518fafec080df3efcd9693b944d05605686200d6500f249475737ea92"
      "46a70c3c2a1ff280663e46c792a8ae0d9a6877d1b427bbae7129b88c92ad61c08a9fe416"
      "29a642263e4857e428a706ba87659361fed38087c0e881f5e15668e0701d7edd63be98fc"
      "c7415819d466c61341de03d7e2a24181d7b9321b0826d59402a87e08514f36cc45b0f7aa"
      "c0e9a6578ddb0534c8ebe528c693b6efb54e76a5a8056f5c27d01ad42119953c5987b05c"
      "9ae2ca04b12838e641b4b1aac21e36f18573f603735fac1f8f611029e4cb76c8a5cc6f2c"
      "4143474e458c8d2ca8e9a71f01d90e0d2d784874ff000ae105483941652e");
  EXPECT_FALSE(UnmarshalToken(token).ok());
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, EmptyExtensionTest) {
  Extension extension;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string encoded_extension,
                                   EncodeExtension(extension));

  std::string expected_extension_encoding = absl::HexStringToBytes("00010000");
  EXPECT_EQ(encoded_extension, expected_extension_encoding);
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest,
     ExtensionValueSizeOfMoreThanTwoBytes) {
  // Input string of size more than 2 bytes.
  std::string large_test_value = std::string(65536, 'a');
  // Random hex number to populate the uint16_t extension_type.
  Extension extension = {/*extension_type=*/0x5E6D,
                         /*extension_value=*/large_test_value};
  absl::StatusOr<std::string> encoded_extension = EncodeExtension(extension);

  EXPECT_EQ(encoded_extension.status().code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(encoded_extension.status().message(),
              ::testing::HasSubstr("Failed to generate extension encoding"));
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, ExtensionEncodingSuccess) {
  Extension extension = {
      // Random hex number to populate the uint16_t extension_type.
      /*extension_type=*/0x5E6D,
      // Random hex string to populate extension_value.
      /*extension_value=*/absl::HexStringToBytes(
          "46a70c3c2a1ff280663e46c792a8ae0d9a6877d1b427bbae7129b88c92ad61c08a9f"
          "e41629a642263e4857e428a706ba87659361fed38087c0e881f5e15668e0701d7edd"
          "63be98fcc7415819d466c61341de03d7e2a24181d7b9321b0826d59402a87e08514f"
          "36cc45b0f7aa")};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string encoded_extension,
                                   EncodeExtension(extension));
  // The first 2 bytes of the expected_extension_encoding store the
  // extension_type. The next two bytes store the number of bytes needed for the
  // extension_value. These 4 bytes are then prefixed to the extension_value.
  std::string expected_extension_encoding = absl::HexStringToBytes(
      "5e6d006c46a70c3c2a1ff280663e46c792a8ae0d9a6877d1b427bbae7129b88c92ad61c0"
      "8a9fe41629a642263e4857e428a706ba87659361fed38087c0e881f5e15668e0701d7edd"
      "63be98fcc7415819d466c61341de03d7e2a24181d7b9321b0826d59402a87e08514f36cc"
      "45b0f7aa");
  EXPECT_EQ(encoded_extension, expected_extension_encoding);
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, EmptyExtensionsTest) {
  Extensions extensions;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string encoded_extensions,
                                   EncodeExtensions(extensions));

  std::string expected_extensions_encoding = absl::HexStringToBytes("0000");
  EXPECT_EQ(encoded_extensions, expected_extensions_encoding);
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest,
     ExtensionsListSizeOfMoreThanTwoBytes) {
  std::string large_test_value = std::string(65532, 'a');
  Extensions extensions;
  extensions.extensions.push_back(
      {// Random hex number to populate the uint16_t extension_type.
       /*extension_type=*/0x5E6D,
       /*extension_value=*/large_test_value});
  absl::StatusOr<std::string> encoded_extensions = EncodeExtensions(extensions);
  // The string encoding of this extensions struct will take at least 65536
  // bytes. This length is not be storable in 2 bytes.
  EXPECT_EQ(encoded_extensions.status().code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(
      encoded_extensions.status().message(),
      ::testing::HasSubstr("Failed to generate encoded extensions list"));
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest,
     SingleExtensionInExtensionsSuccess) {
  Extensions extensions;
  extensions.extensions.push_back(Extension{
      // Random hex number to populate the uint16_t extension_type.
      /*extension_type=*/0x5E6D,
      // Random hex string to populate extension_value.
      /*extension_value=*/absl::HexStringToBytes(
          "46a70c3c2a1ff280663e46c792a8ae0d9a6877d1b427bbae7129b88c92"
          "ad61c08a9fe41629a642263e4857e428a706ba87659361fed38087c0e8"
          "81f5e15668e0701d7edd63be98fcc7415819d466c61341de03d7e2a241"
          "81d7b9321b0826d59402a87e08514f36cc45b0f7aa")});
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string encoded_extensions,
                                   EncodeExtensions(extensions));
  // The first 2 bytes of the expected_extensions_encoding store the length of
  // the rest of the string. The rest of the string is the concatenation
  // of individually encoded extensions.
  std::string expected_extensions_encoding = absl::HexStringToBytes(
      "00705e6d006c46a70c3c2a1ff280663e46c792a8ae0d9a6877d1b427bbae7129b88c92ad"
      "61c08a9fe41629a642263e4857e428a706ba87659361fed38087c0e881f5e15668e0701d"
      "7edd63be98fcc7415819d466c61341de03d7e2a24181d7b9321b0826d59402a87e08514f"
      "36cc45b0f7aa");
  EXPECT_EQ(encoded_extensions, expected_extensions_encoding);
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest,
     MultipleExtensionsEncodingSuccess) {
  Extensions extensions;
  extensions.extensions.push_back(
      Extension{/*extension_type=*/0x0001,
                /*extension_value=*/absl::HexStringToBytes("01")});
  extensions.extensions.push_back(
      Extension{/*extension_type=*/0x0002,
                /*extension_value=*/absl::HexStringToBytes("0202")});
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const std::string encoded_extensions,
                                   EncodeExtensions(extensions));
  // The first 2 bytes of the expected_extensions_encoding store the length of
  // the rest of the string. The rest of the string is the concatenation
  // of individually encoded extensions.
  std::string expected_extensions_encoding =
      absl::HexStringToBytes("000b0001000101000200020202");
  EXPECT_EQ(encoded_extensions, expected_extensions_encoding);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Extensions extensions2,
                                   DecodeExtensions(encoded_extensions));
  EXPECT_EQ(extensions2.extensions.size(), extensions.extensions.size());
  for (int i = 0; i < extensions.extensions.size(); ++i) {
    EXPECT_EQ(extensions2.extensions[i].extension_type,
              extensions.extensions[i].extension_type);
    EXPECT_EQ(extensions2.extensions[i].extension_value,
              extensions.extensions[i].extension_value);
  }
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest,
     ExpirationTimestampRoundTrip) {
  ExpirationTimestamp et{.timestamp_precision = 3600, .timestamp = 1688583600};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Extension ext, et.AsExtension());
  EXPECT_EQ(ext.extension_type, 0x0001);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const ExpirationTimestamp et2,
                                   ExpirationTimestamp::FromExtension(ext));
  EXPECT_EQ(et.timestamp_precision, et2.timestamp_precision);
  EXPECT_EQ(et.timestamp, et2.timestamp);
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest,
     ExpirationTimestampWrongType) {
  const Extension ext = {.extension_type = 0x0002, .extension_value = ""};
  EXPECT_FALSE(ExpirationTimestamp::FromExtension(ext).ok());
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, DecodeExtensions) {
  const std::string encoded_extensions =
      absl::HexStringToBytes("0014000100100000000000000E100000000064A5BDB0");
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Extensions extensions,
                                   DecodeExtensions(encoded_extensions));
  EXPECT_EQ(extensions.extensions.size(), 1);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const ExpirationTimestamp et,
      ExpirationTimestamp::FromExtension(extensions.extensions[0]));
  EXPECT_EQ(et.timestamp_precision, 3600);
  EXPECT_EQ(et.timestamp, 1688583600);
  Extensions extensions2;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Extension ext2, et.AsExtension());
  extensions2.extensions.push_back(ext2);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const std::string encoded_extensions2,
                                   EncodeExtensions(extensions2));
  EXPECT_EQ(absl::BytesToHexString(encoded_extensions2),
            absl::BytesToHexString(encoded_extensions));
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, DecodeTooShort) {
  const std::string encoded_extensions =
      absl::HexStringToBytes("00140001001000");
  const absl::StatusOr<Extensions> extensions =
      DecodeExtensions(encoded_extensions);
  EXPECT_FALSE(extensions.ok()) << extensions.status();
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, DecodeTooLong) {
  const std::string encoded_extensions = absl::HexStringToBytes(
      "0014000100100000000000000E100000000064A5BDB012345");
  const absl::StatusOr<Extensions> extensions =
      DecodeExtensions(encoded_extensions);
  EXPECT_FALSE(extensions.ok());
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, GeoHintRoundTrip) {
  GeoHint gh{.geo_hint = "US,US-AL,ALABASTER"};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Extension ext, gh.AsExtension());
  EXPECT_EQ(ext.extension_type, 0x0002);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const GeoHint gh2,
                                   GeoHint::FromExtension(ext));
  EXPECT_EQ(gh.geo_hint, gh2.geo_hint);
  EXPECT_EQ(gh2.country_code, "US");
  EXPECT_EQ(gh2.region, "US-AL");
  EXPECT_EQ(gh2.city, "ALABASTER");
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, GeoHintNoPostal) {
  GeoHint gh{.geo_hint = "US,US-AL,ALABASTER,FOO"};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Extension ext, gh.AsExtension());
  EXPECT_FALSE(GeoHint::FromExtension(ext).ok());
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, GeoHintNoLowercase) {
  GeoHint gh{.geo_hint = "US,US-AL,Alabaster"};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Extension ext, gh.AsExtension());
  EXPECT_FALSE(GeoHint::FromExtension(ext).ok());
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, GeoHintTooShort) {
  GeoHint gh{.geo_hint = "US,US-AL"};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Extension ext, gh.AsExtension());
  EXPECT_FALSE(GeoHint::FromExtension(ext).ok());
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, GeoHintEmptyOk) {
  GeoHint gh{.geo_hint = "US,,"};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Extension ext, gh.AsExtension());
  EXPECT_TRUE(GeoHint::FromExtension(ext).ok());
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, ServiceTypeRoundTrip) {
  ServiceType st{.service_type_id = 0x01};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Extension ext, st.AsExtension());
  EXPECT_EQ(ext.extension_type, 0xF001);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const ServiceType st2,
                                   ServiceType::FromExtension(ext));
  EXPECT_EQ(st.service_type_id, st2.service_type_id);
  EXPECT_EQ(st2.service_type, "chromeipblinding");
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, WrongExtId) {
  ServiceType st{.service_type_id = 0x01};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(Extension ext, st.AsExtension());
  ext.extension_type = 0xF002;
  EXPECT_FALSE(ServiceType::FromExtension(ext).ok());
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, WrongServiceTypeId) {
  ServiceType st{.service_type_id = 0x02};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(Extension ext, st.AsExtension());
  EXPECT_EQ(ext.extension_type, 0xF001);
  EXPECT_FALSE(ServiceType::FromExtension(ext).ok());
}

TEST(AnonymousTokensDebugMode, RoundTrip) {
  DebugMode dm{.mode = DebugMode::kProd};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const Extension ext, dm.AsExtension());
  EXPECT_EQ(ext.extension_type, 0xF002);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const DebugMode dm2,
                                   DebugMode::FromExtension(ext));
  EXPECT_EQ(dm.mode, dm2.mode);
}

TEST(AnonymousTokensDebugMode, WrongExtId) {
  DebugMode dm{.mode = DebugMode::kProd};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(Extension ext, dm.AsExtension());
  ext.extension_type = 0xF003;
  EXPECT_FALSE(ServiceType::FromExtension(ext).ok());
}

TEST(AnonymousTokensDebugMode, InvalidMode) {
  DebugMode dm{.mode = DebugMode::kProd};
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(Extension ext, dm.AsExtension());
  EXPECT_EQ(ext.extension_type, 0xF002);
  ext.extension_value = std::string("~");
  EXPECT_FALSE(DebugMode::FromExtension(ext).ok());
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest,
     EmptyMarshalTokenChallengeTest) {
  TokenChallenge token_challenge;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string encoded_token,
                                   MarshalTokenChallenge(token_challenge));

  std::string expected_token_encoding = absl::HexStringToBytes("DA7A0000");

  EXPECT_EQ(encoded_token, expected_token_encoding);
}

TEST(AnonymousTokensPrivacyPassTokenEncodingsTest, MarshalTokenChallengeTest) {
  TokenChallenge token_challenge;
  token_challenge.issuer_name = "issuer.google.com";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string encoded_token,
                                   MarshalTokenChallenge(token_challenge));

  std::string expected_token_encoding =
      absl::HexStringToBytes("da7a00116973737565722e676f6f676c652e636f6d");

  EXPECT_EQ(encoded_token, expected_token_encoding);
}

}  // namespace
}  // namespace anonymous_tokens

