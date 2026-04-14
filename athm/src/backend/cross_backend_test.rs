// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Cross-backend integration tests for ATHM.
//!
//! These tests verify that the BoringSSL and RustCrypto backends produce
//! identical outputs for all deterministic operations, ensuring protocol
//! compatibility between the two backends.
//!
//! Note: Both features `rustcrypto` and `boringssl` must be enabled for
//! this test to compile.

#[cfg(all(feature = "rustcrypto", feature = "boringssl"))]
mod cross_backend_tests {
    use crate::backend::boringssl;
    use crate::backend::rustcrypto;

    // -----------------------------------------------------------------------
    // Helper: compare serialized outputs from both backends
    // -----------------------------------------------------------------------

    fn rustcrypto_point_bytes(p: &rustcrypto::RustCryptoPoint) -> Vec<u8> {
        let mut out = Vec::new();
        rustcrypto::encode_point(p, &mut out);
        out
    }

    fn boringssl_point_bytes(p: &boringssl::BsslPoint) -> Vec<u8> {
        let mut out = Vec::new();
        boringssl::encode_point(p, &mut out);
        out
    }

    fn rustcrypto_scalar_bytes(s: &rustcrypto::RustCryptoScalar) -> Vec<u8> {
        let mut out = Vec::new();
        rustcrypto::encode_scalar(s, &mut out);
        out
    }

    fn boringssl_scalar_bytes(s: &boringssl::BsslScalar) -> Vec<u8> {
        let mut out = Vec::new();
        boringssl::encode_scalar(s, &mut out);
        out
    }

    // -----------------------------------------------------------------------
    // Tests: hash_to_point
    // -----------------------------------------------------------------------

    #[test]
    fn test_hash_to_point_parity() {
        // Various message/DST combinations
        let test_cases: Vec<(&[&[u8]], &[&[u8]])> = vec![
            (&[b"test"], &[b"DST"]),
            (&[b"hello world"], &[b"MyDST"]),
            (&[b""], &[b"EmptyMsg"]),
            (&[b"msg1", b"msg2"], &[b"DST1", b"DST2"]),
            (&[b"a", b"b", b"c"], &[b"X", b"Y"]),
        ];

        for (msgs, dsts) in &test_cases {
            let rc_point =
                rustcrypto::hash_to_point(msgs, dsts).expect("rustcrypto hash_to_point failed");
            let bssl_point =
                boringssl::hash_to_point(msgs, dsts).expect("boringssl hash_to_point failed");

            let rc_bytes = rustcrypto_point_bytes(&rc_point);
            let bssl_bytes = boringssl_point_bytes(&bssl_point);

            assert_eq!(
                rc_bytes, bssl_bytes,
                "hash_to_point mismatch for msgs={:?}, dsts={:?}\n  rustcrypto: {:02x?}\n  boringssl:  {:02x?}",
                msgs, dsts, rc_bytes, bssl_bytes
            );
        }
    }

    #[test]
    fn test_hash_to_point_with_athm_style_dsts() {
        // Test with the same DST format used in the actual ATHM protocol
        let context_string = b"ATHMV1-P256-4-test_deployment_id";
        let msgs: &[&[u8]] = &[b"some_point_data"];
        let dsts: &[&[u8]] = &[b"HashToGroup-", context_string.as_slice(), b"generatorH"];

        let rc_point =
            rustcrypto::hash_to_point(msgs, dsts).expect("rustcrypto hash_to_point failed");
        let bssl_point =
            boringssl::hash_to_point(msgs, dsts).expect("boringssl hash_to_point failed");

        assert_eq!(
            rustcrypto_point_bytes(&rc_point),
            boringssl_point_bytes(&bssl_point),
            "hash_to_point mismatch with ATHM-style DSTs"
        );
    }

    // -----------------------------------------------------------------------
    // Tests: hash_to_scalar
    // -----------------------------------------------------------------------

    #[test]
    fn test_hash_to_scalar_parity() {
        let test_cases: Vec<(&[&[u8]], &[&[u8]])> = vec![
            (&[b"test"], &[b"DST"]),
            (&[b"hello world"], &[b"MyDST"]),
            (&[b""], &[b"EmptyMsg"]),
            (&[b"msg1", b"msg2"], &[b"DST1", b"DST2"]),
            (&[b"a", b"b", b"c"], &[b"X", b"Y"]),
        ];

        for (msgs, dsts) in &test_cases {
            let rc_scalar =
                rustcrypto::hash_to_scalar(msgs, dsts).expect("rustcrypto hash_to_scalar failed");
            let bssl_scalar =
                boringssl::hash_to_scalar(msgs, dsts).expect("boringssl hash_to_scalar failed");

            let rc_bytes = rustcrypto_scalar_bytes(&rc_scalar);
            let bssl_bytes = boringssl_scalar_bytes(&bssl_scalar);

            assert_eq!(
                rc_bytes, bssl_bytes,
                "hash_to_scalar mismatch for msgs={:?}, dsts={:?}\n  rustcrypto: {:02x?}\n  boringssl:  {:02x?}",
                msgs, dsts, rc_bytes, bssl_bytes
            );
        }
    }

    #[test]
    fn test_hash_to_scalar_with_athm_style_dsts() {
        // Test with DST formats matching the ATHM Transcript::challenge method
        let context_string = b"ATHMV1-P256-4-test_deployment_id";

        // Simulate a challenge hash similar to what the protocol does
        let scalar_bytes = [0u8; 32];
        let point_bytes = [0u8; 33];
        let len_bytes = (32u16).to_be_bytes();
        let len_bytes2 = (33u16).to_be_bytes();

        let msgs: &[&[u8]] = &[&len_bytes, &scalar_bytes, &len_bytes2, &point_bytes];
        let dsts: &[&[u8]] = &[b"HashToScalar-", context_string.as_slice(), b"KeyCommitments"];

        let rc_scalar =
            rustcrypto::hash_to_scalar(msgs, dsts).expect("rustcrypto hash_to_scalar failed");
        let bssl_scalar =
            boringssl::hash_to_scalar(msgs, dsts).expect("boringssl hash_to_scalar failed");

        assert_eq!(
            rustcrypto_scalar_bytes(&rc_scalar),
            boringssl_scalar_bytes(&bssl_scalar),
            "hash_to_scalar mismatch with ATHM-style DSTs"
        );
    }

    // -----------------------------------------------------------------------
    // Tests: generator point
    // -----------------------------------------------------------------------

    #[test]
    fn test_generator_parity() {
        let rc_gen = rustcrypto::point_generator();
        let bssl_gen = boringssl::point_generator();

        assert_eq!(
            rustcrypto_point_bytes(&rc_gen),
            boringssl_point_bytes(&bssl_gen),
            "Generator points differ between backends"
        );
    }

    // -----------------------------------------------------------------------
    // Tests: scalar encode/decode round-trips across backends
    // -----------------------------------------------------------------------

    #[test]
    fn test_scalar_cross_encode_decode() {
        // Encode with rustcrypto, decode with boringssl
        let test_values: Vec<u64> = vec![0, 1, 42, 256, 65535, u64::MAX];

        for v in &test_values {
            let rc_scalar = rustcrypto::RustCryptoScalar::from(*v);
            let rc_bytes = rustcrypto_scalar_bytes(&rc_scalar);

            let (bssl_decoded, _) = boringssl::decode_scalar(&rc_bytes);
            assert!(
                bool::from(bssl_decoded.is_some()),
                "boringssl failed to decode rustcrypto scalar for value {}",
                v
            );
            let bssl_bytes = boringssl_scalar_bytes(&bssl_decoded.unwrap());
            assert_eq!(rc_bytes, bssl_bytes, "Scalar round-trip mismatch for value {}", v);
        }

        // Encode with boringssl, decode with rustcrypto
        for v in &test_values {
            let bssl_scalar = boringssl::BsslScalar::from(*v);
            let bssl_bytes = boringssl_scalar_bytes(&bssl_scalar);

            let (rc_decoded, _) = rustcrypto::decode_scalar(&bssl_bytes);
            assert!(
                bool::from(rc_decoded.is_some()),
                "rustcrypto failed to decode boringssl scalar for value {}",
                v
            );
            let rc_bytes = rustcrypto_scalar_bytes(&rc_decoded.unwrap());
            assert_eq!(bssl_bytes, rc_bytes, "Scalar round-trip mismatch for value {}", v);
        }
    }

    // -----------------------------------------------------------------------
    // Tests: point encode/decode round-trips across backends
    // -----------------------------------------------------------------------

    #[test]
    fn test_point_cross_encode_decode() {
        // Encode generator with rustcrypto, decode with boringssl
        let rc_gen = rustcrypto::point_generator();
        let rc_bytes = rustcrypto_point_bytes(&rc_gen);

        let (bssl_decoded, _) =
            boringssl::decode_point(rc_bytes.as_slice().try_into().unwrap_or(&rc_bytes));
        assert!(
            bool::from(bssl_decoded.is_some()),
            "boringssl failed to decode rustcrypto generator"
        );
        let bssl_bytes = boringssl_point_bytes(&bssl_decoded.unwrap());
        assert_eq!(rc_bytes, bssl_bytes, "Generator cross-decode mismatch");

        // Encode generator with boringssl, decode with rustcrypto
        let bssl_gen = boringssl::point_generator();
        let bssl_bytes = boringssl_point_bytes(&bssl_gen);

        let (rc_decoded, _) = rustcrypto::decode_point(&bssl_bytes);
        assert!(
            bool::from(rc_decoded.is_some()),
            "rustcrypto failed to decode boringssl generator"
        );
        let rc_bytes2 = rustcrypto_point_bytes(&rc_decoded.unwrap());
        assert_eq!(bssl_bytes, rc_bytes2, "Generator cross-decode mismatch (bssl->rc)");
    }

    #[test]
    fn test_identity_point_cross_encode_decode() {
        // RustCrypto identity
        let rc_identity = rustcrypto::RustCryptoPoint::default();
        let rc_bytes = rustcrypto_point_bytes(&rc_identity);

        // BoringSSL identity
        let bssl_identity = boringssl::BsslPoint::IDENTITY;
        let bssl_bytes = boringssl_point_bytes(&bssl_identity);

        assert_eq!(rc_bytes, bssl_bytes, "Identity point encoding differs between backends");
    }

    #[test]
    fn test_hash_to_point_cross_decode() {
        // Hash to a point with rustcrypto, decode it with boringssl, and vice versa
        let msgs: &[&[u8]] = &[b"cross_decode_test"];
        let dsts: &[&[u8]] = &[b"TestDST"];

        let rc_point = rustcrypto::hash_to_point(msgs, dsts).unwrap();
        let rc_bytes = rustcrypto_point_bytes(&rc_point);

        let (bssl_decoded, _) = boringssl::decode_point(&rc_bytes);
        assert!(bool::from(bssl_decoded.is_some()));
        assert_eq!(rc_bytes, boringssl_point_bytes(&bssl_decoded.unwrap()));

        let bssl_point = boringssl::hash_to_point(msgs, dsts).unwrap();
        let bssl_bytes = boringssl_point_bytes(&bssl_point);

        let (rc_decoded, _) = rustcrypto::decode_point(&bssl_bytes);
        assert!(bool::from(rc_decoded.is_some()));
        assert_eq!(bssl_bytes, rustcrypto_point_bytes(&rc_decoded.unwrap()));
    }

    // -----------------------------------------------------------------------
    // Tests: generator H parity (protocol-critical)
    // -----------------------------------------------------------------------

    #[test]
    fn test_generator_h_parity() {
        // Generator H is derived via:
        //   H = hash_to_point([encode(G)], ["HashToGroup-" || context_string || "generatorH"])
        // This must be identical across both backends.

        let context_strings = [
            b"ATHMV1-P256-4-test_deployment_id".to_vec(),
            b"ATHMV1-P256-1-prod".to_vec(),
            b"ATHMV1-P256-255-max_buckets".to_vec(),
        ];

        for ctx in &context_strings {
            // Both backends should produce the same generator
            let rc_gen = rustcrypto::point_generator();
            let mut g_bytes_rc = Vec::new();
            rustcrypto::encode_point(&rc_gen, &mut g_bytes_rc);

            let bssl_gen = boringssl::point_generator();
            let mut g_bytes_bssl = Vec::new();
            boringssl::encode_point(&bssl_gen, &mut g_bytes_bssl);

            // Verify G is the same (sanity check)
            assert_eq!(g_bytes_rc, g_bytes_bssl, "Generator G mismatch");

            // Now compute H via both backends
            let msgs: &[&[u8]] = &[&g_bytes_rc];
            let dsts: &[&[u8]] = &[b"HashToGroup-", ctx.as_slice(), b"generatorH"];

            let rc_h = rustcrypto::hash_to_point(msgs, dsts).unwrap();
            let bssl_h = boringssl::hash_to_point(msgs, dsts).unwrap();

            assert_eq!(
                rustcrypto_point_bytes(&rc_h),
                boringssl_point_bytes(&bssl_h),
                "Generator H mismatch for context {:?}",
                String::from_utf8_lossy(ctx)
            );
        }
    }

    // -----------------------------------------------------------------------
    // Tests: scalar arithmetic parity
    // -----------------------------------------------------------------------

    #[test]
    fn test_scalar_arithmetic_parity() {
        use subtle::ConstantTimeEq;

        // Use hash_to_scalar to get deterministic scalars for testing
        let a_rc = rustcrypto::hash_to_scalar(&[b"scalar_a"], &[b"TestDST"]).unwrap();
        let b_rc = rustcrypto::hash_to_scalar(&[b"scalar_b"], &[b"TestDST"]).unwrap();
        let a_bssl = boringssl::hash_to_scalar(&[b"scalar_a"], &[b"TestDST"]).unwrap();
        let b_bssl = boringssl::hash_to_scalar(&[b"scalar_b"], &[b"TestDST"]).unwrap();

        // Verify inputs match
        assert_eq!(rustcrypto_scalar_bytes(&a_rc), boringssl_scalar_bytes(&a_bssl));
        assert_eq!(rustcrypto_scalar_bytes(&b_rc), boringssl_scalar_bytes(&b_bssl));

        // Addition
        let sum_rc = a_rc + b_rc;
        let sum_bssl = a_bssl + b_bssl;
        assert_eq!(
            rustcrypto_scalar_bytes(&sum_rc),
            boringssl_scalar_bytes(&sum_bssl),
            "Scalar addition mismatch"
        );

        // Subtraction
        let diff_rc = a_rc - b_rc;
        let diff_bssl = a_bssl - b_bssl;
        assert_eq!(
            rustcrypto_scalar_bytes(&diff_rc),
            boringssl_scalar_bytes(&diff_bssl),
            "Scalar subtraction mismatch"
        );

        // Multiplication
        let prod_rc = a_rc * b_rc;
        let prod_bssl = a_bssl * b_bssl;
        assert_eq!(
            rustcrypto_scalar_bytes(&prod_rc),
            boringssl_scalar_bytes(&prod_bssl),
            "Scalar multiplication mismatch"
        );

        // Negation
        let neg_rc = -a_rc;
        let neg_bssl = -a_bssl;
        assert_eq!(
            rustcrypto_scalar_bytes(&neg_rc),
            boringssl_scalar_bytes(&neg_bssl),
            "Scalar negation mismatch"
        );

        // Inversion
        let inv_rc = a_rc.invert().unwrap();
        let inv_bssl = a_bssl.invert().unwrap();
        assert_eq!(
            rustcrypto_scalar_bytes(&inv_rc),
            boringssl_scalar_bytes(&inv_bssl),
            "Scalar inversion mismatch"
        );
    }

    // -----------------------------------------------------------------------
    // Tests: point arithmetic parity
    // -----------------------------------------------------------------------

    #[test]
    fn test_point_arithmetic_parity() {
        // Get deterministic points via hash_to_point
        let p_rc = rustcrypto::hash_to_point(&[b"point_p"], &[b"TestDST"]).unwrap();
        let q_rc = rustcrypto::hash_to_point(&[b"point_q"], &[b"TestDST"]).unwrap();
        let p_bssl = boringssl::hash_to_point(&[b"point_p"], &[b"TestDST"]).unwrap();
        let q_bssl = boringssl::hash_to_point(&[b"point_q"], &[b"TestDST"]).unwrap();

        // Verify inputs match
        assert_eq!(rustcrypto_point_bytes(&p_rc), boringssl_point_bytes(&p_bssl));
        assert_eq!(rustcrypto_point_bytes(&q_rc), boringssl_point_bytes(&q_bssl));

        // Point addition
        let sum_rc = p_rc + q_rc;
        let sum_bssl = p_bssl + q_bssl;
        assert_eq!(
            rustcrypto_point_bytes(&sum_rc),
            boringssl_point_bytes(&sum_bssl),
            "Point addition mismatch"
        );

        // Point subtraction
        let diff_rc = p_rc - q_rc;
        let diff_bssl = p_bssl - q_bssl;
        assert_eq!(
            rustcrypto_point_bytes(&diff_rc),
            boringssl_point_bytes(&diff_bssl),
            "Point subtraction mismatch"
        );

        // Point negation
        let neg_rc = -p_rc;
        let neg_bssl = -p_bssl;
        assert_eq!(
            rustcrypto_point_bytes(&neg_rc),
            boringssl_point_bytes(&neg_bssl),
            "Point negation mismatch"
        );

        // Scalar multiplication
        let s_rc = rustcrypto::hash_to_scalar(&[b"test_scalar"], &[b"TestDST"]).unwrap();
        let s_bssl = boringssl::hash_to_scalar(&[b"test_scalar"], &[b"TestDST"]).unwrap();

        let mul_rc = p_rc * s_rc;
        let mul_bssl = p_bssl * s_bssl;
        assert_eq!(
            rustcrypto_point_bytes(&mul_rc),
            boringssl_point_bytes(&mul_bssl),
            "Point scalar multiplication mismatch"
        );
    }
}
