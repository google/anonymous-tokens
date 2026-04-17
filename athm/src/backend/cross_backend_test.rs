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
    use crate::backend::boringssl::BoringSslBackend;
    use crate::backend::rustcrypto::RustCryptoBackend;
    use crate::backend::AthmBackend;

    // -----------------------------------------------------------------------
    // Helper: compare serialized outputs from both backends
    // -----------------------------------------------------------------------

    fn rc_point_bytes(p: &<RustCryptoBackend as AthmBackend>::Point) -> Vec<u8> {
        let mut out = Vec::new();
        RustCryptoBackend::encode_point(p, &mut out);
        out
    }

    fn bssl_point_bytes(p: &<BoringSslBackend as AthmBackend>::Point) -> Vec<u8> {
        let mut out = Vec::new();
        BoringSslBackend::encode_point(p, &mut out);
        out
    }

    fn rc_scalar_bytes(s: &<RustCryptoBackend as AthmBackend>::Scalar) -> Vec<u8> {
        let mut out = Vec::new();
        RustCryptoBackend::encode_scalar(s, &mut out);
        out
    }

    fn bssl_scalar_bytes(s: &<BoringSslBackend as AthmBackend>::Scalar) -> Vec<u8> {
        let mut out = Vec::new();
        BoringSslBackend::encode_scalar(s, &mut out);
        out
    }

    // -----------------------------------------------------------------------
    // Tests: hash_to_point
    // -----------------------------------------------------------------------

    #[test]
    fn test_hash_to_point_parity() {
        let test_cases: Vec<(&[&[u8]], &[&[u8]])> = vec![
            (&[b"test"], &[b"DST"]),
            (&[b"hello world"], &[b"MyDST"]),
            (&[b""], &[b"EmptyMsg"]),
            (&[b"msg1", b"msg2"], &[b"DST1", b"DST2"]),
            (&[b"a", b"b", b"c"], &[b"X", b"Y"]),
        ];

        for (msgs, dsts) in &test_cases {
            let rc_point = RustCryptoBackend::hash_to_point(msgs, dsts)
                .expect("rustcrypto hash_to_point failed");
            let bssl_point = BoringSslBackend::hash_to_point(msgs, dsts)
                .expect("boringssl hash_to_point failed");

            let rc_bytes = rc_point_bytes(&rc_point);
            let bssl_bytes = bssl_point_bytes(&bssl_point);

            assert_eq!(
                rc_bytes, bssl_bytes,
                "hash_to_point mismatch for msgs={:?}, dsts={:?}\n  rustcrypto: {:02x?}\n  boringssl:  {:02x?}",
                msgs, dsts, rc_bytes, bssl_bytes
            );
        }
    }

    #[test]
    fn test_hash_to_point_with_athm_style_dsts() {
        let context_string = b"ATHMV1-P256-4-test_deployment_id";
        let msgs: &[&[u8]] = &[b"some_point_data"];
        let dsts: &[&[u8]] = &[b"HashToGroup-", context_string.as_slice(), b"generatorH"];

        let rc_point =
            RustCryptoBackend::hash_to_point(msgs, dsts).expect("rustcrypto hash_to_point failed");
        let bssl_point =
            BoringSslBackend::hash_to_point(msgs, dsts).expect("boringssl hash_to_point failed");

        assert_eq!(
            rc_point_bytes(&rc_point),
            bssl_point_bytes(&bssl_point),
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
            let rc_scalar = RustCryptoBackend::hash_to_scalar(msgs, dsts)
                .expect("rustcrypto hash_to_scalar failed");
            let bssl_scalar = BoringSslBackend::hash_to_scalar(msgs, dsts)
                .expect("boringssl hash_to_scalar failed");

            let rc_bytes = rc_scalar_bytes(&rc_scalar);
            let bssl_bytes = bssl_scalar_bytes(&bssl_scalar);

            assert_eq!(
                rc_bytes, bssl_bytes,
                "hash_to_scalar mismatch for msgs={:?}, dsts={:?}\n  rustcrypto: {:02x?}\n  boringssl:  {:02x?}",
                msgs, dsts, rc_bytes, bssl_bytes
            );
        }
    }

    #[test]
    fn test_hash_to_scalar_with_athm_style_dsts() {
        let context_string = b"ATHMV1-P256-4-test_deployment_id";
        let scalar_bytes = [0u8; 32];
        let point_bytes = [0u8; 33];
        let len_bytes = (32u16).to_be_bytes();
        let len_bytes2 = (33u16).to_be_bytes();

        let msgs: &[&[u8]] = &[&len_bytes, &scalar_bytes, &len_bytes2, &point_bytes];
        let dsts: &[&[u8]] = &[b"HashToScalar-", context_string.as_slice(), b"KeyCommitments"];

        let rc_scalar = RustCryptoBackend::hash_to_scalar(msgs, dsts)
            .expect("rustcrypto hash_to_scalar failed");
        let bssl_scalar =
            BoringSslBackend::hash_to_scalar(msgs, dsts).expect("boringssl hash_to_scalar failed");

        assert_eq!(
            rc_scalar_bytes(&rc_scalar),
            bssl_scalar_bytes(&bssl_scalar),
            "hash_to_scalar mismatch with ATHM-style DSTs"
        );
    }

    // -----------------------------------------------------------------------
    // Tests: generator point
    // -----------------------------------------------------------------------

    #[test]
    fn test_generator_parity() {
        let rc_gen = RustCryptoBackend::point_generator();
        let bssl_gen = BoringSslBackend::point_generator();

        assert_eq!(
            rc_point_bytes(&rc_gen),
            bssl_point_bytes(&bssl_gen),
            "Generator points differ between backends"
        );
    }

    // -----------------------------------------------------------------------
    // Tests: scalar encode/decode round-trips across backends
    // -----------------------------------------------------------------------

    #[test]
    fn test_scalar_cross_encode_decode() {
        let test_values: Vec<u64> = vec![0, 1, 42, 256, 65535, u64::MAX];

        for v in &test_values {
            let rc_scalar = <RustCryptoBackend as AthmBackend>::Scalar::from(*v);
            let rc_bytes = rc_scalar_bytes(&rc_scalar);

            let (bssl_decoded, _) = BoringSslBackend::decode_scalar(&rc_bytes);
            assert!(
                bool::from(bssl_decoded.is_some()),
                "boringssl failed to decode rustcrypto scalar for value {}",
                v
            );
            let bssl_bytes = bssl_scalar_bytes(&bssl_decoded.unwrap());
            assert_eq!(rc_bytes, bssl_bytes, "Scalar round-trip mismatch for value {}", v);
        }

        for v in &test_values {
            let bssl_scalar = <BoringSslBackend as AthmBackend>::Scalar::from(*v);
            let bssl_bytes = bssl_scalar_bytes(&bssl_scalar);

            let (rc_decoded, _) = RustCryptoBackend::decode_scalar(&bssl_bytes);
            assert!(
                bool::from(rc_decoded.is_some()),
                "rustcrypto failed to decode boringssl scalar for value {}",
                v
            );
            let rc_bytes = rc_scalar_bytes(&rc_decoded.unwrap());
            assert_eq!(bssl_bytes, rc_bytes, "Scalar round-trip mismatch for value {}", v);
        }
    }

    // -----------------------------------------------------------------------
    // Tests: point encode/decode round-trips across backends
    // -----------------------------------------------------------------------

    #[test]
    fn test_point_cross_encode_decode() {
        let rc_gen = RustCryptoBackend::point_generator();
        let rc_bytes = rc_point_bytes(&rc_gen);

        let (bssl_decoded, _) = BoringSslBackend::decode_point(&rc_bytes);
        assert!(
            bool::from(bssl_decoded.is_some()),
            "boringssl failed to decode rustcrypto generator"
        );
        let bssl_bytes = bssl_point_bytes(&bssl_decoded.unwrap());
        assert_eq!(rc_bytes, bssl_bytes, "Generator cross-decode mismatch");

        let bssl_gen = BoringSslBackend::point_generator();
        let bssl_bytes = bssl_point_bytes(&bssl_gen);

        let (rc_decoded, _) = RustCryptoBackend::decode_point(&bssl_bytes);
        assert!(
            bool::from(rc_decoded.is_some()),
            "rustcrypto failed to decode boringssl generator"
        );
        let rc_bytes2 = rc_point_bytes(&rc_decoded.unwrap());
        assert_eq!(bssl_bytes, rc_bytes2, "Generator cross-decode mismatch (bssl->rc)");
    }

    #[test]
    fn test_identity_point_cross_encode_decode() {
        let rc_identity = RustCryptoBackend::point_identity();
        let rc_bytes = rc_point_bytes(&rc_identity);

        let bssl_identity = BoringSslBackend::point_identity();
        let bssl_bytes = bssl_point_bytes(&bssl_identity);

        assert_eq!(rc_bytes, bssl_bytes, "Identity point encoding differs between backends");
    }

    #[test]
    fn test_hash_to_point_cross_decode() {
        let msgs: &[&[u8]] = &[b"cross_decode_test"];
        let dsts: &[&[u8]] = &[b"TestDST"];

        let rc_point = RustCryptoBackend::hash_to_point(msgs, dsts).unwrap();
        let rc_bytes = rc_point_bytes(&rc_point);

        let (bssl_decoded, _) = BoringSslBackend::decode_point(&rc_bytes);
        assert!(bool::from(bssl_decoded.is_some()));
        assert_eq!(rc_bytes, bssl_point_bytes(&bssl_decoded.unwrap()));

        let bssl_point = BoringSslBackend::hash_to_point(msgs, dsts).unwrap();
        let bssl_bytes = bssl_point_bytes(&bssl_point);

        let (rc_decoded, _) = RustCryptoBackend::decode_point(&bssl_bytes);
        assert!(bool::from(rc_decoded.is_some()));
        assert_eq!(bssl_bytes, rc_point_bytes(&rc_decoded.unwrap()));
    }

    // -----------------------------------------------------------------------
    // Tests: generator H parity (protocol-critical)
    // -----------------------------------------------------------------------

    #[test]
    fn test_generator_h_parity() {
        let context_strings = [
            b"ATHMV1-P256-4-test_deployment_id".to_vec(),
            b"ATHMV1-P256-1-prod".to_vec(),
            b"ATHMV1-P256-255-max_buckets".to_vec(),
        ];

        for ctx in &context_strings {
            let rc_gen = RustCryptoBackend::point_generator();
            let mut g_bytes_rc = Vec::new();
            RustCryptoBackend::encode_point(&rc_gen, &mut g_bytes_rc);

            let bssl_gen = BoringSslBackend::point_generator();
            let mut g_bytes_bssl = Vec::new();
            BoringSslBackend::encode_point(&bssl_gen, &mut g_bytes_bssl);

            assert_eq!(g_bytes_rc, g_bytes_bssl, "Generator G mismatch");

            let msgs: &[&[u8]] = &[&g_bytes_rc];
            let dsts: &[&[u8]] = &[b"HashToGroup-", ctx.as_slice(), b"generatorH"];

            let rc_h = RustCryptoBackend::hash_to_point(msgs, dsts).unwrap();
            let bssl_h = BoringSslBackend::hash_to_point(msgs, dsts).unwrap();

            assert_eq!(
                rc_point_bytes(&rc_h),
                bssl_point_bytes(&bssl_h),
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
        let a_rc = RustCryptoBackend::hash_to_scalar(&[b"scalar_a"], &[b"TestDST"]).unwrap();
        let b_rc = RustCryptoBackend::hash_to_scalar(&[b"scalar_b"], &[b"TestDST"]).unwrap();
        let a_bssl = BoringSslBackend::hash_to_scalar(&[b"scalar_a"], &[b"TestDST"]).unwrap();
        let b_bssl = BoringSslBackend::hash_to_scalar(&[b"scalar_b"], &[b"TestDST"]).unwrap();

        assert_eq!(rc_scalar_bytes(&a_rc), bssl_scalar_bytes(&a_bssl));
        assert_eq!(rc_scalar_bytes(&b_rc), bssl_scalar_bytes(&b_bssl));

        // Addition
        assert_eq!(
            rc_scalar_bytes(&(a_rc + b_rc)),
            bssl_scalar_bytes(&(a_bssl + b_bssl)),
            "Scalar addition mismatch"
        );

        // Subtraction
        assert_eq!(
            rc_scalar_bytes(&(a_rc - b_rc)),
            bssl_scalar_bytes(&(a_bssl - b_bssl)),
            "Scalar subtraction mismatch"
        );

        // Multiplication
        assert_eq!(
            rc_scalar_bytes(&(a_rc * b_rc)),
            bssl_scalar_bytes(&(a_bssl * b_bssl)),
            "Scalar multiplication mismatch"
        );

        // Negation
        assert_eq!(
            rc_scalar_bytes(&(-a_rc)),
            bssl_scalar_bytes(&(-a_bssl)),
            "Scalar negation mismatch"
        );

        // Inversion
        let inv_rc = RustCryptoBackend::scalar_invert(&a_rc).unwrap();
        let inv_bssl = BoringSslBackend::scalar_invert(&a_bssl).unwrap();
        assert_eq!(
            rc_scalar_bytes(&inv_rc),
            bssl_scalar_bytes(&inv_bssl),
            "Scalar inversion mismatch"
        );
    }

    // -----------------------------------------------------------------------
    // Tests: point arithmetic parity
    // -----------------------------------------------------------------------

    #[test]
    fn test_point_arithmetic_parity() {
        let p_rc = RustCryptoBackend::hash_to_point(&[b"point_p"], &[b"TestDST"]).unwrap();
        let q_rc = RustCryptoBackend::hash_to_point(&[b"point_q"], &[b"TestDST"]).unwrap();
        let p_bssl = BoringSslBackend::hash_to_point(&[b"point_p"], &[b"TestDST"]).unwrap();
        let q_bssl = BoringSslBackend::hash_to_point(&[b"point_q"], &[b"TestDST"]).unwrap();

        assert_eq!(rc_point_bytes(&p_rc), bssl_point_bytes(&p_bssl));
        assert_eq!(rc_point_bytes(&q_rc), bssl_point_bytes(&q_bssl));

        // Point addition
        assert_eq!(
            rc_point_bytes(&(p_rc + q_rc)),
            bssl_point_bytes(&(p_bssl + q_bssl)),
            "Point addition mismatch"
        );

        // Point subtraction
        assert_eq!(
            rc_point_bytes(&(p_rc - q_rc)),
            bssl_point_bytes(&(p_bssl - q_bssl)),
            "Point subtraction mismatch"
        );

        // Point negation
        assert_eq!(
            rc_point_bytes(&(-p_rc)),
            bssl_point_bytes(&(-p_bssl)),
            "Point negation mismatch"
        );

        // Scalar multiplication
        let s_rc = RustCryptoBackend::hash_to_scalar(&[b"test_scalar"], &[b"TestDST"]).unwrap();
        let s_bssl = BoringSslBackend::hash_to_scalar(&[b"test_scalar"], &[b"TestDST"]).unwrap();

        assert_eq!(
            rc_point_bytes(&(p_rc * s_rc)),
            bssl_point_bytes(&(p_bssl * s_bssl)),
            "Point scalar multiplication mismatch"
        );
    }

    // -----------------------------------------------------------------------
    // Tests: end-to-end protocol with both backends
    //
    // These tests verify cross-backend interoperability by running the
    // protocol with one backend for key generation/server-side operations,
    // serializing all messages, then deserializing and verifying with the
    // other backend. This mimics the realistic deployment scenario where
    // server and client use different ECC implementations.
    // -----------------------------------------------------------------------

    /// Run the full protocol with backend S (server) and backend C (client),
    /// exchanging all messages via serialization/deserialization.
    fn run_cross_backend_protocol<S: AthmBackend, C: AthmBackend>() {
        use crate::{
            finalize_token_generic, key_gen_generic, token_request_generic, token_response_generic,
            verify_token_generic, GenericParams, GenericPrivateKey, GenericPublicKey,
            GenericPublicKeyProof, GenericToken, GenericTokenRequest, GenericTokenResponse,
        };

        const N_BUCKETS: u8 = 4;
        let mut rng = rand::thread_rng();

        // --- Server (backend S): Generate keys ---
        let server_params =
            GenericParams::<S>::new_generic(N_BUCKETS, b"cross_backend_test".to_vec()).unwrap();
        let (sk, pk, proof) = key_gen_generic::<S, _>(&server_params, &mut rng);

        // Serialize server outputs.
        let mut params_bytes = Vec::new();
        server_params.encode_generic(&mut params_bytes);
        let mut pk_bytes = Vec::new();
        pk.encode_generic(&mut pk_bytes);
        let mut proof_bytes = Vec::new();
        proof.encode_generic(&mut proof_bytes);
        let mut sk_bytes = Vec::new();
        sk.encode_generic(&mut sk_bytes);

        // --- Client (backend C): Deserialize and create token request ---
        let client_params = GenericParams::<C>::decode_generic(&params_bytes).unwrap();
        let client_pk = GenericPublicKey::<C>::decode_generic(&pk_bytes).unwrap();
        let client_proof = GenericPublicKeyProof::<C>::decode_generic(&proof_bytes).unwrap();

        // Verify that params encode identically on both backends.
        let mut client_params_bytes = Vec::new();
        client_params.encode_generic(&mut client_params_bytes);
        assert_eq!(params_bytes, client_params_bytes, "Params re-encode mismatch");

        let (ctx, req) =
            token_request_generic::<C, _>(&client_pk, &client_proof, &client_params, &mut rng)
                .unwrap();

        // Serialize client outputs.
        let mut ctx_bytes = Vec::new();
        ctx.encode_generic(&mut ctx_bytes);
        let mut req_bytes = Vec::new();
        req.encode_generic(&mut req_bytes);

        // --- Server (backend S): Deserialize request and create responses ---
        let server_req = GenericTokenRequest::<S>::decode_generic(&req_bytes).unwrap();

        for metadata in 0..N_BUCKETS {
            let resp = token_response_generic::<S, _>(
                &sk,
                &pk,
                &server_req,
                metadata,
                &server_params,
                &mut rng,
            )
            .unwrap();

            // Serialize server response.
            let mut resp_bytes = Vec::new();
            resp.encode_generic(&mut resp_bytes);

            // --- Client (backend C): Deserialize response and finalize ---
            let client_resp =
                GenericTokenResponse::<C>::decode_generic(&resp_bytes, N_BUCKETS).unwrap();

            // Verify the response re-encodes identically.
            let mut client_resp_bytes = Vec::new();
            client_resp.encode_generic(&mut client_resp_bytes);
            assert_eq!(
                resp_bytes, client_resp_bytes,
                "TokenResponse re-encode mismatch for metadata {metadata}"
            );

            let token = finalize_token_generic::<C, _>(
                &ctx,
                &client_pk,
                &req,
                &client_resp,
                &client_params,
                &mut rng,
            )
            .unwrap();

            // Serialize the token.
            let mut token_bytes = Vec::new();
            token.encode_generic(&mut token_bytes);

            // --- Server (backend S): Deserialize token and verify ---
            let server_token = GenericToken::<S>::decode_generic(&token_bytes).unwrap();
            let recovered = verify_token_generic::<S>(&sk, &server_token, &server_params).unwrap();
            assert_eq!(
                recovered, metadata,
                "Metadata mismatch: server(S) generated with metadata={metadata}, got {recovered}"
            );

            // Also verify with backend C (using deserialized private key).
            let client_sk = GenericPrivateKey::<C>::decode_generic(&sk_bytes).unwrap();
            let client_token_for_verify = GenericToken::<C>::decode_generic(&token_bytes).unwrap();
            let recovered_c =
                verify_token_generic::<C>(&client_sk, &client_token_for_verify, &client_params)
                    .unwrap();
            assert_eq!(
                recovered_c, metadata,
                "Metadata mismatch: client(C) verify with metadata={metadata}, got {recovered_c}"
            );
        }
    }

    #[test]
    fn test_cross_backend_server_boringssl_client_rustcrypto() {
        run_cross_backend_protocol::<BoringSslBackend, RustCryptoBackend>();
    }

    #[test]
    fn test_cross_backend_server_rustcrypto_client_boringssl() {
        run_cross_backend_protocol::<RustCryptoBackend, BoringSslBackend>();
    }

    #[test]
    fn test_cross_backend_server_rustcrypto_client_rustcrypto() {
        run_cross_backend_protocol::<RustCryptoBackend, RustCryptoBackend>();
    }

    #[test]
    fn test_cross_backend_server_boringssl_client_boringssl() {
        run_cross_backend_protocol::<BoringSslBackend, BoringSslBackend>();
    }
}
