use athm::{Encodable, Params};
use hex;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Serialize)]
struct TestVector {
    procedure: &'static str,
    args: BTreeMap<&'static str, String>,
    output: BTreeMap<&'static str, String>,
}

trait ToHex {
    fn to_hex(&self) -> String;
}

impl<T: Encodable> ToHex for T {
    fn to_hex(&self) -> String {
        let mut buf = vec![];
        self.encode(&mut buf);
        hex::encode(buf)
    }
}

fn main() {
    let n_buckets = 4;
    let deployment_id = b"test_vector_deployment_id";
    let params = Params::new(n_buckets, deployment_id.into()).unwrap();

    let mut test_vectors = vec![];

    // Print Parameters.
    test_vectors.push(TestVector {
        procedure: "params",
        args: BTreeMap::new(),
        output: BTreeMap::from([
            ("n_buckets", "4".to_string()),
            ("generator_g", params.big_g.to_hex()),
            ("generator_h", params.big_h.to_hex()),
            ("deployment_id", std::str::from_utf8(&params.deployment_id).unwrap().into()),
        ]),
    });

    // Run key_gen.
    let rng_seed = "0101010101010101010101010101010101010101010101010101010101010101";
    let mut rng = ChaCha20Rng::from_seed(hex::decode(rng_seed).unwrap().try_into().unwrap());
    let (private_key, public_key, public_key_proof) = athm::key_gen(&params, &mut rng);
    let key_id = Sha256::digest(public_key.to_hex() + &public_key_proof.to_hex());
    test_vectors.push(TestVector {
        procedure: "key_gen",
        args: BTreeMap::from([("rng_seed", rng_seed.to_string())]),
        output: BTreeMap::from([
            ("private_key", private_key.to_hex()),
            ("public_key", public_key.to_hex()),
            ("public_key_proof", public_key_proof.to_hex()),
            ("key_id", hex::encode(key_id)),
        ]),
    });

    // Run token_request.
    let rng_seed = "0202020202020202020202020202020202020202020202020202020202020202";
    let mut rng = ChaCha20Rng::from_seed(hex::decode(rng_seed).unwrap().try_into().unwrap());
    let (token_context, token_request) =
        athm::token_request(&public_key, &public_key_proof, &params, &mut rng).unwrap();
    test_vectors.push(TestVector {
        procedure: "token_request",
        args: BTreeMap::from([
            ("rng_seed", rng_seed.to_string()),
            ("public_key", public_key.to_hex()),
            ("public_key_proof", public_key_proof.to_hex()),
        ]),
        output: BTreeMap::from([
            ("token_context", token_context.to_hex()),
            ("token_request", token_request.to_hex()),
        ]),
    });

    // Run token_response.
    let rng_seed = "0303030303030303030303030303030303030303030303030303030303030303";
    let hidden_metadata = 3;
    let mut rng = ChaCha20Rng::from_seed(hex::decode(rng_seed).unwrap().try_into().unwrap());
    let token_response = athm::token_response(
        &private_key,
        &public_key,
        &token_request,
        hidden_metadata,
        &params,
        &mut rng,
    )
    .unwrap();
    test_vectors.push(TestVector {
        procedure: "token_response",
        args: BTreeMap::from([
            ("rng_seed", rng_seed.to_string()),
            ("private_key", private_key.to_hex()),
            ("public_key", public_key.to_hex()),
            ("token_request", token_request.to_hex()),
            ("hidden_metadata", hidden_metadata.to_string()),
        ]),
        output: BTreeMap::from([("token_response", token_response.to_hex())]),
    });

    // Run finalize_token.
    let rng_seed = "0404040404040404040404040404040404040404040404040404040404040404";
    let mut rng = ChaCha20Rng::from_seed(hex::decode(rng_seed).unwrap().try_into().unwrap());
    let token = athm::finalize_token(
        &token_context,
        &public_key,
        &token_request,
        &token_response,
        &params,
        &mut rng,
    )
    .unwrap();
    test_vectors.push(TestVector {
        procedure: "finalize_token",
        args: BTreeMap::from([
            ("rng_seed", rng_seed.to_string()),
            ("token_context", token_context.to_hex()),
            ("public_key", public_key.to_hex()),
            ("token_request", token_request.to_hex()),
            ("token_response", token_response.to_hex()),
        ]),
        output: BTreeMap::from([("token", token.to_hex())]),
    });

    // Run verify_token.
    let hidden_metadata = athm::verify_token(&private_key, &token, &params).into_option().unwrap();
    test_vectors.push(TestVector {
        procedure: "verify_token",
        args: BTreeMap::from([("private_key", private_key.to_hex()), ("token", token.to_hex())]),
        output: BTreeMap::from([("hidden_metadata", hidden_metadata.to_string())]),
    });

    println!("{}", serde_json::to_string_pretty(&test_vectors).unwrap());
}
