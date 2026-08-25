use athm::{Encodable, Params};
use hex;
use serde::Serialize;
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
    let (private_key, public_key, public_key_proof) = athm::key_gen(&params);
    let key_id = public_key.key_id();
    test_vectors.push(TestVector {
        procedure: "key_gen",
        args: BTreeMap::new(),
        output: BTreeMap::from([
            ("private_key", private_key.to_hex()),
            ("public_key", public_key.to_hex()),
            ("public_key_proof", public_key_proof.to_hex()),
            ("key_id", hex::encode(key_id)),
        ]),
    });

    // Run token_request.
    let (token_context, token_request) =
        athm::token_request(&public_key, &public_key_proof, &params).unwrap();
    test_vectors.push(TestVector {
        procedure: "token_request",
        args: BTreeMap::from([
            ("public_key", public_key.to_hex()),
            ("public_key_proof", public_key_proof.to_hex()),
        ]),
        output: BTreeMap::from([
            ("token_context", token_context.to_hex()),
            ("token_request", token_request.to_hex()),
        ]),
    });

    // Run token_response.
    let hidden_metadata = 3;
    let token_response =
        athm::token_response(&private_key, &public_key, &token_request, hidden_metadata, &params)
            .unwrap();
    test_vectors.push(TestVector {
        procedure: "token_response",
        args: BTreeMap::from([
            ("private_key", private_key.to_hex()),
            ("public_key", public_key.to_hex()),
            ("token_request", token_request.to_hex()),
            ("hidden_metadata", hidden_metadata.to_string()),
        ]),
        output: BTreeMap::from([("token_response", token_response.to_hex())]),
    });

    // Run finalize_token.
    let token =
        athm::finalize_token(&token_context, &public_key, &token_request, &token_response, &params)
            .unwrap();
    test_vectors.push(TestVector {
        procedure: "finalize_token",
        args: BTreeMap::from([
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
