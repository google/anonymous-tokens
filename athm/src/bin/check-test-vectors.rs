use athm::{
    Decodable, Params, PrivateKey, PublicKey, PublicKeyProof, Token, TokenContext, TokenRequest,
    TokenResponse,
};
use p256::ProjectivePoint;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct TestVector {
    procedure: String,
    args: BTreeMap<String, String>,
    output: BTreeMap<String, String>,
}

trait FromHex {
    fn from_hex(input: &str) -> Result<Self, String>
    where
        Self: Sized;
}

impl<T: Decodable + Sized> FromHex for T {
    fn from_hex(input: &str) -> Result<T, String> {
        Ok(T::decode(&hex::decode(input).map_err(|e| format!("Failed to decode hex: {}", e))?)?)
    }
}

fn main() {
    let json_file = std::env::args().nth(1).unwrap_or("test_vectors.json".to_string());
    let test_vectors: Vec<TestVector> = serde_json::from_reader(
        std::fs::File::open(&json_file)
            .map_err(|e| format!("Failed to open file {}: {}", &json_file, e))
            .unwrap(),
    )
    .map_err(|e| format!("Failed to parse JSON: {}", e))
    .unwrap();

    // Extract deployment ID and check params.
    let params_tv = test_vectors.iter().find(|tv| tv.procedure == "params").unwrap();
    let deployment_id = params_tv.output.get("deployment_id").unwrap();
    let n_buckets = params_tv.output.get("n_buckets").unwrap().parse::<u8>().unwrap();
    let params = Params::new(n_buckets, deployment_id.clone().into_bytes()).unwrap();
    assert_eq!(
        params.big_g,
        ProjectivePoint::from_hex(params_tv.output.get("generator_g").unwrap()).unwrap()
    );
    assert_eq!(
        params.big_h,
        ProjectivePoint::from_hex(params_tv.output.get("generator_h").unwrap()).unwrap()
    );
    println!("params: OK");

    // Check all remaining test vectors.
    for test_vector in &test_vectors {
        let procedure = test_vector.procedure.as_str();
        match procedure {
            "params" => {
                // Already checked above.
            }
            "token_request" => {
                let public_key =
                    PublicKey::from_hex(test_vector.args.get("public_key").unwrap()).unwrap();
                let public_key_proof =
                    PublicKeyProof::from_hex(test_vector.args.get("public_key_proof").unwrap())
                        .unwrap();
                let mut rng = rand::thread_rng();
                // Ignore output, just checking that the proofs pass.
                let _ =
                    athm::token_request(&public_key, &public_key_proof, &params, &mut rng).unwrap();
                println!("{}: OK", procedure);
            }
            "token_response" => {
                let private_key =
                    PrivateKey::from_hex(test_vector.args.get("private_key").unwrap()).unwrap();
                let public_key =
                    PublicKey::from_hex(test_vector.args.get("public_key").unwrap()).unwrap();
                let token_request =
                    TokenRequest::from_hex(test_vector.args.get("token_request").unwrap()).unwrap();
                let hidden_metadata =
                    test_vector.args.get("hidden_metadata").unwrap().parse::<u8>().unwrap();
                let mut rng = rand::thread_rng();
                let _ = athm::token_response(
                    &private_key,
                    &public_key,
                    &token_request,
                    hidden_metadata,
                    &params,
                    &mut rng,
                )
                .unwrap();
                println!("{}: OK", procedure);
            }
            "finalize_token" => {
                let public_key =
                    PublicKey::from_hex(test_vector.args.get("public_key").unwrap()).unwrap();
                let token_request =
                    TokenRequest::from_hex(test_vector.args.get("token_request").unwrap()).unwrap();
                let token_context =
                    TokenContext::from_hex(test_vector.args.get("token_context").unwrap()).unwrap();
                let token_response = TokenResponse::decode(
                    &hex::decode(test_vector.args.get("token_response").unwrap()).unwrap(),
                    &params,
                )
                .unwrap();
                let mut rng = rand::thread_rng();
                let _ = athm::finalize_token(
                    &token_context,
                    &public_key,
                    &token_request,
                    &token_response,
                    &params,
                    &mut rng,
                )
                .unwrap();
                println!("{}: OK", procedure);
            }
            "verify_token" => {
                let private_key =
                    PrivateKey::from_hex(test_vector.args.get("private_key").unwrap()).unwrap();
                let token = Token::from_hex(test_vector.args.get("token").unwrap()).unwrap();
                let expected_hidden_metadata =
                    test_vector.output.get("hidden_metadata").unwrap().parse::<u8>().unwrap();
                let hidden_metadata = athm::verify_token(&private_key, &token, &params).unwrap();
                assert_eq!(hidden_metadata, expected_hidden_metadata);
                println!("{}: OK", procedure);
            }
            _ => {
                println!("Ignoring procedure: {}", procedure);
            }
        }
    }
}
