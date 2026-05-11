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

//! Anonymous Tokens with Hidden Metadata (ATHM)
//!
//! Privacy-preserving tokens where servers can embed metadata invisible to clients.
//!
//! # Overview
//!
//! ATHM allows servers to embed categorical metadata (like risk scores or user tiers)
//! in tokens without clients knowing which metadata values. This enables privacy-preserving authentication
//! with hidden authorization levels.
//!
//! # Example
//!
//! ```
//! use athm::*;
//!
//! // Setup with 4 metadata buckets (e.g., risk levels 0-3)
//! let params = Params::new(4, b"deployment_id".to_vec()).unwrap();
//! let mut rng = rand::thread_rng();
//! let (private_key, public_key, proof) = key_gen(&params, &mut rng);
//!
//! // Client creates blinded request
//! let (context, request) = token_request(&public_key, &proof, &params, &mut rng).unwrap();
//!
//! // Server responds with hidden metadata
//! let hidden_metadata = 2;
//! let response = token_response(
//!     &private_key, &public_key, &request, hidden_metadata, &params, &mut rng
//! ).unwrap();
//!
//! // Client unblinds token
//! let token = finalize_token(
//!     &context, &public_key, &request, &response, &params, &mut rng
//! ).unwrap();
//!
//! // Server verifies and recovers metadata
//! let metadata = verify_token(&private_key, &token, &params).unwrap();
//! assert_eq!(metadata, hidden_metadata);
//! ```
//!
//! # Protocol Flow
//!
//! 1. Server generates keys with [`key_gen`]
//! 2. Client creates blinded request with [`token_request`]
//! 3. Server embeds metadata with [`token_response`]
//! 4. Client unblinds with [`finalize_token`]
//! 5. Server verifies with [`verify_token`]

pub(crate) mod backend;

use backend::{AthmBackend, DefaultBackend, Point as ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

/// A transcript for Fiat-Shamir transform
///
/// This struct provides a clean abstraction for building transcripts
/// and generating challenges in non-interactive zero-knowledge proofs.
///
//
#[derive(Clone)]
struct Transcript {
    context_string: Vec<u8>,
    messages: Vec<Vec<u8>>,
}

impl Transcript {
    /// Create a new transcript
    fn new(context_string: Vec<u8>) -> Self {
        Self { context_string: context_string, messages: Vec::new() }
    }

    /// Add a scalar to the transcript
    fn append_scalar<B: AthmBackend>(&mut self, scalar: &B::Scalar) {
        let mut encoded = Vec::new();
        B::encode_scalar(scalar, &mut encoded);
        self.messages.push((encoded.len() as u16).to_be_bytes().to_vec());
        self.messages.push(encoded);
    }

    /// Add a point to the transcript
    fn append_point<B: AthmBackend>(&mut self, point: &B::Point) {
        let mut encoded = Vec::new();
        B::encode_point(point, &mut encoded);
        self.messages.push((encoded.len() as u16).to_be_bytes().to_vec());
        self.messages.push(encoded);
    }

    /// Generate a challenge scalar with domain separation
    fn challenge<B: AthmBackend>(&self, info: &[u8]) -> B::Scalar {
        let msgs = &self.messages.iter().map(|v| v.as_slice()).collect::<Vec<&[u8]>>();
        let dsts = &[b"HashToScalar-".as_slice(), &self.context_string, info];

        B::hash_to_scalar(msgs, dsts).unwrap()
    }
}

/// Default number of metadata buckets (from spec)
///
/// This is used as a default value for tests and examples.
/// In production use, the number of buckets should be specified
/// dynamically when calling token_response and verify_token.
#[cfg(test)]
const DEFAULT_N_BUCKETS: u8 = 4;

const SCALAR_SIZE: usize = backend::SCALAR_SIZE;
const POINT_SIZE: usize = backend::POINT_SIZE;
const DECODING_ERROR: &'static str = "decoding failed";
const INPUT_TOO_SHORT: &'static str = "input is too short";

// Helper to encode a Scalar and append it to a byte vector.
fn encode_scalar(scalar: &Scalar, out: &mut Vec<u8>) {
    DefaultBackend::encode_scalar(scalar, out);
}

// Trait for anything that can be encoded into a byte vector.
pub trait Encodable {
    fn encode(&self, out: &mut Vec<u8>);
}

// Trait for anything that can be decoded from a byte slice.
pub trait Decodable {
    fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str>
    where
        Self: Sized;
}

// Helper to decode a Scalar from a byte slice. Returns a CtOption of the resulting scalar if successful, and a new slice of the remaining input.
// Panics if the input is too small.
fn decode_scalar<'a>(input: &'a [u8]) -> (CtOption<Scalar>, &'a [u8]) {
    DefaultBackend::decode_scalar(input)
}

impl Encodable for Scalar {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_scalar(&self, out);
    }
}

impl Decodable for Scalar {
    fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < SCALAR_SIZE {
            return Err(INPUT_TOO_SHORT);
        }
        let (scalar, _) = decode_scalar(input);
        if !bool::from(scalar.is_some()) {
            return Err(DECODING_ERROR);
        }
        Ok(scalar.unwrap())
    }
}

// Helper to encode a ProjectivePoint and append it to a byte vector.
fn encode_point(point: &ProjectivePoint, out: &mut Vec<u8>) {
    DefaultBackend::encode_point(point, out);
}

// Helper to decode a ProjectivePoint from a byte slice. Returns a CtOption of the resulting point if successful, and a new slice of the remaining input.
// Panics if the input is too small.
fn decode_point<'a>(input: &'a [u8]) -> (CtOption<ProjectivePoint>, &'a [u8]) {
    DefaultBackend::decode_point(input)
}

impl Encodable for ProjectivePoint {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_point(&self, out);
    }
}

impl Decodable for ProjectivePoint {
    fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < POINT_SIZE {
            return Err(INPUT_TOO_SHORT);
        }
        let (point, _) = decode_point(input);
        if !bool::from(point.is_some()) {
            return Err(DECODING_ERROR);
        }
        Ok(point.unwrap())
    }
}

/// Server's private key for the ATHM protocol
///
/// Secret values the server uses to embed and recover hidden metadata.
/// Automatically zeroed on drop for security.
#[derive(Clone, Debug, Zeroize)]
pub struct GenericPrivateKey<B: AthmBackend> {
    pub x: B::Scalar,
    pub y: B::Scalar,
    pub z: B::Scalar,
    pub r_x: B::Scalar,
    pub r_y: B::Scalar,
}

/// Private key using the default backend.
pub type PrivateKey = GenericPrivateKey<DefaultBackend>;

impl<B: AthmBackend> GenericPrivateKey<B> {
    fn encoded_size() -> usize {
        5 * B::SCALAR_SIZE
    }

    pub fn encode_generic(&self, out: &mut Vec<u8>) {
        B::encode_scalar(&self.x, out);
        B::encode_scalar(&self.y, out);
        B::encode_scalar(&self.z, out);
        B::encode_scalar(&self.r_x, out);
        B::encode_scalar(&self.r_y, out);
    }

    pub fn decode_generic<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size() {
            return Err(INPUT_TOO_SHORT);
        }

        let (x, input) = B::decode_scalar(input);
        let (y, input) = B::decode_scalar(input);
        let (z, input) = B::decode_scalar(input);
        let (r_x, input) = B::decode_scalar(input);
        let (r_y, _input) = B::decode_scalar(input);

        let is_some = x.is_some() & y.is_some() & z.is_some() & r_x.is_some() & r_y.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }
        Ok(Self {
            x: x.unwrap(),
            y: y.unwrap(),
            z: z.unwrap(),
            r_x: r_x.unwrap(),
            r_y: r_y.unwrap(),
        })
    }
}

impl Encodable for PrivateKey {
    fn encode(&self, out: &mut Vec<u8>) {
        self.encode_generic(out);
    }
}

impl Decodable for PrivateKey {
    fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        Self::decode_generic(input)
    }
}

/// Server's public key for the ATHM protocol
///
/// Public values clients use to create token requests.
/// Must be verified with the accompanying proof.
#[derive(Clone, Debug)]
pub struct GenericPublicKey<B: AthmBackend> {
    pub big_z: B::Point,
    pub big_c_x: B::Point,
    pub big_c_y: B::Point,
}

/// Public key using the default backend.
pub type PublicKey = GenericPublicKey<DefaultBackend>;

impl<B: AthmBackend> GenericPublicKey<B> {
    fn encoded_size() -> usize {
        3 * B::POINT_SIZE
    }

    pub fn encode_generic(&self, out: &mut Vec<u8>) {
        B::encode_point(&self.big_z, out);
        B::encode_point(&self.big_c_x, out);
        B::encode_point(&self.big_c_y, out);
    }

    pub fn decode_generic<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size() {
            return Err(INPUT_TOO_SHORT);
        }
        let (big_z, input) = B::decode_point(input);
        let (big_c_x, input) = B::decode_point(input);
        let (big_c_y, _input) = B::decode_point(input);
        let is_some = big_z.is_some() & big_c_x.is_some() & big_c_y.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }
        Ok(Self { big_z: big_z.unwrap(), big_c_x: big_c_x.unwrap(), big_c_y: big_c_y.unwrap() })
    }
}

impl Encodable for PublicKey {
    fn encode(&self, out: &mut Vec<u8>) {
        self.encode_generic(out);
    }
}

impl Decodable for PublicKey {
    fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        Self::decode_generic(input)
    }
}

/// Proof of knowledge for the server's public key
///
/// Proves the server knows the private key. Clients must verify this
/// before creating token requests.
#[derive(Clone, Debug)]
pub struct GenericPublicKeyProof<B: AthmBackend> {
    pub e: B::Scalar,
    pub a_z: B::Scalar,
}

/// Public key proof using the default backend.
pub type PublicKeyProof = GenericPublicKeyProof<DefaultBackend>;

impl<B: AthmBackend> GenericPublicKeyProof<B> {
    fn encoded_size() -> usize {
        2 * B::SCALAR_SIZE
    }

    pub fn encode_generic(&self, out: &mut Vec<u8>) {
        B::encode_scalar(&self.e, out);
        B::encode_scalar(&self.a_z, out);
    }

    pub fn decode_generic<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size() {
            return Err(INPUT_TOO_SHORT);
        }
        let (e, input) = B::decode_scalar(input);
        let (a_z, _input) = B::decode_scalar(input);
        let is_some = e.is_some() & a_z.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }
        Ok(Self { e: e.unwrap(), a_z: a_z.unwrap() })
    }
}

impl Encodable for PublicKeyProof {
    fn encode(&self, out: &mut Vec<u8>) {
        self.encode_generic(out);
    }
}

impl Decodable for PublicKeyProof {
    fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        Self::decode_generic(input)
    }
}

/// Client's context for a token request
///
/// Secret values the client needs to finalize the token after receiving
/// the server's response. Keep these secure until deleted.
#[derive(Debug, Clone, Zeroize)]
pub struct GenericTokenContext<B: AthmBackend> {
    pub r: B::Scalar,
    pub tc: B::Scalar,
}

/// Token context using the default backend.
pub type TokenContext = GenericTokenContext<DefaultBackend>;

impl<B: AthmBackend> GenericTokenContext<B> {
    fn encoded_size() -> usize {
        2 * B::SCALAR_SIZE
    }

    pub fn encode_generic(&self, out: &mut Vec<u8>) {
        B::encode_scalar(&self.r, out);
        B::encode_scalar(&self.tc, out);
    }

    pub fn decode_generic<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size() {
            return Err(INPUT_TOO_SHORT);
        }
        let (r, input) = B::decode_scalar(input);
        let (tc, _input) = B::decode_scalar(input);
        let is_some = r.is_some() & tc.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }
        Ok(Self { r: r.unwrap(), tc: tc.unwrap() })
    }
}

impl Encodable for TokenContext {
    fn encode(&self, out: &mut Vec<u8>) {
        self.encode_generic(out);
    }
}

impl Decodable for TokenContext {
    fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        Self::decode_generic(input)
    }
}

/// Blinded token request from the client
///
/// A blinded point that hides the client's randomness from the server,
/// ensuring tokens can't be linked to their requests.
#[derive(Debug, Clone)]
pub struct GenericTokenRequest<B: AthmBackend> {
    pub big_t: B::Point,
}

/// Token request using the default backend.
pub type TokenRequest = GenericTokenRequest<DefaultBackend>;

impl<B: AthmBackend> GenericTokenRequest<B> {
    fn encoded_size() -> usize {
        1 * B::POINT_SIZE
    }

    pub fn encode_generic(&self, out: &mut Vec<u8>) {
        B::encode_point(&self.big_t, out);
    }

    pub fn decode_generic<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size() {
            return Err(INPUT_TOO_SHORT);
        }
        let (big_t, _) = B::decode_point(input);
        if !bool::from(big_t.is_some()) {
            return Err(DECODING_ERROR);
        }
        Ok(Self { big_t: big_t.unwrap() })
    }
}

impl Encodable for TokenRequest {
    fn encode(&self, out: &mut Vec<u8>) {
        self.encode_generic(out);
    }
}

impl Decodable for TokenRequest {
    fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        Self::decode_generic(input)
    }
}

/// Zero-knowledge proof for token issuance
///
/// Proves the server correctly embedded metadata without revealing
/// which metadata value was chosen.
#[derive(Debug, Clone)]
pub struct GenericIssuanceProof<B: AthmBackend> {
    pub big_c: B::Point,
    pub e_vec: Vec<B::Scalar>,
    pub a_vec: Vec<B::Scalar>,
    pub a_d: B::Scalar,
    pub a_rho: B::Scalar,
    pub a_w: B::Scalar,
}

/// Issuance proof using the default backend.
pub type IssuanceProof = GenericIssuanceProof<DefaultBackend>;

impl<B: AthmBackend> Default for GenericIssuanceProof<B> {
    fn default() -> Self {
        Self {
            big_c: B::point_identity(),
            e_vec: Vec::new(),
            a_vec: Vec::new(),
            a_d: B::scalar_zero(),
            a_rho: B::scalar_zero(),
            a_w: B::scalar_zero(),
        }
    }
}

impl<B: AthmBackend> GenericIssuanceProof<B> {
    fn encoded_size_for_buckets(n_buckets: u8) -> usize {
        3 * B::SCALAR_SIZE + 1 * B::POINT_SIZE + 2 * n_buckets as usize * B::SCALAR_SIZE
    }

    pub fn encode_generic(&self, out: &mut Vec<u8>) {
        B::encode_point(&self.big_c, out);
        for e in &self.e_vec {
            B::encode_scalar(e, out);
        }
        for a in &self.a_vec {
            B::encode_scalar(a, out);
        }
        B::encode_scalar(&self.a_d, out);
        B::encode_scalar(&self.a_rho, out);
        B::encode_scalar(&self.a_w, out);
    }

    pub fn decode_generic<'a>(input: &'a [u8], n_buckets: u8) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size_for_buckets(n_buckets) {
            return Err(INPUT_TOO_SHORT);
        }

        let (big_c, mut input) = B::decode_point(input);
        let mut is_some = big_c.is_some();
        let mut e_vec = Vec::new();
        for _ in 0..n_buckets {
            let e;
            (e, input) = B::decode_scalar(input);
            is_some &= e.is_some();
            e_vec.push(e.unwrap_or(B::scalar_zero()));
        }
        let mut a_vec = Vec::new();
        for _ in 0..n_buckets {
            let a;
            (a, input) = B::decode_scalar(input);
            is_some &= a.is_some();
            a_vec.push(a.unwrap_or(B::scalar_zero()));
        }
        let (a_d, input) = B::decode_scalar(input);
        let (a_rho, input) = B::decode_scalar(input);
        let (a_w, _input) = B::decode_scalar(input);

        is_some &= a_d.is_some() & a_rho.is_some() & a_w.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }
        Ok(Self {
            big_c: big_c.unwrap(),
            e_vec,
            a_vec,
            a_d: a_d.unwrap(),
            a_rho: a_rho.unwrap(),
            a_w: a_w.unwrap(),
        })
    }
}

impl Encodable for IssuanceProof {
    fn encode(&self, out: &mut Vec<u8>) {
        self.encode_generic(out);
    }
}

impl IssuanceProof {
    fn encoded_size(params: &Params) -> usize {
        Self::encoded_size_for_buckets(params.n_buckets)
    }

    pub fn decode<'a>(input: &'a [u8], params: &Params) -> Result<Self, &'static str> {
        Self::decode_generic(input, params.n_buckets)
    }
}

/// Server's response to a token request
///
/// Contains signed values with hidden metadata embedded and a proof
/// of correct computation.
#[derive(Debug, Clone)]
pub struct GenericTokenResponse<B: AthmBackend> {
    pub big_u: B::Point,
    pub big_v: B::Point,
    pub ts: B::Scalar,
    pub issuance_proof: GenericIssuanceProof<B>,
}

/// Token response using the default backend.
pub type TokenResponse = GenericTokenResponse<DefaultBackend>;

impl<B: AthmBackend> Default for GenericTokenResponse<B> {
    fn default() -> Self {
        Self {
            big_u: B::point_identity(),
            big_v: B::point_identity(),
            ts: B::scalar_zero(),
            issuance_proof: GenericIssuanceProof::default(),
        }
    }
}

impl<B: AthmBackend> GenericTokenResponse<B> {
    fn encoded_size_for_buckets(n_buckets: u8) -> usize {
        1 * B::SCALAR_SIZE
            + 2 * B::POINT_SIZE
            + GenericIssuanceProof::<B>::encoded_size_for_buckets(n_buckets)
    }

    pub fn encode_generic(&self, out: &mut Vec<u8>) {
        B::encode_point(&self.big_u, out);
        B::encode_point(&self.big_v, out);
        B::encode_scalar(&self.ts, out);
        self.issuance_proof.encode_generic(out);
    }

    pub fn decode_generic<'a>(input: &'a [u8], n_buckets: u8) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size_for_buckets(n_buckets) {
            return Err(INPUT_TOO_SHORT);
        }
        let (big_u, input) = B::decode_point(input);
        let (big_v, input) = B::decode_point(input);
        let (ts, input) = B::decode_scalar(input);

        let is_some = big_u.is_some() & big_v.is_some() & ts.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }

        let issuance_proof = GenericIssuanceProof::<B>::decode_generic(input, n_buckets)?;
        Ok(Self {
            big_u: big_u.unwrap(),
            big_v: big_v.unwrap(),
            ts: ts.unwrap(),
            issuance_proof: issuance_proof,
        })
    }
}

impl Encodable for TokenResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        self.encode_generic(out);
    }
}

impl TokenResponse {
    fn encoded_size(params: &Params) -> usize {
        Self::encoded_size_for_buckets(params.n_buckets)
    }
    pub fn decode<'a>(input: &'a [u8], params: &Params) -> Result<Self, &'static str> {
        Self::decode_generic(input, params.n_buckets)
    }
}

/// Finalized anonymous token
///
/// The unblinded token clients present for authentication.
/// Contains hidden metadata only the server can recover.
/// Automatically zeroed on drop for security.
#[derive(Debug, Clone, Zeroize)]
pub struct GenericToken<B: AthmBackend> {
    pub t: B::Scalar,
    pub big_p: B::Point,
    pub big_q: B::Point,
}

/// Token using the default backend.
pub type Token = GenericToken<DefaultBackend>;

impl<B: AthmBackend> GenericToken<B> {
    fn encoded_size() -> usize {
        1 * B::SCALAR_SIZE + 2 * B::POINT_SIZE
    }

    pub fn encode_generic(&self, out: &mut Vec<u8>) {
        B::encode_scalar(&self.t, out);
        B::encode_point(&self.big_p, out);
        B::encode_point(&self.big_q, out);
    }

    pub fn decode_generic<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size() {
            return Err(INPUT_TOO_SHORT);
        }
        let (t, input) = B::decode_scalar(input);
        let (big_p, input) = B::decode_point(input);
        let (big_q, _input) = B::decode_point(input);
        let is_some = t.is_some() & big_p.is_some() & big_q.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }
        Ok(Self { t: t.unwrap(), big_p: big_p.unwrap(), big_q: big_q.unwrap() })
    }
}

impl Encodable for Token {
    fn encode(&self, out: &mut Vec<u8>) {
        self.encode_generic(out);
    }
}

impl Decodable for Token {
    fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        Self::decode_generic(input)
    }
}

/// Protocol parameters
///
/// Defines the number of metadata buckets and elliptic curve generators.
/// Create once and reuse throughout the protocol.
///
/// ```
/// use athm::Params;
/// let params = Params::new(4, b"deployment_id".to_vec()).unwrap(); // 4 metadata buckets
/// ```
#[derive(Debug, Clone)]
pub struct GenericParams<B: AthmBackend> {
    /// Number of metadata buckets
    pub n_buckets: u8,
    /// Generator G (standard P256 generator)
    pub big_g: B::Point,
    /// Generator H (derived from G via hash-to-curve)
    pub big_h: B::Point,
    /// Deployment ID
    pub deployment_id: Vec<u8>,
}

/// Params using the default backend.
pub type Params = GenericParams<DefaultBackend>;

impl<B: AthmBackend> GenericParams<B> {
    /// Create new protocol parameters (generic over backend).
    pub fn new_generic(n_buckets: u8, deployment_id: Vec<u8>) -> Result<Self, &'static str> {
        if n_buckets == 0 {
            return Err("Number of buckets must be greater than 0");
        }
        if deployment_id.len() > 255 {
            return Err("Deployment ID must be less than 256 bytes");
        }
        let ctx = Self::build_context_string(n_buckets, &deployment_id);
        Ok(GenericParams {
            n_buckets,
            big_g: B::point_generator(),
            big_h: generator_h_generic::<B>(&ctx),
            deployment_id: deployment_id,
        })
    }

    pub fn context_string(&self) -> Vec<u8> {
        Self::build_context_string(self.n_buckets, &self.deployment_id)
    }

    fn build_context_string(n_buckets: u8, deployment_id: &[u8]) -> Vec<u8> {
        let mut out = format!("ATHMV1-P256-{n_buckets}-").into_bytes();
        out.extend_from_slice(deployment_id);
        out
    }

    pub fn encode_generic(&self, out: &mut Vec<u8>) {
        out.push(self.n_buckets);
        B::encode_point(&self.big_g, out);
        B::encode_point(&self.big_h, out);
        out.push(self.deployment_id.len() as u8);
        out.extend_from_slice(&self.deployment_id);
    }

    pub fn decode_generic<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        let min_size = 1 + 2 * B::POINT_SIZE + 1;
        if input.len() < min_size {
            return Err(INPUT_TOO_SHORT);
        }
        let (n_buckets, input) = (input[0], &input[1..]);
        let (big_g, input) = B::decode_point(input);
        let (big_h, input) = B::decode_point(input);
        let is_some = big_g.is_some() & big_h.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }
        let deployment_id_len = input[0] as usize;
        let input = &input[1..];
        if input.len() < deployment_id_len {
            return Err(INPUT_TOO_SHORT);
        }
        Ok(Self {
            n_buckets,
            big_g: big_g.unwrap(),
            big_h: big_h.unwrap(),
            deployment_id: input[..deployment_id_len].to_owned(),
        })
    }
}

impl Params {
    /// Create new protocol parameters
    pub fn new(n_buckets: u8, deployment_id: Vec<u8>) -> Result<Self, &'static str> {
        Self::new_generic(n_buckets, deployment_id)
    }
}

impl Encodable for Params {
    fn encode(&self, out: &mut Vec<u8>) {
        self.encode_generic(out);
    }
}

impl Decodable for Params {
    fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        Self::decode_generic(input)
    }
}

fn generator_h_generic<B: AthmBackend>(context_string: &[u8]) -> B::Point {
    let mut g_bytes = Vec::new();
    B::encode_point(&B::point_generator(), &mut g_bytes);
    let msg_array: &[&[u8]] = &[&g_bytes];
    let dst_array: &[&[u8]] = &[b"HashToGroup-", context_string, b"generatorH"];
    B::hash_to_point(msg_array, dst_array).unwrap()
}

fn create_public_key_proof_generic<B: AthmBackend, R: CryptoRngCore>(
    z: &B::Scalar,
    big_z: &B::Point,
    params: &GenericParams<B>,
    rng: &mut R,
) -> GenericPublicKeyProof<B> {
    // Generate random scalar rho_z
    let rho_z = B::random_scalar(rng);

    // Compute gamma_z = rho_z * G
    let gamma_z = params.big_g * rho_z;

    // Build transcript and compute challenge
    let mut transcript = Transcript::new(params.context_string());
    transcript.append_point::<B>(&params.big_g);
    transcript.append_point::<B>(big_z);
    transcript.append_point::<B>(&gamma_z);

    // Compute challenge e = HashToScalar(transcript, "KeyCommitments")
    let e = transcript.challenge::<B>(b"KeyCommitments");

    // Compute a_z = rho_z - (e * z)
    let a_z = rho_z - (e * *z);

    GenericPublicKeyProof { e, a_z }
}

/// Verify a public key proof
///
/// Checks that the server knows the private key. Call this before
/// creating token requests.
pub fn verify_public_key_proof(pk: &PublicKey, proof: &PublicKeyProof, params: &Params) -> bool {
    verify_public_key_proof_generic::<DefaultBackend>(pk, proof, params)
}

/// Verify a public key proof (generic over backend).
pub fn verify_public_key_proof_generic<B: AthmBackend>(
    pk: &GenericPublicKey<B>,
    proof: &GenericPublicKeyProof<B>,
    params: &GenericParams<B>,
) -> bool {
    // Recompute gamma_z = a_z * G + e * Z
    let gamma_z = params.big_g * proof.a_z + pk.big_z * proof.e;

    // Build transcript and recompute challenge
    let mut transcript = Transcript::new(params.context_string());
    transcript.append_point::<B>(&params.big_g);
    transcript.append_point::<B>(&pk.big_z);
    transcript.append_point::<B>(&gamma_z);

    // Recompute challenge e = HashToScalar(transcript, "KeyCommitments")
    let e_verify = transcript.challenge::<B>(b"KeyCommitments");

    // Verify that e_computed equals e using constant-time comparison
    proof.e.ct_eq(&e_verify).into()
}

/// Generate server keys
pub fn key_gen<R: CryptoRngCore>(
    params: &Params,
    rng: &mut R,
) -> (PrivateKey, PublicKey, PublicKeyProof) {
    key_gen_generic::<DefaultBackend, R>(params, rng)
}

/// Generate server keys (generic over backend).
pub fn key_gen_generic<B: AthmBackend, R: CryptoRngCore>(
    params: &GenericParams<B>,
    rng: &mut R,
) -> (GenericPrivateKey<B>, GenericPublicKey<B>, GenericPublicKeyProof<B>) {
    let x = B::random_scalar(rng);
    let y = B::random_non_zero_scalar(rng);
    let z = B::random_non_zero_scalar(rng);
    let r_x = B::random_scalar(rng);
    let r_y = B::random_scalar(rng);

    let big_z = params.big_g * z;
    let big_c_x = (params.big_g * x) + (params.big_h * r_x);
    let big_c_y = (params.big_g * y) + (params.big_h * r_y);

    let pi = create_public_key_proof_generic::<B, R>(&z, &big_z, params, rng);

    let private_key = GenericPrivateKey { x, y, z, r_x, r_y };
    let public_key = GenericPublicKey { big_z, big_c_x, big_c_y };

    (private_key, public_key, pi)
}

/// Create a token request (client side)
pub fn token_request<R: CryptoRngCore>(
    public_key: &PublicKey,
    public_key_proof: &PublicKeyProof,
    params: &Params,
    rng: &mut R,
) -> Result<(TokenContext, TokenRequest), &'static str> {
    token_request_generic::<DefaultBackend, R>(public_key, public_key_proof, params, rng)
}

/// Create a token request (generic over backend).
pub fn token_request_generic<B: AthmBackend, R: CryptoRngCore>(
    public_key: &GenericPublicKey<B>,
    public_key_proof: &GenericPublicKeyProof<B>,
    params: &GenericParams<B>,
    rng: &mut R,
) -> Result<(GenericTokenContext<B>, GenericTokenRequest<B>), &'static str> {
    if !verify_public_key_proof_generic::<B>(public_key, public_key_proof, params) {
        return Err("Invalid public key proof");
    }
    let r = B::random_scalar(rng);
    let tc = B::random_scalar(rng);
    let big_t = params.big_g * r + public_key.big_z * tc;
    Ok((GenericTokenContext { r, tc }, GenericTokenRequest { big_t }))
}

/// Create an issuance proof for the token response
#[allow(clippy::too_many_arguments)]
fn create_issuance_proof_generic<B: AthmBackend, R: CryptoRngCore>(
    private_key: &GenericPrivateKey<B>,
    public_key: &GenericPublicKey<B>,
    hidden_metadata: u8,
    params: &GenericParams<B>,
    d: &B::Scalar,
    big_u: &B::Point,
    big_v: &B::Point,
    ts: &B::Scalar,
    big_t: &B::Point,
    rng: &mut R,
) -> GenericIssuanceProof<B> {
    let mut e_vec: Vec<B::Scalar> = (0..params.n_buckets)
        .map(|i| {
            B::Scalar::conditional_select(
                &B::random_scalar(rng),
                &B::scalar_zero(),
                i.ct_eq(&hidden_metadata),
            )
        })
        .collect();
    let mut a_vec: Vec<B::Scalar> = (0..params.n_buckets)
        .map(|i| {
            B::Scalar::conditional_select(
                &B::random_scalar(rng),
                &B::scalar_zero(),
                i.ct_eq(&hidden_metadata),
            )
        })
        .collect();

    let r_mu = B::random_scalar(rng);
    let r_d = B::random_scalar(rng);
    let r_rho = B::random_scalar(rng);
    let r_w = B::random_scalar(rng);
    let mu = B::random_scalar(rng);

    let big_c = public_key.big_c_y * B::Scalar::from(hidden_metadata as u64) + params.big_h * mu;

    let c_vec: Vec<B::Point> = (0..params.n_buckets)
        .map(|i| {
            B::Point::conditional_select(
                &(params.big_h * a_vec[i as usize]
                    - (big_c - public_key.big_c_y * B::Scalar::from(i as u64)) * e_vec[i as usize]),
                &(params.big_h * r_mu),
                i.ct_eq(&hidden_metadata),
            )
        })
        .collect();

    let c_d = *big_u * r_d;
    let c_rho = *big_v * r_d + params.big_h * r_rho;
    let c_w = *big_v * r_d + params.big_g * r_w;

    let mut transcript = Transcript::new(params.context_string());
    transcript.append_point::<B>(&params.big_g);
    transcript.append_point::<B>(&params.big_h);
    transcript.append_point::<B>(&public_key.big_c_x);
    transcript.append_point::<B>(&public_key.big_c_y);
    transcript.append_point::<B>(&public_key.big_z);
    transcript.append_point::<B>(big_u);
    transcript.append_point::<B>(big_v);
    transcript.append_scalar::<B>(ts);
    transcript.append_point::<B>(big_t);
    transcript.append_point::<B>(&big_c);
    c_vec.iter().for_each(|c_i| {
        transcript.append_point::<B>(c_i);
    });
    transcript.append_point::<B>(&c_d);
    transcript.append_point::<B>(&c_rho);
    transcript.append_point::<B>(&c_w);

    let e = transcript.challenge::<B>(b"TokenResponseProof");

    let e_sum: B::Scalar = e_vec.iter().copied().fold(B::scalar_zero(), |acc, x| acc + x);
    e_vec.iter_mut().enumerate().for_each(|(i, e_val)| {
        *e_val =
            B::Scalar::conditional_select(e_val, &(e - e_sum), (i as u8).ct_eq(&hidden_metadata));
    });

    let d_inv = B::scalar_invert(d).unwrap();
    let rho = -(private_key.r_x + B::Scalar::from(hidden_metadata as u64) * private_key.r_y + mu);
    let w = private_key.x
        + B::Scalar::from(hidden_metadata as u64) * private_key.y
        + *ts * private_key.z;

    let a_hidden_metadata = r_mu + (e - e_sum) * mu;
    a_vec.iter_mut().enumerate().for_each(|(i, a_val)| {
        *a_val = B::Scalar::conditional_select(
            a_val,
            &a_hidden_metadata,
            (i as u8).ct_eq(&hidden_metadata),
        );
    });
    let a_d = r_d - e * d_inv;
    let a_rho = r_rho + e * rho;
    let a_w = r_w + e * w;

    GenericIssuanceProof { big_c, e_vec, a_vec, a_d, a_rho, a_w }
}

/// Create a token response (server side)
pub fn token_response<R: CryptoRngCore>(
    private_key: &PrivateKey,
    public_key: &PublicKey,
    token_request: &TokenRequest,
    hidden_metadata: u8,
    params: &Params,
    rng: &mut R,
) -> Result<TokenResponse, &'static str> {
    token_response_generic::<DefaultBackend, R>(
        private_key,
        public_key,
        token_request,
        hidden_metadata,
        params,
        rng,
    )
}

/// Create a token response (generic over backend).
pub fn token_response_generic<B: AthmBackend, R: CryptoRngCore>(
    private_key: &GenericPrivateKey<B>,
    public_key: &GenericPublicKey<B>,
    token_request: &GenericTokenRequest<B>,
    hidden_metadata: u8,
    params: &GenericParams<B>,
    rng: &mut R,
) -> Result<GenericTokenResponse<B>, &'static str> {
    if hidden_metadata >= params.n_buckets {
        return Err("Hidden metadata index out of range");
    }
    let big_t = &token_request.big_t;
    let ts = B::random_scalar(rng);
    let d = B::random_non_zero_scalar(rng);
    let big_u = params.big_g * d;
    let big_x = params.big_g * private_key.x;
    let big_y = params.big_g * private_key.y;
    let big_v =
        (big_x + big_y * B::Scalar::from(hidden_metadata as u64) + public_key.big_z * ts + *big_t)
            * d;
    let issuance_proof = create_issuance_proof_generic::<B, R>(
        private_key,
        public_key,
        hidden_metadata,
        params,
        &d,
        &big_u,
        &big_v,
        &ts,
        big_t,
        rng,
    );
    Ok(GenericTokenResponse { big_u, big_v, ts, issuance_proof })
}

/// Verify an issuance proof
pub fn verify_issuance_proof(
    pk: &PublicKey,
    big_t: &ProjectivePoint,
    response: &TokenResponse,
    params: &Params,
) -> bool {
    verify_issuance_proof_generic::<DefaultBackend>(pk, big_t, response, params)
}

/// Verify an issuance proof (generic over backend).
pub fn verify_issuance_proof_generic<B: AthmBackend>(
    pk: &GenericPublicKey<B>,
    big_t: &B::Point,
    response: &GenericTokenResponse<B>,
    params: &GenericParams<B>,
) -> bool {
    let proof = &response.issuance_proof;
    let big_u = &response.big_u;
    let big_v = &response.big_v;
    let ts = &response.ts;

    let c_vec: Vec<B::Point> = (0..params.n_buckets)
        .map(|i| {
            params.big_h * proof.a_vec[i as usize]
                - (proof.big_c - pk.big_c_y * B::Scalar::from(i as u64)) * proof.e_vec[i as usize]
        })
        .collect();

    let e: B::Scalar = proof.e_vec.iter().copied().fold(B::scalar_zero(), |acc, x| acc + x);

    let c_d = *big_u * proof.a_d + params.big_g * e;
    let c_rho = *big_v * proof.a_d
        + params.big_h * proof.a_rho
        + (pk.big_c_x + proof.big_c + pk.big_z * *ts + *big_t) * e;
    let c_w = *big_v * proof.a_d + params.big_g * proof.a_w + *big_t * e;

    let mut transcript = Transcript::new(params.context_string());
    transcript.append_point::<B>(&params.big_g);
    transcript.append_point::<B>(&params.big_h);
    transcript.append_point::<B>(&pk.big_c_x);
    transcript.append_point::<B>(&pk.big_c_y);
    transcript.append_point::<B>(&pk.big_z);
    transcript.append_point::<B>(big_u);
    transcript.append_point::<B>(big_v);
    transcript.append_scalar::<B>(ts);
    transcript.append_point::<B>(big_t);
    transcript.append_point::<B>(&proof.big_c);
    c_vec.iter().for_each(|c_i| {
        transcript.append_point::<B>(c_i);
    });
    transcript.append_point::<B>(&c_d);
    transcript.append_point::<B>(&c_rho);
    transcript.append_point::<B>(&c_w);

    let e_verify = transcript.challenge::<B>(b"TokenResponseProof");
    e.ct_eq(&e_verify).into()
}

/// Finalize a token (client side)
pub fn finalize_token<R: CryptoRngCore>(
    context: &TokenContext,
    public_key: &PublicKey,
    request: &TokenRequest,
    response: &TokenResponse,
    params: &Params,
    rng: &mut R,
) -> Result<Token, &'static str> {
    finalize_token_generic::<DefaultBackend, R>(context, public_key, request, response, params, rng)
}

/// Finalize a token (generic over backend).
pub fn finalize_token_generic<B: AthmBackend, R: CryptoRngCore>(
    context: &GenericTokenContext<B>,
    public_key: &GenericPublicKey<B>,
    request: &GenericTokenRequest<B>,
    response: &GenericTokenResponse<B>,
    params: &GenericParams<B>,
    rng: &mut R,
) -> Result<GenericToken<B>, &'static str> {
    if !verify_issuance_proof_generic::<B>(public_key, &request.big_t, response, params) {
        return Err("Invalid issuance proof");
    }
    let c = B::random_non_zero_scalar(rng);
    let big_p = response.big_u * c;
    let big_q = (response.big_v - response.big_u * context.r) * c;
    let t = context.tc + response.ts;
    Ok(GenericToken { t, big_p, big_q })
}

/// Verify token and recover metadata (server side)
pub fn verify_token(private_key: &PrivateKey, token: &Token, params: &Params) -> CtOption<u8> {
    verify_token_generic::<DefaultBackend>(private_key, token, params)
}

/// Verify token and recover metadata (generic over backend).
pub fn verify_token_generic<B: AthmBackend>(
    private_key: &GenericPrivateKey<B>,
    token: &GenericToken<B>,
    params: &GenericParams<B>,
) -> CtOption<u8> {
    let check = B::point_is_identity(&token.big_p) | B::point_is_identity(&token.big_q);

    let i_match = (0..params.n_buckets).fold(CtOption::new(0u8, Choice::from(0u8)), |acc, i| {
        let q_i = token.big_p
            * (private_key.x + token.t * private_key.z + B::Scalar::from(i as u64) * private_key.y);
        CtOption::<u8>::conditional_select(
            &acc,
            &CtOption::new(i as u8, Choice::from(1u8)),
            token.big_q.ct_eq(&q_i),
        )
    });

    CtOption::<u8>::conditional_select(&i_match, &CtOption::new(0u8, Choice::from(0u8)), check)
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_DEPLOYMENT_ID: &[u8] = b"test_deployment_id";

    // Test helpers for the default backend.
    fn test_generator_g() -> ProjectivePoint {
        DefaultBackend::point_generator()
    }
    fn test_generator_h(ctx: &[u8]) -> ProjectivePoint {
        generator_h_generic::<DefaultBackend>(ctx)
    }
    fn test_random_scalar(rng: &mut impl CryptoRngCore) -> Scalar {
        DefaultBackend::random_scalar(rng)
    }
    fn test_random_point(rng: &mut impl CryptoRngCore) -> ProjectivePoint {
        test_generator_g() * test_random_scalar(rng)
    }
    fn test_scalar_zero() -> Scalar {
        DefaultBackend::scalar_zero()
    }
    fn test_scalar_one() -> Scalar {
        DefaultBackend::scalar_one()
    }
    fn test_point_identity() -> ProjectivePoint {
        DefaultBackend::point_identity()
    }
    fn test_scalar_is_zero(s: &Scalar) -> bool {
        bool::from(DefaultBackend::scalar_is_zero(s))
    }
    fn test_point_is_identity(p: &ProjectivePoint) -> bool {
        bool::from(DefaultBackend::point_is_identity(p))
    }

    fn gen_test_params() -> Params {
        Params::new(DEFAULT_N_BUCKETS, TEST_DEPLOYMENT_ID.into()).unwrap()
    }

    #[test]
    fn test_gen_params_fails_when_n_buckets_is_zero() {
        let result = Params::new(0, TEST_DEPLOYMENT_ID.into());
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("Number of buckets"));
    }

    #[test]
    fn test_gen_params_fails_when_deployment_id_is_too_long() {
        let long_deployment_id = b"a".repeat(256);
        let result = Params::new(DEFAULT_N_BUCKETS, long_deployment_id);
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("Deployment ID"));
    }

    #[test]
    fn test_params() {
        let params = gen_test_params();
        assert_eq!(params.n_buckets, DEFAULT_N_BUCKETS);
        assert_eq!(params.big_g, test_generator_g());
        assert_eq!(params.big_h, test_generator_h(&params.context_string()));
        assert_eq!(params.deployment_id, TEST_DEPLOYMENT_ID);
    }

    #[test]
    fn test_params_serialization() {
        let params = gen_test_params();
        let mut buf = vec![];
        params.encode(&mut buf);
        let params_deserialized = Params::decode(&buf).unwrap();

        assert_eq!(params_deserialized.n_buckets, DEFAULT_N_BUCKETS);
        assert_eq!(params_deserialized.big_g, test_generator_g());
        assert_eq!(params_deserialized.big_h, test_generator_h(&params.context_string()));
        assert_eq!(params_deserialized.deployment_id, TEST_DEPLOYMENT_ID);
    }

    #[test]
    fn test_params_deserialization_fails_when_no_deployment_id() {
        let params = gen_test_params();
        let mut buf = vec![];
        params.encode(&mut buf);
        let result = Params::decode(&buf[..buf.len() - 1]);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), INPUT_TOO_SHORT);
    }

    #[test]
    fn test_params_deserialization_fails_when_deployment_id_too_short() {
        let mut params = gen_test_params();
        params.deployment_id = b"a".to_vec();
        let mut buf = vec![];
        params.encode(&mut buf);
        let result = Params::decode(&buf[..buf.len() - 1]);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), INPUT_TOO_SHORT);
    }

    #[test]
    fn test_key_gen() {
        let params = gen_test_params();
        let mut rng = rand::thread_rng();
        let (private_key, public_key, _proof) = key_gen(&params, &mut rng);

        // Verify that the keys were generated
        assert!(!test_scalar_is_zero(&private_key.x));
        assert!(!test_scalar_is_zero(&private_key.y));
        assert!(!test_scalar_is_zero(&private_key.z));

        // Verify public key points are not identity
        assert!(!test_point_is_identity(&public_key.big_z));
        assert!(!test_point_is_identity(&public_key.big_c_x));
        assert!(!test_point_is_identity(&public_key.big_c_y));
    }

    #[test]
    fn test_generators() {
        let g = test_generator_g();
        let h = test_generator_h(b"test");

        assert!(g != h);
        assert!(!test_point_is_identity(&g));
        assert!(!test_point_is_identity(&h));
    }

    #[test]
    fn test_verify_public_key_proof() {
        let params = gen_test_params();
        let mut rng = rand::thread_rng();
        let (_, public_key, proof) = key_gen(&params, &mut rng);

        // Verify that the proof is valid
        assert!(verify_public_key_proof(&public_key, &proof, &params));

        // Test with invalid proof (modified challenge)
        let mut invalid_proof = proof.clone();
        invalid_proof.e = invalid_proof.e + test_scalar_one();
        assert!(!verify_public_key_proof(&public_key, &invalid_proof, &params));

        // Test with invalid proof (modified response)
        let mut invalid_proof2 = proof.clone();
        invalid_proof2.a_z = invalid_proof2.a_z + test_scalar_one();
        assert!(!verify_public_key_proof(&public_key, &invalid_proof2, &params));
    }

    #[test]
    fn test_token_request() {
        let mut rng = rand::thread_rng();
        let params = gen_test_params();
        let (_, public_key, proof) = key_gen(&params, &mut rng);

        // Create a token request
        let result = token_request(&public_key, &proof, &params, &mut rng);
        assert!(result.is_ok());

        let (context, request) = result.unwrap();

        // Verify that the request T is not identity
        assert!(!test_point_is_identity(&request.big_t));

        // Verify context contains random scalars
        assert!(!test_scalar_is_zero(&context.r));
        assert!(!test_scalar_is_zero(&context.tc));

        // Test with invalid proof
        let mut invalid_proof = proof.clone();
        invalid_proof.e = invalid_proof.e + test_scalar_one();
        let result = token_request(&public_key, &invalid_proof, &params, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_response() {
        let mut rng = rand::thread_rng();
        let params = gen_test_params();
        let (server_private_key, server_public_key, proof) = key_gen(&params, &mut rng);

        // Create a token request from client
        let (_, token_req) = token_request(&server_public_key, &proof, &params, &mut rng).unwrap();

        // Create token response with metadata bucket index
        let hidden_metadata: u8 = 2;
        let response = token_response(
            &server_private_key,
            &server_public_key,
            &token_req,
            hidden_metadata,
            &params,
            &mut rng,
        );
        assert!(response.is_ok());
        let response = response.unwrap();

        // Verify response elements are not identity
        assert!(!test_point_is_identity(&response.big_u));
        assert!(!test_point_is_identity(&response.big_v));

        // Test with different metadata
        let hidden_metadata_alt: u8 = 3;
        let response_alt = token_response(
            &server_private_key,
            &server_public_key,
            &token_req,
            hidden_metadata_alt,
            &params,
            &mut rng,
        )
        .unwrap();

        // Responses should be different for different metadata
        assert!(response.big_v != response_alt.big_v);

        // Test with invalid metadata index
        let invalid_metadata: u8 = DEFAULT_N_BUCKETS + 1;
        let response_err = token_response(
            &server_private_key,
            &server_public_key,
            &token_req,
            invalid_metadata,
            &params,
            &mut rng,
        );
        assert!(response_err.is_err());
    }

    #[test]
    fn test_verify_issuance_proof() {
        let mut rng = rand::thread_rng();
        let params = gen_test_params();
        let (server_private_key, server_public_key, proof) = key_gen(&params, &mut rng);

        // Create a token request from client
        let (_, token_req) = token_request(&server_public_key, &proof, &params, &mut rng).unwrap();

        // Create token response with metadata bucket
        let hidden_metadata: u8 = 3;
        let response = token_response(
            &server_private_key,
            &server_public_key,
            &token_req,
            hidden_metadata,
            &params,
            &mut rng,
        )
        .unwrap();

        // Verify the issuance proof
        assert!(verify_issuance_proof(&server_public_key, &token_req.big_t, &response, &params));

        // Test with tampered proof
        let mut tampered_response = response.clone();
        if !tampered_response.issuance_proof.e_vec.is_empty() {
            tampered_response.issuance_proof.e_vec[0] =
                tampered_response.issuance_proof.e_vec[0] + test_scalar_one();
        }
        assert!(!verify_issuance_proof(
            &server_public_key,
            &token_req.big_t,
            &tampered_response,
            &params
        ));

        // Test with tampered U
        let mut tampered_response2 = response.clone();
        tampered_response2.big_u = tampered_response2.big_u + params.big_g;
        assert!(!verify_issuance_proof(
            &server_public_key,
            &token_req.big_t,
            &tampered_response2,
            &params
        ));
    }

    #[test]
    fn test_end_to_end_protocol() {
        let mut rng = rand::thread_rng();
        let params = gen_test_params();

        // Server generates keys
        let (server_private_key, server_public_key, proof) = key_gen(&params, &mut rng);

        // Client creates token request
        let (context, token_req) =
            token_request(&server_public_key, &proof, &params, &mut rng).unwrap();

        // Server chooses hidden metadata and creates response
        let hidden_metadata: u8 = 2;
        let response = token_response(
            &server_private_key,
            &server_public_key,
            &token_req,
            hidden_metadata,
            &params,
            &mut rng,
        )
        .unwrap();

        // Client finalizes the token
        let token =
            finalize_token(&context, &server_public_key, &token_req, &response, &params, &mut rng)
                .unwrap();

        // Server verifies the token and recovers the metadata
        let recovered_metadata = verify_token(&server_private_key, &token, &params).unwrap();
        assert_eq!(recovered_metadata, hidden_metadata);

        // Test with different metadata values
        (0u8..3).for_each(|metadata| {
            let (context, token_req) =
                token_request(&server_public_key, &proof, &params, &mut rng).unwrap();
            let response = token_response(
                &server_private_key,
                &server_public_key,
                &token_req,
                metadata,
                &params,
                &mut rng,
            )
            .unwrap();
            let token = finalize_token(
                &context,
                &server_public_key,
                &token_req,
                &response,
                &params,
                &mut rng,
            )
            .unwrap();
            let recovered = verify_token(&server_private_key, &token, &params).unwrap();
            assert_eq!(recovered, metadata);
        });
    }

    #[test]
    fn test_verify_token_edge_cases() {
        let mut rng = rand::thread_rng();
        let params = gen_test_params();
        let (server_private_key, server_public_key, proof) = key_gen(&params, &mut rng);

        // Create a valid token
        let (context, token_req) =
            token_request(&server_public_key, &proof, &params, &mut rng).unwrap();
        let hidden_metadata: u8 = 3;
        let response = token_response(
            &server_private_key,
            &server_public_key,
            &token_req,
            hidden_metadata,
            &params,
            &mut rng,
        )
        .unwrap();
        let token =
            finalize_token(&context, &server_public_key, &token_req, &response, &params, &mut rng)
                .unwrap();

        // Test with identity P (should fail)
        let mut invalid_token = token.clone();
        invalid_token.big_p = test_point_identity();
        assert!(bool::from(verify_token(&server_private_key, &invalid_token, &params).is_none()));

        // Test with identity Q (should fail)
        let mut invalid_token2 = token.clone();
        invalid_token2.big_q = test_point_identity();
        assert!(bool::from(verify_token(&server_private_key, &invalid_token2, &params).is_none()));

        // Test with modified t (should fail to find match)
        let mut invalid_token3 = token.clone();
        invalid_token3.t = invalid_token3.t + test_scalar_one();
        assert!(bool::from(verify_token(&server_private_key, &invalid_token3, &params).is_none()));
    }

    #[test]
    fn test_tampered_tokens() {
        let mut rng = rand::thread_rng();
        let params = gen_test_params();
        let (server_private_key, server_public_key, proof) = key_gen(&params, &mut rng);

        // Create a valid token
        let (context, token_req) =
            token_request(&server_public_key, &proof, &params, &mut rng).unwrap();
        let hidden_metadata: u8 = 3;
        let response = token_response(
            &server_private_key,
            &server_public_key,
            &token_req,
            hidden_metadata,
            &params,
            &mut rng,
        )
        .unwrap();
        let token =
            finalize_token(&context, &server_public_key, &token_req, &response, &params, &mut rng)
                .unwrap();

        // Test 1: Tampered scalar t values
        // Small modification
        let mut tampered = token.clone();
        tampered.t = tampered.t + test_scalar_one();
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        // Large modification
        let mut tampered = token.clone();
        tampered.t = tampered.t + Scalar::from(12345u64);
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        // Negated t
        let mut tampered = token.clone();
        tampered.t = -tampered.t;
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        // Random t
        let mut tampered = token.clone();
        tampered.t = test_random_scalar(&mut rng);
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        // Test 2: Tampered points P and Q
        // Modified P with random point
        let mut tampered = token.clone();
        tampered.big_p = test_random_point(&mut rng);
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        // Modified Q with random point
        let mut tampered = token.clone();
        tampered.big_q = test_random_point(&mut rng);
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        // Negated P
        let mut tampered = token.clone();
        tampered.big_p = -tampered.big_p;
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        // Negated Q
        let mut tampered = token.clone();
        tampered.big_q = -tampered.big_q;
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        // Test 3: Swapped P and Q
        let mut tampered = token.clone();
        let temp = tampered.big_p;
        tampered.big_p = tampered.big_q;
        tampered.big_q = temp;
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        // Test 4: Using generator as P or Q
        let mut tampered = token.clone();
        tampered.big_p = test_generator_g();
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        let mut tampered = token.clone();
        tampered.big_q = test_generator_g();
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        // Test 5: All components tampered
        let tampered = Token {
            t: test_random_scalar(&mut rng),
            big_p: test_random_point(&mut rng),
            big_q: test_random_point(&mut rng),
        };
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));
    }

    #[test]
    fn test_tokens_from_different_sessions() {
        let mut rng = rand::thread_rng();
        let params = gen_test_params();
        let (server_private_key, server_public_key, proof) = key_gen(&params, &mut rng);

        // Session 1: Create first token
        let (context1, token_req1) =
            token_request(&server_public_key, &proof, &params, &mut rng).unwrap();
        let response1 = token_response(
            &server_private_key,
            &server_public_key,
            &token_req1,
            2,
            &params,
            &mut rng,
        )
        .unwrap();
        let token1 = finalize_token(
            &context1,
            &server_public_key,
            &token_req1,
            &response1,
            &params,
            &mut rng,
        )
        .unwrap();

        // Session 2: Create second token with different metadata
        let (context2, token_req2) =
            token_request(&server_public_key, &proof, &params, &mut rng).unwrap();
        let response2 = token_response(
            &server_private_key,
            &server_public_key,
            &token_req2,
            3,
            &params,
            &mut rng,
        )
        .unwrap();
        let token2 = finalize_token(
            &context2,
            &server_public_key,
            &token_req2,
            &response2,
            &params,
            &mut rng,
        )
        .unwrap();

        // Mix components from different sessions
        let mut mixed = token1.clone();
        mixed.t = token2.t;
        assert!(bool::from(verify_token(&server_private_key, &mixed, &params).is_none()));

        let mut mixed = token1.clone();
        mixed.big_p = token2.big_p;
        assert!(bool::from(verify_token(&server_private_key, &mixed, &params).is_none()));

        let mut mixed = token1.clone();
        mixed.big_q = token2.big_q;
        assert!(bool::from(verify_token(&server_private_key, &mixed, &params).is_none()));

        // Try partial component mixing
        let mixed = Token { t: token1.t, big_p: token1.big_p, big_q: token2.big_q };
        assert!(bool::from(verify_token(&server_private_key, &mixed, &params).is_none()));

        let mixed = Token { t: token1.t, big_p: token2.big_p, big_q: token1.big_q };
        assert!(bool::from(verify_token(&server_private_key, &mixed, &params).is_none()));

        let mixed = Token { t: token2.t, big_p: token1.big_p, big_q: token1.big_q };
        assert!(bool::from(verify_token(&server_private_key, &mixed, &params).is_none()));
    }

    #[test]
    fn test_forged_tokens() {
        let mut rng = rand::thread_rng();
        let params = gen_test_params();
        let (server_private_key, server_public_key, _proof) = key_gen(&params, &mut rng);

        // Attempt 1: Completely random token
        let forged = Token {
            t: test_random_scalar(&mut rng),
            big_p: test_random_point(&mut rng),
            big_q: test_random_point(&mut rng),
        };
        assert!(bool::from(verify_token(&server_private_key, &forged, &params).is_none()));

        // Attempt 2: Try to forge with known generator relationships
        let rs = test_random_scalar(&mut rng);
        let forged = Token {
            t: rs,
            big_p: test_generator_g() * rs,
            big_q: test_generator_g() * (rs + test_scalar_one()),
        };
        assert!(bool::from(verify_token(&server_private_key, &forged, &params).is_none()));

        // Attempt 3: Try to use server's public key components
        let forged = Token {
            t: Scalar::from(5u64),
            big_p: server_public_key.big_z,
            big_q: server_public_key.big_c_x,
        };
        assert!(bool::from(verify_token(&server_private_key, &forged, &params).is_none()));

        // Attempt 4: Try to construct token that might pass for metadata 0
        // Q should equal x * P for metadata 0, but without proper blinding
        let fake_c = test_random_scalar(&mut rng);
        let fake_p = test_generator_g() * fake_c;
        let fake_t = test_random_scalar(&mut rng);
        let fake_q = fake_p * server_private_key.x; // This won't work without proper protocol
        let forged = Token { t: fake_t, big_p: fake_p, big_q: fake_q };
        assert!(bool::from(verify_token(&server_private_key, &forged, &params).is_none()));
    }

    #[test]
    fn test_dynamic_buckets() {
        let mut rng = rand::thread_rng();

        let test_cases = [
            (1, vec![0]),
            (2, vec![0, 1]),
            (4, (0..4).collect()),
            (8, (0..8).collect()),
            (32, vec![0, 1, 23, 31]),
            (255, vec![0, 1, 23, 42, 254]),
        ];

        // Test with different numbers of buckets
        for (n_buckets, metadata_values) in test_cases {
            let params = Params::new(n_buckets, TEST_DEPLOYMENT_ID.into()).unwrap();
            let (server_private_key, server_public_key, proof) = key_gen(&params, &mut rng);

            // Create token request
            let (context, token_req) =
                token_request(&server_public_key, &proof, &params, &mut rng).unwrap();

            // Test with all valid metadata values for this bucket size
            for metadata in metadata_values {
                let response = token_response(
                    &server_private_key,
                    &server_public_key,
                    &token_req,
                    metadata,
                    &params,
                    &mut rng,
                )
                .unwrap();

                let token = finalize_token(
                    &context,
                    &server_public_key,
                    &token_req,
                    &response,
                    &params,
                    &mut rng,
                )
                .unwrap();

                let recovered = verify_token(&server_private_key, &token, &params).unwrap();
                assert_eq!(recovered, metadata);
            }

            // Test that metadata index >= n_buckets fails
            let (_, token_req2) =
                token_request(&server_public_key, &proof, &params, &mut rng).unwrap();
            let invalid_response = token_response(
                &server_private_key,
                &server_public_key,
                &token_req2,
                n_buckets, // This should be out of range
                &params,
                &mut rng,
            );
            assert!(invalid_response.is_err());
        }
    }

    #[test]
    fn test_serialize_scalar() {
        let x = test_scalar_zero();
        let mut bytes = vec![];
        encode_scalar(&x, &mut bytes);
        let y = decode_scalar(&bytes).0.unwrap();
        assert_eq!(x, y);

        let mut rng = rand::thread_rng();
        let x = test_random_scalar(&mut rng);
        bytes.clear();
        encode_scalar(&x, &mut bytes);
        let y = decode_scalar(&bytes).0.unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn test_serialize_point() {
        let x = test_point_identity();
        let mut bytes = vec![];
        encode_point(&x, &mut bytes);
        let y = decode_point(&bytes).0.unwrap();
        assert_eq!(x, y);

        let mut rng = rand::thread_rng();
        let x = test_random_point(&mut rng);
        bytes.clear();
        encode_point(&x, &mut bytes);
        let y = decode_point(&bytes).0.unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn test_end_to_end_protocol_serialized() {
        let mut rng = rand::thread_rng();
        let params = gen_test_params();
        let mut params_bytes = vec![];
        params.encode(&mut params_bytes);

        // Server generates keys
        let params = Params::decode(&params_bytes).unwrap();
        let (server_private_key, server_public_key, proof) = key_gen(&params, &mut rng);
        let mut server_private_key_bytes = vec![];
        server_private_key.encode(&mut server_private_key_bytes);
        let mut server_public_key_bytes = vec![];
        server_public_key.encode(&mut server_public_key_bytes);
        let mut proof_bytes = vec![];
        proof.encode(&mut proof_bytes);

        // Client creates token request
        let server_public_key = PublicKey::decode(&server_public_key_bytes).unwrap();
        let proof = PublicKeyProof::decode(&proof_bytes).unwrap();
        let params = Params::decode(&params_bytes).unwrap();
        let (context, token_req) =
            token_request(&server_public_key, &proof, &params, &mut rng).unwrap();
        let mut context_bytes = vec![];
        context.encode(&mut context_bytes);
        let mut token_req_bytes = vec![];
        token_req.encode(&mut token_req_bytes);

        // Server chooses hidden metadata and creates response
        let server_private_key = PrivateKey::decode(&server_private_key_bytes).unwrap();
        let server_public_key = PublicKey::decode(&server_public_key_bytes).unwrap();
        let token_req = TokenRequest::decode(&token_req_bytes).unwrap();
        let params = Params::decode(&params_bytes).unwrap();
        let hidden_metadata: u8 = 2;
        let response = token_response(
            &server_private_key,
            &server_public_key,
            &token_req,
            hidden_metadata,
            &params,
            &mut rng,
        )
        .unwrap();
        let mut response_bytes = vec![];
        response.encode(&mut response_bytes);

        // Client finalizes the token
        let context = TokenContext::decode(&context_bytes).unwrap();
        let server_public_key = PublicKey::decode(&server_public_key_bytes).unwrap();
        let token_req = TokenRequest::decode(&token_req_bytes).unwrap();
        let params = Params::decode(&params_bytes).unwrap();
        let response = TokenResponse::decode(&response_bytes, &params).unwrap();
        let token =
            finalize_token(&context, &server_public_key, &token_req, &response, &params, &mut rng)
                .unwrap();
        let mut token_bytes = vec![];
        token.encode(&mut token_bytes);

        // Server verifies the token and recovers the metadata
        let server_private_key = PrivateKey::decode(&server_private_key_bytes).unwrap();
        let token = Token::decode(&token_bytes).unwrap();
        let params = Params::decode(&params_bytes).unwrap();
        let recovered_metadata = verify_token(&server_private_key, &token, &params).unwrap();
        assert_eq!(recovered_metadata, hidden_metadata);
    }
}
