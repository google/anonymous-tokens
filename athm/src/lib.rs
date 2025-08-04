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
//! use rand_core::OsRng;
//!
//! // Setup with 4 metadata buckets (e.g., risk levels 0-3)
//! let params = Params::new(4).unwrap();
//! let (private_key, public_key, proof) = key_gen(&params);
//!
//! // Client creates blinded request
//! let mut rng = OsRng;
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

use elliptic_curve::generic_array::typenum::Unsigned;
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::{
    elliptic_curve::{
        bigint::U256,
        group::GroupEncoding,
        ops::Reduce,
        sec1::{ModulusSize, ToEncodedPoint},
        subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
        Field, FieldBytes, FieldBytesSize, Group, PrimeField,
    },
    NistP256, NonZeroScalar, ProjectivePoint, Scalar,
};
use rand_core::{CryptoRngCore, OsRng};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A transcript for Fiat-Shamir transform
///
/// This struct provides a clean abstraction for building transcripts
/// and generating challenges in non-interactive zero-knowledge proofs.
///
/// The transcript follows a similar pattern to anonymous-credit-tokens:
/// - Elements are added with labels for clarity
/// - Points and scalars are length-prefixed
/// - Domain separation is applied when generating challenges
#[derive(Clone)]
struct Transcript {
    hasher: Sha256,
}


impl Transcript {
    /// Create a new transcript
    fn new() -> Self {
        Self { hasher: Sha256::new() }
    }

    /// Add a scalar to the transcript
    fn append_scalar(&mut self, label: &[u8], scalar: &Scalar) {
        let encoded = scalar.to_bytes();
        self.hasher.update((label.len() as u16).to_be_bytes());
        self.hasher.update(label);
        self.hasher.update(&(encoded.len() as u16).to_be_bytes());
        self.hasher.update(&scalar.to_bytes());
    }

    /// Add a point to the transcript
    fn append_point(&mut self, label: &[u8], point: &ProjectivePoint) {
        let encoded = point.to_affine().to_encoded_point(false);
        self.hasher.update((label.len() as u16).to_be_bytes());
        self.hasher.update(label);
        self.hasher.update(&(encoded.len() as u16).to_be_bytes());
        self.hasher.update(encoded.as_bytes());
    }

    /// Generate a challenge scalar with domain separation
    fn challenge(&self, domain_separator: &str) -> Scalar {
        let mut hasher = self.hasher.clone();
        hasher.update((domain_separator.len() as u16).to_be_bytes());
        hasher.update(domain_separator.as_bytes());
        let hash = hasher.finalize();

        // Reduce the hash modulo the curve order
        let hash_bytes: [u8; 32] = hash.into();
        let hash_uint = U256::from_be_slice(&hash_bytes);
        Scalar::reduce(hash_uint)
    }
}

/// Default number of metadata buckets (from spec)
///
/// This is used as a default value for tests and examples.
/// In production use, the number of buckets should be specified
/// dynamically when calling token_response and verify_token.
#[cfg(test)]
const DEFAULT_N_BUCKETS: u8 = 4;

const SCALAR_SIZE: usize = FieldBytesSize::<NistP256>::USIZE;
const POINT_SIZE: usize = <FieldBytesSize<NistP256> as ModulusSize>::CompressedPointSize::USIZE;
const DECODING_ERROR: &'static str = "decoding failed";
const INPUT_TOO_SHORT: &'static str = "input is too short";

// Helper to encode a Scalar and append it to a byte vector.
fn encode_scalar(scalar: &Scalar, out: &mut Vec<u8>) {
    out.extend_from_slice(scalar.to_bytes().as_ref());
}

// Helper to decode a Scalar from a byte slice. Returns a CtOption of the resulting scalar if successful, and a new slice of the remaining input.
// Panics if the input is too small.
fn decode_scalar<'a>(input: &'a [u8]) -> (CtOption<Scalar>, &'a [u8]) {
    (
        Scalar::from_repr(*FieldBytes::<NistP256>::from_slice(&input[..SCALAR_SIZE])),
        &input[SCALAR_SIZE..],
    )
}

// Helper to encode a ProjectivePoint and append it to a byte vector.
fn encode_point(point: &ProjectivePoint, out: &mut Vec<u8>) {
    out.extend_from_slice(point.to_bytes().as_ref());
}

// Helper to decode a ProjectivePoint from a byte slice. Returns a CtOption of the resulting point if successful, and a new slice of the remaining input.
// Panics if the input is too small.
fn decode_point<'a>(input: &'a [u8]) -> (CtOption<ProjectivePoint>, &'a [u8]) {
    (ProjectivePoint::from_bytes((&input[..POINT_SIZE]).into()), &input[POINT_SIZE..])
}

/// Server's private key for the ATHM protocol
///
/// Secret values the server uses to embed and recover hidden metadata.
/// Automatically zeroed on drop for security.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    pub x: Scalar,
    pub y: Scalar,
    pub z: Scalar,
    pub r_x: Scalar,
    pub r_y: Scalar,
}

impl PrivateKey {
    fn encoded_size() -> usize {
        5 * SCALAR_SIZE
    }

    // Encode a private key and append the result to a byte vector.
    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_scalar(&self.x, out);
        encode_scalar(&self.y, out);
        encode_scalar(&self.z, out);
        encode_scalar(&self.r_x, out);
        encode_scalar(&self.r_y, out);
    }

    // Decode a private key from a byte slice. Returns a CtOption with the resulting private key if successful, and None otherwise.
    // Panics if the input is smaller than 5 * SCALAR_SIZE.
    pub fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size() {
            return Err(INPUT_TOO_SHORT);
        }

        let (x, input) = decode_scalar(input);
        let (y, input) = decode_scalar(input);
        let (z, input) = decode_scalar(input);
        let (r_x, input) = decode_scalar(input);
        let (r_y, _input) = decode_scalar(input);

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

/// Server's public key for the ATHM protocol
///
/// Public values clients use to create token requests.
/// Must be verified with the accompanying proof.
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub big_z: ProjectivePoint,
    pub big_c_x: ProjectivePoint,
    pub big_c_y: ProjectivePoint,
}

impl PublicKey {
    fn encoded_size() -> usize {
        3 * POINT_SIZE
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_point(&self.big_z, out);
        encode_point(&self.big_c_x, out);
        encode_point(&self.big_c_y, out);
    }

    pub fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size() {
            return Err(INPUT_TOO_SHORT);
        }

        let (big_z, input) = decode_point(input);
        let (big_c_x, input) = decode_point(input);
        let (big_c_y, _input) = decode_point(input);

        let is_some = big_z.is_some() & big_c_x.is_some() & big_c_y.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }
        Ok(Self { big_z: big_z.unwrap(), big_c_x: big_c_x.unwrap(), big_c_y: big_c_y.unwrap() })
    }
}

/// Proof of knowledge for the server's public key
///
/// Proves the server knows the private key. Clients must verify this
/// before creating token requests.
#[derive(Clone, Debug)]
pub struct PublicKeyProof {
    pub e: Scalar,
    pub a_z: Scalar,
}

impl PublicKeyProof {
    fn encoded_size() -> usize {
        2 * SCALAR_SIZE
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_scalar(&self.e, out);
        encode_scalar(&self.a_z, out);
    }

    pub fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size() {
            return Err(INPUT_TOO_SHORT);
        }

        let (e, input) = decode_scalar(input);
        let (a_z, _input) = decode_scalar(input);

        let is_some = e.is_some() & a_z.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }
        Ok(Self { e: e.unwrap(), a_z: a_z.unwrap() })
    }
}

/// Client's context for a token request
///
/// Secret values the client needs to finalize the token after receiving
/// the server's response. Keep these secure until deleted.
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct TokenContext {
    pub r: Scalar,
    pub tc: Scalar,
}

impl TokenContext {
    fn encoded_size() -> usize {
        2 * SCALAR_SIZE
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_scalar(&self.r, out);
        encode_scalar(&self.tc, out);
    }

    pub fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size() {
            return Err(INPUT_TOO_SHORT);
        }

        let (r, input) = decode_scalar(input);
        let (tc, _input) = decode_scalar(input);

        let is_some = r.is_some() & tc.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }
        Ok(Self { r: r.unwrap(), tc: tc.unwrap() })
    }
}

/// Blinded token request from the client
///
/// A blinded point that hides the client's randomness from the server,
/// ensuring tokens can't be linked to their requests.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub big_t: ProjectivePoint,
}

impl TokenRequest {
    fn encoded_size() -> usize {
        1 * POINT_SIZE
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_point(&self.big_t, out);
    }

    pub fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size() {
            return Err(INPUT_TOO_SHORT);
        }
        let (big_t, _) = decode_point(input);
        if !bool::from(big_t.is_some()) {
            return Err(DECODING_ERROR);
        }
        Ok(Self { big_t: big_t.unwrap() })
    }
}

/// Zero-knowledge proof for token issuance
///
/// Proves the server correctly embedded metadata without revealing
/// which metadata value was chosen.
#[derive(Default, Debug, Clone)]
pub struct IssuanceProof {
    pub big_c: ProjectivePoint,
    pub e_vec: Vec<Scalar>,
    pub a_vec: Vec<Scalar>,
    pub a_d: Scalar,
    pub a_rho: Scalar,
    pub a_w: Scalar,
}

impl IssuanceProof {
    fn encoded_size(params: &Params) -> usize {
        3 * SCALAR_SIZE + 1 * POINT_SIZE + 2 * params.n_buckets as usize * SCALAR_SIZE
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_point(&self.big_c, out);
        for e in &self.e_vec {
            encode_scalar(&e, out);
        }
        for a in &self.a_vec {
            encode_scalar(&a, out);
        }
        encode_scalar(&self.a_d, out);
        encode_scalar(&self.a_rho, out);
        encode_scalar(&self.a_w, out);
    }

    pub fn decode<'a>(input: &'a [u8], params: &Params) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size(params) {
            return Err(INPUT_TOO_SHORT);
        }

        let (big_c, mut input) = decode_point(input);
        let mut is_some = big_c.is_some();
        let mut e_vec = Vec::new();
        for _ in 0..params.n_buckets {
            let e;
            (e, input) = decode_scalar(input);
            is_some &= e.is_some();
            e_vec.push(e.unwrap_or(Scalar::ZERO));
        }
        let mut a_vec = Vec::new();
        for _ in 0..params.n_buckets {
            let a;
            (a, input) = decode_scalar(input);
            is_some &= a.is_some();
            a_vec.push(a.unwrap_or(Scalar::ZERO));
        }
        let (a_d, input) = decode_scalar(input);
        let (a_rho, input) = decode_scalar(input);
        let (a_w, _input) = decode_scalar(input);

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

/// Server's response to a token request
///
/// Contains signed values with hidden metadata embedded and a proof
/// of correct computation.
#[derive(Default, Debug, Clone)]
pub struct TokenResponse {
    pub big_u: ProjectivePoint,
    pub big_v: ProjectivePoint,
    pub ts: Scalar,
    pub issuance_proof: IssuanceProof,
}

impl TokenResponse {
    fn encoded_size(params: &Params) -> usize {
        1 * SCALAR_SIZE + 2 * POINT_SIZE + IssuanceProof::encoded_size(params)
    }

    // Encodes a response and appends the result to the given byte vector.
    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_point(&self.big_u, out);
        encode_point(&self.big_v, out);
        encode_scalar(&self.ts, out);
        self.issuance_proof.encode(out);
    }

    // Decodes a response from the given byte slice.
    pub fn decode<'a>(input: &'a [u8], params: &Params) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size(params) {
            return Err(INPUT_TOO_SHORT);
        }
        let (big_u, input) = decode_point(input);
        let (big_v, input) = decode_point(input);
        let (ts, input) = decode_scalar(input);

        let is_some = big_u.is_some() & big_v.is_some() & ts.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }

        let issuance_proof = IssuanceProof::decode(input, params)?;
        Ok(Self {
            big_u: big_u.unwrap(),
            big_v: big_v.unwrap(),
            ts: ts.unwrap(),
            issuance_proof: issuance_proof,
        })
    }
}

/// Finalized anonymous token
///
/// The unblinded token clients present for authentication.
/// Contains hidden metadata only the server can recover.
/// Automatically zeroed on drop for security.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Token {
    pub t: Scalar,
    pub big_p: ProjectivePoint,
    pub big_q: ProjectivePoint,
}

impl Token {
    fn encoded_size() -> usize {
        1 * SCALAR_SIZE + 2 * POINT_SIZE
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_scalar(&self.t, out);
        encode_point(&self.big_p, out);
        encode_point(&self.big_q, out);
    }

    pub fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size() {
            return Err(INPUT_TOO_SHORT);
        }

        let (t, input) = decode_scalar(input);
        let (big_p, input) = decode_point(input);
        let (big_q, _input) = decode_point(input);

        let is_some = t.is_some() & big_p.is_some() & big_q.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }
        Ok(Self { t: t.unwrap(), big_p: big_p.unwrap(), big_q: big_q.unwrap() })
    }
}

/// Protocol parameters
///
/// Defines the number of metadata buckets and elliptic curve generators.
/// Create once and reuse throughout the protocol.
///
/// ```
/// use athm::Params;
/// let params = Params::new(4).unwrap(); // 4 metadata buckets
/// ```
#[derive(Debug, Clone)]
pub struct Params {
    /// Number of metadata buckets
    pub n_buckets: u8,
    /// Generator G (standard P256 generator)
    pub big_g: ProjectivePoint,
    /// Generator H (derived from G via hash-to-curve)
    pub big_h: ProjectivePoint,
}

impl Params {
    /// Create new protocol parameters
    ///
    /// # Arguments
    ///
    /// * `n_buckets` - Number of metadata values (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns error if n_buckets is 0
    pub fn new(n_buckets: u8) -> Result<Self, &'static str> {
        if n_buckets == 0 {
            return Err("Number of buckets must be greater than 0");
        }

        Ok(Params { n_buckets, big_g: generator_g(), big_h: generator_h() })
    }

    fn encoded_size() -> usize {
        1 + 2 * POINT_SIZE
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.n_buckets);
        encode_point(&self.big_g, out);
        encode_point(&self.big_h, out);
    }

    /// Decode parameters from the given byte slice.
    /// Returns an error if the decoding fails or the provided slice is too short.
    pub fn decode<'a>(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < Self::encoded_size() {
            return Err(INPUT_TOO_SHORT);
        }
        let (n_buckets, input) = (input[0], &input[1..]);
        let (big_g, input) = decode_point(input);
        let (big_h, _input) = decode_point(input);

        let is_some = big_g.is_some() & big_h.is_some();
        if !bool::from(is_some) {
            return Err(DECODING_ERROR);
        }
        Ok(Self { n_buckets: n_buckets, big_g: big_g.unwrap(), big_h: big_h.unwrap() })
    }
}

/// Get the generator G for the P256 curve
fn generator_g() -> ProjectivePoint {
    ProjectivePoint::GENERATOR
}

/// Get the generator H by hashing generator G
fn generator_h() -> ProjectivePoint {
    let g = generator_g();
    let g_bytes = g.to_affine().to_encoded_point(false);
    let g_bytes = g_bytes.as_bytes();

    // Use hash-to-curve to derive H from G
    let dst = b"P256_XMD:SHA-256_SSWU_RO_generatorH";
    let msg_array: &[&[u8]] = &[g_bytes];
    let dst_array: &[&[u8]] = &[&dst[..]];
    // Safety (see docs for ExpandMsgXmd)
    // - destination is not empty
    // - input is not empty and is less than or equal to u16::MAX bytes
    // - input is not greater than 255 * 32
    let h = NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(msg_array, dst_array).unwrap();

    ProjectivePoint::from(h)
}

/// Generate a random scalar
fn random_scalar<R: CryptoRngCore>(rng: &mut R) -> Scalar {
    Scalar::random(rng)
}

/// Generate a random non-zero scalar
fn random_non_zero_scalar<R: CryptoRngCore>(rng: &mut R) -> Scalar {
    *NonZeroScalar::random(rng).as_ref()
}

/// Create a proof of knowledge for the public key
fn create_public_key_proof<R: CryptoRngCore>(
    z: &Scalar,
    big_z: &ProjectivePoint,
    params: &Params,
    rng: &mut R,
) -> PublicKeyProof {
    // Generate random scalar rho_z
    let rho_z = random_scalar(rng);

    // Compute gamma_z = rho_z * G
    let gamma_z = params.big_g * rho_z;

    // Build transcript and compute challenge
    let mut transcript = Transcript::new();
    transcript.append_point(b"G", &params.big_g);
    transcript.append_point(b"Z", big_z);
    transcript.append_point(b"gamma_z", &gamma_z);

    // Compute challenge e = HashToScalar(transcript, "KeyCommitments")
    let e = transcript.challenge("KeyCommitments");

    // Compute a_z = rho_z - (e * z)
    let a_z = rho_z - (e * z);

    PublicKeyProof { e, a_z }
}

/// Verify a public key proof
///
/// Checks that the server knows the private key. Call this before
/// creating token requests.
pub fn verify_public_key_proof(pk: &PublicKey, proof: &PublicKeyProof, params: &Params) -> bool {
    // Recompute gamma_z = a_z * G + e * Z
    let gamma_z = params.big_g * proof.a_z + pk.big_z * proof.e;

    // Build transcript and recompute challenge
    let mut transcript = Transcript::new();
    transcript.append_point(b"G", &params.big_g);
    transcript.append_point(b"Z", &pk.big_z);
    transcript.append_point(b"gamma_z", &gamma_z);

    // Recompute challenge e = HashToScalar(transcript, "KeyCommitments")
    let e_verify = transcript.challenge("KeyCommitments");

    // Verify that e_computed equals e using constant-time comparison
    proof.e.ct_eq(&e_verify).into()
}

/// Generate server keys
///
/// Creates a new private/public key pair and proof for the server.
///
/// # Example
///
/// ```
/// use athm::{key_gen, Params};
/// let params = Params::new(4).unwrap();
/// let (private_key, public_key, proof) = key_gen(&params);
/// ```
pub fn key_gen(params: &Params) -> (PrivateKey, PublicKey, PublicKeyProof) {
    let mut rng = OsRng;

    // Generate random scalars
    let x = random_scalar(&mut rng);
    let y = random_non_zero_scalar(&mut rng);
    let z = random_non_zero_scalar(&mut rng);
    let r_x = random_scalar(&mut rng);
    let r_y = random_scalar(&mut rng);

    // Compute public key elements
    let big_z = params.big_g * z;
    let big_c_x = (params.big_g * x) + (params.big_h * r_x);
    let big_c_y = (params.big_g * y) + (params.big_h * r_y);

    // Create proof of knowledge for z
    let pi = create_public_key_proof(&z, &big_z, params, &mut rng);

    let private_key = PrivateKey { x, y, z, r_x, r_y };
    let public_key = PublicKey { big_z, big_c_x, big_c_y };

    (private_key, public_key, pi)
}

/// Create a token request (client side)
///
/// Creates a blinded request that hides the client's randomness.
/// Returns context needed to finalize the token later.
///
/// # Errors
///
/// Returns error if the public key proof is invalid.
pub fn token_request<R: CryptoRngCore>(
    public_key: &PublicKey,
    public_key_proof: &PublicKeyProof,
    params: &Params,
    rng: &mut R,
) -> Result<(TokenContext, TokenRequest), &'static str> {
    // First verify the public key proof
    if !verify_public_key_proof(public_key, public_key_proof, params) {
        return Err("Invalid public key proof");
    }

    // Generate random scalars r and tc
    let r = random_scalar(rng);
    let tc = random_scalar(rng);

    // Compute T = r * G + tc * Z
    let big_t = params.big_g * r + public_key.big_z * tc;

    // Create token context
    let context = TokenContext { r, tc };

    // Create token request
    let request = TokenRequest { big_t };

    Ok((context, request))
}

/// Create an issuance proof for the token response
#[allow(clippy::too_many_arguments)]
fn create_issuance_proof<R: CryptoRngCore>(
    private_key: &PrivateKey,
    public_key: &PublicKey,
    hidden_metadata: u8,
    params: &Params,
    d: &Scalar,
    big_u: &ProjectivePoint,
    big_v: &ProjectivePoint,
    ts: &Scalar,
    big_t: &ProjectivePoint,
    rng: &mut R,
) -> IssuanceProof {
    // Generate random values for the proof
    let mut e_vec: Vec<Scalar> = (0..params.n_buckets)
        .map(|i| {
            Scalar::conditional_select(
                &random_scalar(rng),
                &Scalar::ZERO,
                i.ct_eq(&hidden_metadata),
            )
        })
        .collect();
    let mut a_vec: Vec<Scalar> = (0..params.n_buckets)
        .map(|i| {
            Scalar::conditional_select(
                &random_scalar(rng),
                &Scalar::ZERO,
                i.ct_eq(&hidden_metadata),
            )
        })
        .collect();

    let r_mu = random_scalar(rng);
    let r_d = random_scalar(rng);
    let r_rho = random_scalar(rng);
    let r_w = random_scalar(rng);
    let mu = random_scalar(rng);

    // Compute C = hiddenMetadata * C_y + mu * H
    let big_c = public_key.big_c_y * Scalar::from(hidden_metadata as u64) + params.big_h * mu;

    // Compute C_vec[i] for all buckets
    let c_vec: Vec<ProjectivePoint> = (0..params.n_buckets)
        .map(|i| {
            ProjectivePoint::conditional_select(
                &(params.big_h * a_vec[i as usize]
                    - (big_c - public_key.big_c_y * Scalar::from(i as u64)) * e_vec[i as usize]),
                &(params.big_h * r_mu),
                i.ct_eq(&hidden_metadata),
            )
        })
        .collect();

    // Compute commitments
    let c_d = *big_u * r_d;
    let c_rho = *big_v * r_d + params.big_h * r_rho;
    let c_w = *big_v * r_d + params.big_g * r_w;

    // Build challenge transcript
    let mut transcript = Transcript::new();

    // Add all elements according to spec
    transcript.append_point(b"G", &params.big_g);
    transcript.append_point(b"H", &params.big_h);
    transcript.append_point(b"C_x", &public_key.big_c_x);
    transcript.append_point(b"C_y", &public_key.big_c_y);
    transcript.append_point(b"Z", &public_key.big_z);
    transcript.append_point(b"U", big_u);
    transcript.append_point(b"V", big_v);

    // Add ts (serialized scalar)
    transcript.append_scalar(b"ts", ts);

    // Add T and C
    transcript.append_point(b"T", big_t);
    transcript.append_point(b"C", &big_c);

    // Add all C_vec[i] to transcript
    c_vec.iter().enumerate().for_each(|(i, c_i)| {
        transcript.append_point(&format!("C_{}", i).as_bytes(), c_i);
    });

    // Add C_d, C_rho, C_w
    transcript.append_point(b"C_d", &c_d);
    transcript.append_point(b"C_rho", &c_rho);
    transcript.append_point(b"C_w", &c_w);

    // Hash to get challenge e
    let e = transcript.challenge("TokenResponseProof");

    // Calculate e_vec[hidden_metadata] = e - sum(other e_vec values)
    let e_sum: Scalar = e_vec.iter().sum();
    e_vec.iter_mut().enumerate().for_each(|(i, e_val)| {
        *e_val = Scalar::conditional_select(e_val, &(e - e_sum), (i as u8).ct_eq(&hidden_metadata));
    });

    // Calculate proof values
    let d_inv = d.invert().unwrap();
    let rho = -(private_key.r_x + Scalar::from(hidden_metadata as u64) * private_key.r_y + mu);
    let w =
        private_key.x + Scalar::from(hidden_metadata as u64) * private_key.y + *ts * private_key.z;

    let a_hidden_metadata = r_mu + (e - e_sum) * mu;

    // Set the correct a_vec[hidden_metadata] value
    a_vec.iter_mut().enumerate().for_each(|(i, a_val)| {
        *a_val = Scalar::conditional_select(
            a_val,
            &a_hidden_metadata,
            (i as u8).ct_eq(&hidden_metadata),
        );
    });
    let a_d = r_d - e * d_inv;
    let a_rho = r_rho + e * rho;
    let a_w = r_w + e * w;

    IssuanceProof { big_c, e_vec, a_vec, a_d, a_rho, a_w }
}

/// Create a token response (server side)
///
/// Embeds hidden metadata and signs the token request.
///
/// # Arguments
///
/// * `hidden_metadata` - Metadata value to embed (0 to n_buckets-1)
///
/// # Errors
///
/// Returns error if metadata index is out of range.
pub fn token_response<R: CryptoRngCore>(
    private_key: &PrivateKey,
    public_key: &PublicKey,
    token_request: &TokenRequest,
    hidden_metadata: u8,
    params: &Params,
    rng: &mut R,
) -> Result<TokenResponse, &'static str> {
    if hidden_metadata >= params.n_buckets {
        return Err("Hidden metadata index out of range");
    }

    let big_t = &token_request.big_t;

    let ts = random_scalar(rng);
    let d = random_non_zero_scalar(rng);

    let big_u = params.big_g * d;

    // Compute V = d * (X + hiddenMetadata * Y + ts * Z + T)
    let big_x = params.big_g * private_key.x;
    let big_y = params.big_g * private_key.y;
    let big_v =
        (big_x + big_y * Scalar::from(hidden_metadata as u64) + public_key.big_z * ts + big_t) * d;

    // Create issuance proof
    let issuance_proof = create_issuance_proof(
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

    Ok(TokenResponse { big_u, big_v, ts, issuance_proof })
}

/// Verify an issuance proof
///
/// Checks that the server correctly computed the token response.
/// Called internally by `finalize_token`.
pub fn verify_issuance_proof(
    pk: &PublicKey,
    big_t: &ProjectivePoint,
    response: &TokenResponse,
    params: &Params,
) -> bool {
    let proof = &response.issuance_proof;
    let big_u = &response.big_u;
    let big_v = &response.big_v;
    let ts = &response.ts;

    // Recompute C_vec[i] for all buckets
    let c_vec: Vec<ProjectivePoint> = (0..params.n_buckets)
        .map(|i| {
            // C_vec[i] = a_vec[i] * H - e_vec[i] * (C - i * C_y)
            params.big_h * proof.a_vec[i as usize]
                - (proof.big_c - pk.big_c_y * Scalar::from(i as u64)) * proof.e_vec[i as usize]
        })
        .collect();

    // Compute e = sum(e_vec)
    let e: Scalar = proof.e_vec.iter().sum();

    // Compute commitments according to spec
    let c_d = big_u * &proof.a_d + params.big_g * &e;
    let c_rho = big_v * &proof.a_d
        + params.big_h * &proof.a_rho
        + (pk.big_c_x + proof.big_c + pk.big_z * ts + big_t) * &e;
    let c_w = big_v * &proof.a_d + params.big_g * &proof.a_w + big_t * &e;

    // Build challenge transcript
    let mut transcript = Transcript::new();

    // Add elements according to spec
    transcript.append_point(b"G", &params.big_g);
    transcript.append_point(b"H", &params.big_h);
    transcript.append_point(b"C_x", &pk.big_c_x);
    transcript.append_point(b"C_y", &pk.big_c_y);
    transcript.append_point(b"Z", &pk.big_z);
    transcript.append_point(b"U", big_u);
    transcript.append_point(b"V", big_v);

    // Add ts (serialized scalar)
    transcript.append_scalar(b"ts", ts);

    // Add T and C
    transcript.append_point(b"T", big_t);
    transcript.append_point(b"C", &proof.big_c);

    // Add all C_vec[i] to transcript
    c_vec.iter().enumerate().for_each(|(i, c_i)| {
        transcript.append_point(&format!("C_{}", i).as_bytes(), c_i);
    });

    // Add C_d, C_rho, C_w
    transcript.append_point(b"C_d", &c_d);
    transcript.append_point(b"C_rho", &c_rho);
    transcript.append_point(b"C_w", &c_w);

    // Hash to get challenge e_verify
    let e_verify = transcript.challenge("TokenResponseProof");

    // Verify that computed e equals e_verify
    e.ct_eq(&e_verify).into()
}

/// Finalize a token (client side)
///
/// Unblinds the server's response to get the final token.
///
/// # Errors
///
/// Returns error if the issuance proof is invalid.
pub fn finalize_token<R: CryptoRngCore>(
    context: &TokenContext,
    public_key: &PublicKey,
    request: &TokenRequest,
    response: &TokenResponse,
    params: &Params,
    rng: &mut R,
) -> Result<Token, &'static str> {
    // First verify the issuance proof
    if !verify_issuance_proof(public_key, &request.big_t, response, params) {
        return Err("Invalid issuance proof");
    }

    let c = random_non_zero_scalar(rng);

    // Compute P = c * U
    let big_p = response.big_u * c;

    // Compute Q = c * (V - r * U)
    let big_q = (response.big_v - response.big_u * context.r) * c;

    // Compute t = tc + ts
    let t = context.tc + response.ts;

    Ok(Token { t, big_p, big_q })
}

/// Verify token and recover metadata (server side)
///
/// Validates the token and extracts the hidden metadata value.
/// Returns `None` if the token is invalid.
pub fn verify_token(private_key: &PrivateKey, token: &Token, params: &Params) -> CtOption<u8> {
    // Check that P and Q are not identity (zero)
    let check = token.big_p.is_identity() | token.big_q.is_identity();

    // Try each bucket to find the matching metadata
    let i_match = (0..params.n_buckets).fold(CtOption::new(0u8, Choice::from(0u8)), |acc, i| {
        // Compute Q_i = (x + t * z + i * y) * P
        let q_i = token.big_p
            * (private_key.x + token.t * private_key.z + Scalar::from(i as u64) * private_key.y);

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


    fn test_params() -> Params {
        Params::new(DEFAULT_N_BUCKETS).unwrap()
    }

    #[test]
    fn test_key_gen() {
        let params = test_params();
        let (private_key, public_key, _proof) = key_gen(&params);

        // Verify that the keys were generated
        assert!(!bool::from(private_key.x.is_zero()));
        assert!(!bool::from(private_key.y.is_zero()));
        assert!(!bool::from(private_key.z.is_zero()));

        // Verify public key points are not identity
        assert!(!bool::from(public_key.big_z.is_identity()));
        assert!(!bool::from(public_key.big_c_x.is_identity()));
        assert!(!bool::from(public_key.big_c_y.is_identity()));
    }

    #[test]
    fn test_generators() {
        let g = generator_g();
        let h = generator_h();

        // Verify generators are distinct
        assert!(g != h);

        // Verify generators are not identity
        assert!(!bool::from(g.is_identity()));
        assert!(!bool::from(h.is_identity()));
    }

    #[test]
    fn test_verify_public_key_proof() {
        let params = test_params();
        let (_, public_key, proof) = key_gen(&params);

        // Verify that the proof is valid
        assert!(verify_public_key_proof(&public_key, &proof, &params));

        // Test with invalid proof (modified challenge)
        let mut invalid_proof = proof.clone();
        invalid_proof.e = invalid_proof.e + Scalar::ONE;
        assert!(!verify_public_key_proof(&public_key, &invalid_proof, &params));

        // Test with invalid proof (modified response)
        let mut invalid_proof2 = proof.clone();
        invalid_proof2.a_z = invalid_proof2.a_z + Scalar::ONE;
        assert!(!verify_public_key_proof(&public_key, &invalid_proof2, &params));
    }

    #[test]
    fn test_token_request() {
        let mut rng = OsRng;
        let params = test_params();
        let (_, public_key, proof) = key_gen(&params);

        // Create a token request
        let result = token_request(&public_key, &proof, &params, &mut rng);
        assert!(result.is_ok());

        let (context, request) = result.unwrap();

        // Verify that the request T is not identity
        assert!(!bool::from(request.big_t.is_identity()));

        // Verify context contains random scalars
        assert!(!bool::from(context.r.is_zero()));
        assert!(!bool::from(context.tc.is_zero()));

        // Test with invalid proof
        let mut invalid_proof = proof.clone();
        invalid_proof.e = invalid_proof.e + Scalar::ONE;
        let result = token_request(&public_key, &invalid_proof, &params, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_response() {
        let mut rng = OsRng;
        let params = test_params();
        let (server_private_key, server_public_key, proof) = key_gen(&params);

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
        assert!(!bool::from(response.big_u.is_identity()));
        assert!(!bool::from(response.big_v.is_identity()));

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
        let mut rng = OsRng;
        let params = test_params();
        let (server_private_key, server_public_key, proof) = key_gen(&params);

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
                tampered_response.issuance_proof.e_vec[0] + Scalar::ONE;
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
        let mut rng = OsRng;
        let params = test_params();

        // Server generates keys
        let (server_private_key, server_public_key, proof) = key_gen(&params);

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
        let mut rng = OsRng;
        let params = test_params();
        let (server_private_key, server_public_key, proof) = key_gen(&params);

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
        invalid_token.big_p = ProjectivePoint::IDENTITY;
        assert!(bool::from(verify_token(&server_private_key, &invalid_token, &params).is_none()));

        // Test with identity Q (should fail)
        let mut invalid_token2 = token.clone();
        invalid_token2.big_q = ProjectivePoint::IDENTITY;
        assert!(bool::from(verify_token(&server_private_key, &invalid_token2, &params).is_none()));

        // Test with modified t (should fail to find match)
        let mut invalid_token3 = token.clone();
        invalid_token3.t = invalid_token3.t + Scalar::ONE;
        assert!(bool::from(verify_token(&server_private_key, &invalid_token3, &params).is_none()));
    }

    #[test]
    fn test_tampered_tokens() {
        let mut rng = OsRng;
        let params = test_params();
        let (server_private_key, server_public_key, proof) = key_gen(&params);

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
        tampered.t = tampered.t + Scalar::ONE;
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
        tampered.t = Scalar::random(&mut rng);
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        // Test 2: Tampered points P and Q
        // Modified P with random point
        let mut tampered = token.clone();
        tampered.big_p = ProjectivePoint::random(&mut rng);
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        // Modified Q with random point
        let mut tampered = token.clone();
        tampered.big_q = ProjectivePoint::random(&mut rng);
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
        tampered.big_p = ProjectivePoint::GENERATOR;
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        let mut tampered = token.clone();
        tampered.big_q = ProjectivePoint::GENERATOR;
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));

        // Test 5: All components tampered
        let tampered = Token {
            t: Scalar::random(&mut rng),
            big_p: ProjectivePoint::random(&mut rng),
            big_q: ProjectivePoint::random(&mut rng),
        };
        assert!(bool::from(verify_token(&server_private_key, &tampered, &params).is_none()));
    }

    #[test]
    fn test_tokens_from_different_sessions() {
        let mut rng = OsRng;
        let params = test_params();
        let (server_private_key, server_public_key, proof) = key_gen(&params);

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
        let mut rng = OsRng;
        let params = test_params();
        let (server_private_key, server_public_key, _proof) = key_gen(&params);

        // Attempt 1: Completely random token
        let forged = Token {
            t: Scalar::random(&mut rng),
            big_p: ProjectivePoint::random(&mut rng),
            big_q: ProjectivePoint::random(&mut rng),
        };
        assert!(bool::from(verify_token(&server_private_key, &forged, &params).is_none()));

        // Attempt 2: Try to forge with known generator relationships
        let random_scalar = Scalar::random(&mut rng);
        let forged = Token {
            t: random_scalar,
            big_p: ProjectivePoint::GENERATOR * random_scalar,
            big_q: ProjectivePoint::GENERATOR * (random_scalar + Scalar::ONE),
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
        let fake_c = Scalar::random(&mut rng);
        let fake_p = ProjectivePoint::GENERATOR * fake_c;
        let fake_t = Scalar::random(&mut rng);
        let fake_q = fake_p * server_private_key.x; // This won't work without proper protocol
        let forged = Token { t: fake_t, big_p: fake_p, big_q: fake_q };
        assert!(bool::from(verify_token(&server_private_key, &forged, &params).is_none()));
    }

    #[test]
    fn test_dynamic_buckets() {
        let mut rng = OsRng;

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
            let params = Params::new(n_buckets).unwrap();
            let (server_private_key, server_public_key, proof) = key_gen(&params);

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

        // Test with n_buckets = 0 (should fail)
        let params_zero = Params::new(0);
        assert!(params_zero.is_err());
    }

    #[test]
    fn test_serialize_scalar() {
        let x = Scalar::ZERO;
        let mut bytes = vec![];
        encode_scalar(&x, &mut bytes);
        let y = decode_scalar(&bytes).0.unwrap();
        assert_eq!(x, y);

        let x = Scalar::random(OsRng);
        bytes.clear();
        encode_scalar(&x, &mut bytes);
        let y = decode_scalar(&bytes).0.unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn test_serialize_point() {
        let x = ProjectivePoint::IDENTITY;
        let mut bytes = vec![];
        encode_point(&x, &mut bytes);
        let y = decode_point(&bytes).0.unwrap();
        assert_eq!(x, y);

        let x = generator_g() * Scalar::random(OsRng);
        bytes.clear();
        encode_point(&x, &mut bytes);
        let y = decode_point(&bytes).0.unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn test_end_to_end_protocol_serialized() {
        let mut rng = OsRng;
        let params = test_params();
        let mut params_bytes = vec![];
        params.encode(&mut params_bytes);

        // Server generates keys
        let params = Params::decode(&params_bytes).unwrap();
        let (server_private_key, server_public_key, proof) = key_gen(&params);
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
