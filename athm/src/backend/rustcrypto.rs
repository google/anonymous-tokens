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

//! RustCrypto backend for ATHM using the `p256` and `elliptic-curve` crates.
//!
//! This module re-exports the types from the `p256` crate and provides
//! helper functions that wrap the hash-to-curve/hash-to-scalar operations
//! for use by the ATHM protocol.

pub use p256::ProjectivePoint as RustCryptoPoint;
pub use p256::Scalar as RustCryptoScalar;

// Re-export traits and types needed by lib.rs from the p256/elliptic-curve ecosystem.
pub use elliptic_curve::generic_array::typenum::Unsigned;
pub use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
pub use p256::elliptic_curve::{
    group::GroupEncoding,
    sec1::ModulusSize,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    Field, FieldBytes, FieldBytesSize, Group, PrimeField,
};
pub use p256::{NistP256, NonZeroScalar};

/// The size of a serialized scalar in bytes.
pub const SCALAR_SIZE: usize = FieldBytesSize::<NistP256>::USIZE;

/// The size of a serialized compressed point in bytes.
pub const POINT_SIZE: usize = <FieldBytesSize<NistP256> as ModulusSize>::CompressedPointSize::USIZE;

/// Hash a set of messages to a curve point using the P-256 hash-to-curve suite
/// (P256_XMD:SHA-256_SSWU_RO_).
pub fn hash_to_point(msgs: &[&[u8]], dsts: &[&[u8]]) -> Result<RustCryptoPoint, &'static str> {
    NistP256::hash_from_bytes::<ExpandMsgXmd<sha2::Sha256>>(msgs, dsts)
        .map_err(|_| "hash_to_point failed")
}

/// Hash a set of messages to a scalar using the P-256 hash-to-scalar suite.
pub fn hash_to_scalar(msgs: &[&[u8]], dsts: &[&[u8]]) -> Result<RustCryptoScalar, &'static str> {
    NistP256::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(msgs, dsts)
        .map_err(|_| "hash_to_scalar failed")
}

/// Decode a scalar from a byte slice. Returns the scalar as a `CtOption` and
/// the remaining input.
pub fn decode_scalar(input: &[u8]) -> (CtOption<RustCryptoScalar>, &[u8]) {
    (
        RustCryptoScalar::from_repr(*FieldBytes::<NistP256>::from_slice(&input[..SCALAR_SIZE])),
        &input[SCALAR_SIZE..],
    )
}

/// Decode a point from a byte slice. Returns the point as a `CtOption` and
/// the remaining input.
pub fn decode_point(input: &[u8]) -> (CtOption<RustCryptoPoint>, &[u8]) {
    (RustCryptoPoint::from_bytes((&input[..POINT_SIZE]).into()), &input[POINT_SIZE..])
}

/// Serialize a scalar to bytes and append to the output buffer.
pub fn encode_scalar(scalar: &RustCryptoScalar, out: &mut Vec<u8>) {
    out.extend_from_slice(scalar.to_bytes().as_ref());
}

/// Serialize a point (compressed) to bytes and append to the output buffer.
pub fn encode_point(point: &RustCryptoPoint, out: &mut Vec<u8>) {
    out.extend_from_slice(point.to_bytes().as_ref());
}

/// Generate a random scalar.
pub fn random_scalar<R: rand_core::CryptoRngCore>(rng: &mut R) -> RustCryptoScalar {
    RustCryptoScalar::random(rng)
}

/// Generate a random non-zero scalar.
pub fn random_non_zero_scalar<R: rand_core::CryptoRngCore>(rng: &mut R) -> RustCryptoScalar {
    *NonZeroScalar::random(rng).as_ref()
}

/// The identity element of the group (point at infinity).
#[allow(dead_code)]
pub fn point_identity() -> RustCryptoPoint {
    RustCryptoPoint::IDENTITY
}

/// The standard generator of the P-256 curve.
pub fn point_generator() -> RustCryptoPoint {
    RustCryptoPoint::GENERATOR
}
