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

//! Backend abstraction for elliptic curve operations.
//!
//! This module defines the [`AthmBackend`] trait for scalar and point operations
//! on P-256, allowing the ATHM protocol to be backed by different ECC
//! implementations.
//!
//! Available backends (selected via Cargo features):
//! - `rustcrypto` (default): Uses the `p256` and `elliptic-curve` crates.
//! - `boringssl`: Uses BoringSSL via `bssl-sys`.

use core::fmt;
use core::ops::{Add, Mul, Neg, Sub};
use rand_core::CryptoRngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

#[cfg(feature = "rustcrypto")]
pub mod rustcrypto;

#[cfg(feature = "boringssl")]
pub mod boringssl;

#[cfg(all(test, feature = "rustcrypto", feature = "boringssl"))]
mod cross_backend_test;

/// Trait abstracting the elliptic curve backend for the ATHM protocol.
///
/// Implementors provide P-256 scalar and point types along with all
/// operations needed by the protocol (arithmetic, hashing, serialization).
pub trait AthmBackend: 'static + Sized {
    /// Scalar type (element of the P-256 scalar field).
    type Scalar: Copy
        + Clone
        + fmt::Debug
        + Default
        + PartialEq
        + Eq
        + Zeroize
        + Add<Output = Self::Scalar>
        + Sub<Output = Self::Scalar>
        + Mul<Output = Self::Scalar>
        + Neg<Output = Self::Scalar>
        + From<u64>
        + ConstantTimeEq
        + ConditionallySelectable;

    /// Point type (element of the P-256 curve group).
    type Point: Copy
        + Clone
        + fmt::Debug
        + Default
        + PartialEq
        + Eq
        + Zeroize
        + Add<Output = Self::Point>
        + Sub<Output = Self::Point>
        + Neg<Output = Self::Point>
        + Mul<Self::Scalar, Output = Self::Point>
        + ConstantTimeEq
        + ConditionallySelectable;

    /// Size of a serialized scalar in bytes.
    const SCALAR_SIZE: usize;

    /// Size of a serialized (compressed) point in bytes.
    const POINT_SIZE: usize;

    // ----- Scalar constants and operations -----

    /// The additive identity (zero).
    fn scalar_zero() -> Self::Scalar;

    /// The multiplicative identity (one).
    fn scalar_one() -> Self::Scalar;

    /// Returns whether the scalar is zero, as a constant-time `Choice`.
    fn scalar_is_zero(s: &Self::Scalar) -> Choice;

    /// Computes the modular inverse. Returns `None` (in constant time) if the
    /// input is zero.
    fn scalar_invert(s: &Self::Scalar) -> CtOption<Self::Scalar>;

    // ----- Point constants and operations -----

    /// The identity element (point at infinity).
    fn point_identity() -> Self::Point;

    /// The standard P-256 generator.
    fn point_generator() -> Self::Point;

    /// Returns whether the point is the identity, as a constant-time `Choice`.
    fn point_is_identity(p: &Self::Point) -> Choice;

    // ----- Hash functions -----

    /// Hash to a curve point (P256_XMD:SHA-256_SSWU_RO_).
    fn hash_to_point(msgs: &[&[u8]], dsts: &[&[u8]]) -> Result<Self::Point, &'static str>;

    /// Hash to a scalar (using expand_message_xmd with SHA-256).
    fn hash_to_scalar(msgs: &[&[u8]], dsts: &[&[u8]]) -> Result<Self::Scalar, &'static str>;

    // ----- Serialization -----

    /// Serialize a scalar and append to the output buffer.
    fn encode_scalar(scalar: &Self::Scalar, out: &mut Vec<u8>);

    /// Deserialize a scalar from the front of `input`. Returns the scalar
    /// (as a `CtOption`) and the remaining slice.
    fn decode_scalar(input: &[u8]) -> (CtOption<Self::Scalar>, &[u8]);

    /// Serialize a point (compressed) and append to the output buffer.
    fn encode_point(point: &Self::Point, out: &mut Vec<u8>);

    /// Deserialize a point from the front of `input`. Returns the point
    /// (as a `CtOption`) and the remaining slice.
    fn decode_point(input: &[u8]) -> (CtOption<Self::Point>, &[u8]);

    // ----- Random generation -----

    /// Generate a uniformly random scalar.
    fn random_scalar<R: CryptoRngCore>(rng: &mut R) -> Self::Scalar;

    /// Generate a uniformly random non-zero scalar.
    fn random_non_zero_scalar<R: CryptoRngCore>(rng: &mut R) -> Self::Scalar;
}

// ---------------------------------------------------------------------------
// Default backend selection (compile-time, via Cargo features)
// ---------------------------------------------------------------------------

/// The default backend, selected at compile time.
///
/// When `boringssl` is enabled it takes priority; otherwise `rustcrypto` is
/// used.
#[cfg(feature = "boringssl")]
pub type DefaultBackend = boringssl::BoringSslBackend;

#[cfg(all(feature = "rustcrypto", not(feature = "boringssl")))]
pub type DefaultBackend = rustcrypto::RustCryptoBackend;

// Re-export scalar/point sizes from the default backend for convenience.
pub const SCALAR_SIZE: usize = DefaultBackend::SCALAR_SIZE;
pub const POINT_SIZE: usize = DefaultBackend::POINT_SIZE;

/// Convenience alias for the default scalar type.
pub type Scalar = <DefaultBackend as AthmBackend>::Scalar;

/// Convenience alias for the default point type.
pub type Point = <DefaultBackend as AthmBackend>::Point;
