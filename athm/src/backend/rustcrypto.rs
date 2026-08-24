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
//! This module provides [`RustCryptoBackend`], which implements
//! [`AthmBackend`](super::AthmBackend) by delegating to the `p256` and
//! `elliptic-curve` ecosystem.

use super::AthmBackend;
use elliptic_curve::array::typenum::Unsigned;
use elliptic_curve::Generate;
use hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::{
    group::GroupEncoding,
    sec1::ModulusSize,
    subtle::{Choice, CtOption},
    Field, FieldBytes, FieldBytesSize, Group, PrimeField,
};
use p256::{NistP256, NonZeroScalar};
use sha2::Digest;

pub use p256::ProjectivePoint as RustCryptoPoint;
pub use p256::Scalar as RustCryptoScalar;

/// The size of a serialized scalar in bytes.
pub const SCALAR_SIZE: usize = FieldBytesSize::<NistP256>::USIZE;

/// The size of a serialized compressed point in bytes.
pub const POINT_SIZE: usize = <FieldBytesSize<NistP256> as ModulusSize>::CompressedPointSize::USIZE;

/// Zero-sized marker type for the RustCrypto backend.
#[derive(Clone)]
pub struct RustCryptoBackend;

impl AthmBackend for RustCryptoBackend {
    type Scalar = RustCryptoScalar;
    type Point = RustCryptoPoint;

    const SCALAR_SIZE: usize = SCALAR_SIZE;
    const POINT_SIZE: usize = POINT_SIZE;

    fn scalar_zero() -> Self::Scalar {
        RustCryptoScalar::ZERO
    }

    fn scalar_one() -> Self::Scalar {
        RustCryptoScalar::ONE
    }

    fn scalar_is_zero(s: &Self::Scalar) -> Choice {
        s.is_zero()
    }

    fn scalar_invert(s: &Self::Scalar) -> CtOption<Self::Scalar> {
        s.invert()
    }

    fn point_identity() -> Self::Point {
        RustCryptoPoint::IDENTITY
    }

    fn point_generator() -> Self::Point {
        RustCryptoPoint::GENERATOR
    }

    fn point_is_identity(p: &Self::Point) -> Choice {
        p.is_identity()
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        sha2::Sha256::digest(data).into()
    }

    fn hash_to_point(msgs: &[&[u8]], dsts: &[&[u8]]) -> Result<Self::Point, &'static str> {
        NistP256::hash_from_bytes(msgs, dsts).map_err(|_| "hash_to_point failed")
    }

    fn hash_to_scalar(msgs: &[&[u8]], dsts: &[&[u8]]) -> Result<Self::Scalar, &'static str> {
        hash2curve::hash_to_scalar::<
            NistP256,
            ExpandMsgXmd<sha2::Sha256>,
            elliptic_curve::consts::U48,
        >(msgs, dsts)
        .map_err(|_| "hash_to_scalar failed")
    }

    fn encode_scalar(scalar: &Self::Scalar, out: &mut Vec<u8>) {
        out.extend_from_slice(scalar.to_bytes().as_ref());
    }

    fn decode_scalar(input: &[u8]) -> (CtOption<Self::Scalar>, &[u8]) {
        let bytes = FieldBytes::<NistP256>::try_from(&input[..SCALAR_SIZE]).unwrap();
        (RustCryptoScalar::from_repr(bytes), &input[SCALAR_SIZE..])
    }

    fn encode_point(point: &Self::Point, out: &mut Vec<u8>) {
        out.extend_from_slice(point.to_bytes().as_ref());
    }

    fn decode_point(input: &[u8]) -> (CtOption<Self::Point>, &[u8]) {
        let bytes =
            elliptic_curve::sec1::CompressedPoint::<NistP256>::try_from(&input[..POINT_SIZE])
                .unwrap();
        (RustCryptoPoint::from_bytes(&bytes), &input[POINT_SIZE..])
    }

    fn random_scalar() -> Self::Scalar {
        RustCryptoScalar::generate()
    }

    fn random_non_zero_scalar() -> Self::Scalar {
        *NonZeroScalar::generate().as_ref()
    }
}
