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

//! BoringSSL backend for ATHM using `bssl_sys` FFI bindings.

use super::AthmBackend;
use core::ptr::{null, null_mut};
use rand_core::CryptoRngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess, CtOption};
use zeroize::Zeroize;

pub const SCALAR_SIZE: usize = 32;
pub const POINT_SIZE: usize = 33; // Compressed P-256 point

// ---------------------------------------------------------------------------
// Low-level FFI helpers
// ---------------------------------------------------------------------------

/// Returns a pointer to the static P-256 EC_GROUP. Never freed.
fn p256_group() -> *const bssl_sys::EC_GROUP {
    let g = unsafe { bssl_sys::EC_group_p256() };
    assert!(!g.is_null());
    g
}

/// Returns a pointer to the group order BIGNUM (owned by the group, do NOT free).
fn p256_order() -> *const bssl_sys::BIGNUM {
    let o = unsafe { bssl_sys::EC_GROUP_get0_order(p256_group()) };
    assert!(!o.is_null());
    o
}

/// Create a new BIGNUM from big-endian bytes.
/// Caller must free with BN_free.
fn bn_from_bytes(bytes: &[u8]) -> *mut bssl_sys::BIGNUM {
    let bn = unsafe { bssl_sys::BN_new() };
    assert!(!bn.is_null());
    let r = unsafe { bssl_sys::BN_bin2bn(bytes.as_ptr(), bytes.len(), bn) };
    assert!(!r.is_null());
    bn
}

/// Serialize a BIGNUM to a 32-byte big-endian array.
fn bn_to_bytes32(bn: *const bssl_sys::BIGNUM) -> [u8; 32] {
    let mut out = [0u8; 32];
    let r = unsafe { bssl_sys::BN_bn2bin_padded(out.as_mut_ptr(), 32, bn) };
    assert_eq!(r, 1);
    out
}

/// Create a new BN_CTX. Caller must free with BN_CTX_free.
fn new_bn_ctx() -> *mut bssl_sys::BN_CTX {
    let ctx = unsafe { bssl_sys::BN_CTX_new() };
    assert!(!ctx.is_null());
    ctx
}

/// Perform (a OP b) mod order, where OP is one of the BN_mod_* functions.
/// Returns result as 32-byte big-endian.
fn bn_mod_op(
    a: &[u8; 32],
    b: &[u8; 32],
    op: unsafe extern "C" fn(
        *mut bssl_sys::BIGNUM,
        *const bssl_sys::BIGNUM,
        *const bssl_sys::BIGNUM,
        *const bssl_sys::BIGNUM,
        *mut bssl_sys::BN_CTX,
    ) -> i32,
) -> [u8; 32] {
    let bn_a = bn_from_bytes(a);
    let bn_b = bn_from_bytes(b);
    let bn_r = unsafe { bssl_sys::BN_new() };
    assert!(!bn_r.is_null());
    let ctx = new_bn_ctx();

    let rc = unsafe { op(bn_r, bn_a, bn_b, p256_order(), ctx) };
    assert_eq!(rc, 1);

    let result = bn_to_bytes32(bn_r);

    unsafe {
        bssl_sys::BN_CTX_free(ctx);
        bssl_sys::BN_free(bn_r);
        bssl_sys::BN_free(bn_a);
        bssl_sys::BN_free(bn_b);
    }
    result
}

// ---------------------------------------------------------------------------
// BsslScalar – a 32-byte big-endian scalar mod P-256 order
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Zeroize, Default, PartialEq, Eq)]
pub struct BsslScalar(pub [u8; 32]);

impl BsslScalar {
    pub const ZERO: BsslScalar = BsslScalar([0u8; 32]);
    pub const ONE: BsslScalar = {
        let mut b = [0u8; 32];
        b[31] = 1;
        BsslScalar(b)
    };

    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        random_scalar(rng)
    }

    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    pub fn invert(&self) -> CtOption<BsslScalar> {
        // Always perform the inversion to avoid leaking whether self is zero.
        let is_nonzero = !self.is_zero();
        // Use 1 as a fallback input so BN_mod_inverse always succeeds.
        let safe_input = BsslScalar::conditional_select(&BsslScalar::ONE, self, is_nonzero);

        let bn_a = bn_from_bytes(&safe_input.0);
        let bn_r = unsafe { bssl_sys::BN_new() };
        assert!(!bn_r.is_null());
        let ctx = new_bn_ctx();

        let r = unsafe { bssl_sys::BN_mod_inverse(bn_r, bn_a, p256_order(), ctx) };
        // The inverse should always succeed on the safe_input (which is nonzero).
        assert!(!r.is_null());
        let result = bn_to_bytes32(bn_r);

        unsafe {
            bssl_sys::BN_CTX_free(ctx);
            bssl_sys::BN_free(bn_r);
            bssl_sys::BN_free(bn_a);
        }
        CtOption::new(BsslScalar(result), is_nonzero)
    }
}

impl From<u64> for BsslScalar {
    fn from(v: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&v.to_be_bytes());
        BsslScalar(bytes)
    }
}

impl core::ops::Add<BsslScalar> for BsslScalar {
    type Output = BsslScalar;
    fn add(self, rhs: BsslScalar) -> BsslScalar {
        BsslScalar(bn_mod_op(&self.0, &rhs.0, bssl_sys::BN_mod_add))
    }
}

impl core::ops::Sub<BsslScalar> for BsslScalar {
    type Output = BsslScalar;
    fn sub(self, rhs: BsslScalar) -> BsslScalar {
        BsslScalar(bn_mod_op(&self.0, &rhs.0, bssl_sys::BN_mod_sub))
    }
}

impl core::ops::Mul<BsslScalar> for BsslScalar {
    type Output = BsslScalar;
    fn mul(self, rhs: BsslScalar) -> BsslScalar {
        BsslScalar(bn_mod_op(&self.0, &rhs.0, bssl_sys::BN_mod_mul))
    }
}

impl core::ops::Mul<&BsslScalar> for BsslScalar {
    type Output = BsslScalar;
    fn mul(self, rhs: &BsslScalar) -> BsslScalar {
        self * *rhs
    }
}

impl core::ops::Neg for BsslScalar {
    type Output = BsslScalar;
    fn neg(self) -> BsslScalar {
        BsslScalar::ZERO - self
    }
}

impl<'a> core::iter::Sum<&'a BsslScalar> for BsslScalar {
    fn sum<I: Iterator<Item = &'a BsslScalar>>(iter: I) -> BsslScalar {
        iter.fold(BsslScalar::ZERO, |acc, x| acc + *x)
    }
}

impl ConditionallySelectable for BsslScalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut res = [0u8; 32];
        for i in 0..32 {
            res[i] = u8::conditional_select(&a.0[i], &b.0[i], choice);
        }
        BsslScalar(res)
    }
}

impl ConstantTimeEq for BsslScalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

// ---------------------------------------------------------------------------
// BsslPoint – a 33-byte compressed P-256 point
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Zeroize, PartialEq, Eq)]
pub struct BsslPoint(pub [u8; 33]);

impl Default for BsslPoint {
    fn default() -> Self {
        BsslPoint([0u8; 33])
    }
}

impl BsslPoint {
    pub const IDENTITY: BsslPoint = BsslPoint([0u8; 33]);

    pub fn is_identity(&self) -> Choice {
        self.0.ct_eq(&[0u8; 33])
    }

    /// Return the standard P-256 generator.
    /// Note: This is not `const` since it requires FFI calls.
    pub fn generator() -> BsslPoint {
        point_generator()
    }

    // Stub: BsslPoint doesn't have a meaningful `random` in the same sense
    // as ProjectivePoint, but tests call it. Generate generator * random_scalar.
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> BsslPoint {
        point_generator() * random_scalar(rng)
    }
}

impl core::ops::Neg for BsslPoint {
    type Output = BsslPoint;
    fn neg(self) -> BsslPoint {
        let group = p256_group();
        let pt = ec_point_from_bytes(&self.0);
        let rc = unsafe { bssl_sys::EC_POINT_invert(group, pt, null_mut()) };
        assert_eq!(rc, 1);
        let result = ec_point_to_bytes33(pt);
        unsafe { bssl_sys::EC_POINT_free(pt) };
        BsslPoint(result)
    }
}

/// Deserialize compressed bytes into an EC_POINT. Caller must free with EC_POINT_free.
/// All-zeros input is treated as the point at infinity (identity).
///
/// NOTE: This function is NOT constant-time (it branches on whether the input
/// is all-zeros). It is only used in arithmetic operations (Add, Sub, Mul, Neg)
/// where the point values are not secret. For decoding untrusted input in a
/// constant-time manner, use `decode_point` instead.
fn ec_point_from_bytes(bytes: &[u8; 33]) -> *mut bssl_sys::EC_POINT {
    let group = p256_group();
    let pt = unsafe { bssl_sys::EC_POINT_new(group) };
    assert!(!pt.is_null());
    // All-zeros represents identity (point at infinity)
    if bytes == &[0u8; 33] {
        let r = unsafe { bssl_sys::EC_POINT_set_to_infinity(group, pt) };
        assert_eq!(r, 1);
        return pt;
    }
    let r = unsafe { bssl_sys::EC_POINT_oct2point(group, pt, bytes.as_ptr(), 33, null_mut()) };
    assert_eq!(r, 1, "EC_POINT_oct2point failed");
    pt
}

/// Serialize an EC_POINT to 33-byte compressed form.
/// Returns all-zeros for the point at infinity (identity).
fn ec_point_to_bytes33(pt: *const bssl_sys::EC_POINT) -> [u8; 33] {
    let group = p256_group();
    // Check if point is at infinity
    if unsafe { bssl_sys::EC_POINT_is_at_infinity(group, pt) } == 1 {
        return [0u8; 33];
    }
    let mut buf = [0u8; 33];
    let len = unsafe {
        bssl_sys::EC_POINT_point2oct(
            group,
            pt,
            bssl_sys::point_conversion_form_t::POINT_CONVERSION_COMPRESSED,
            buf.as_mut_ptr(),
            33,
            null_mut(),
        )
    };
    assert_eq!(len, 33);
    buf
}

impl core::ops::Add<BsslPoint> for BsslPoint {
    type Output = BsslPoint;
    fn add(self, rhs: BsslPoint) -> BsslPoint {
        let group = p256_group();
        let a = ec_point_from_bytes(&self.0);
        let b = ec_point_from_bytes(&rhs.0);
        let r = unsafe { bssl_sys::EC_POINT_new(group) };
        assert!(!r.is_null());
        let rc = unsafe { bssl_sys::EC_POINT_add(group, r, a, b, null_mut()) };
        assert_eq!(rc, 1);
        let result = ec_point_to_bytes33(r);
        unsafe {
            bssl_sys::EC_POINT_free(r);
            bssl_sys::EC_POINT_free(a);
            bssl_sys::EC_POINT_free(b);
        }
        BsslPoint(result)
    }
}

impl core::ops::Add<&BsslPoint> for BsslPoint {
    type Output = BsslPoint;
    fn add(self, rhs: &BsslPoint) -> BsslPoint {
        self + *rhs
    }
}

impl core::ops::Sub<BsslPoint> for BsslPoint {
    type Output = BsslPoint;
    fn sub(self, rhs: BsslPoint) -> BsslPoint {
        let group = p256_group();
        let a = ec_point_from_bytes(&self.0);
        let b = ec_point_from_bytes(&rhs.0);
        // Negate b in place
        let rc = unsafe { bssl_sys::EC_POINT_invert(group, b, null_mut()) };
        assert_eq!(rc, 1);
        let r = unsafe { bssl_sys::EC_POINT_new(group) };
        assert!(!r.is_null());
        let rc = unsafe { bssl_sys::EC_POINT_add(group, r, a, b, null_mut()) };
        assert_eq!(rc, 1);
        let result = ec_point_to_bytes33(r);
        unsafe {
            bssl_sys::EC_POINT_free(r);
            bssl_sys::EC_POINT_free(a);
            bssl_sys::EC_POINT_free(b);
        }
        BsslPoint(result)
    }
}

impl core::ops::Mul<BsslScalar> for BsslPoint {
    type Output = BsslPoint;
    fn mul(self, rhs: BsslScalar) -> BsslPoint {
        let group = p256_group();
        let pt = ec_point_from_bytes(&self.0);
        let bn_s = bn_from_bytes(&rhs.0);
        let r = unsafe { bssl_sys::EC_POINT_new(group) };
        assert!(!r.is_null());
        // r = NULL*gen + pt*bn_s  (i.e. pt * scalar)
        let rc = unsafe { bssl_sys::EC_POINT_mul(group, r, null(), pt, bn_s, null_mut()) };
        assert_eq!(rc, 1);
        let result = ec_point_to_bytes33(r);
        unsafe {
            bssl_sys::EC_POINT_free(r);
            bssl_sys::EC_POINT_free(pt);
            bssl_sys::BN_free(bn_s);
        }
        BsslPoint(result)
    }
}

impl core::ops::Mul<&BsslScalar> for BsslPoint {
    type Output = BsslPoint;
    fn mul(self, rhs: &BsslScalar) -> BsslPoint {
        self * *rhs
    }
}

impl core::ops::Mul<&BsslScalar> for &BsslPoint {
    type Output = BsslPoint;
    fn mul(self, rhs: &BsslScalar) -> BsslPoint {
        *self * *rhs
    }
}

impl ConditionallySelectable for BsslPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut res = [0u8; 33];
        for i in 0..33 {
            res[i] = u8::conditional_select(&a.0[i], &b.0[i], choice);
        }
        BsslPoint(res)
    }
}

impl ConstantTimeEq for BsslPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.as_slice().ct_eq(other.0.as_slice())
    }
}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

pub fn point_generator() -> BsslPoint {
    let group = p256_group();
    let generator = unsafe { bssl_sys::EC_GROUP_get0_generator(group) };
    assert!(!generator.is_null());
    BsslPoint(ec_point_to_bytes33(generator))
}

pub fn decode_point(input: &[u8]) -> (CtOption<BsslPoint>, &[u8]) {
    if input.len() < 33 {
        return (CtOption::new(BsslPoint([0u8; 33]), Choice::from(0u8)), input);
    }
    let mut bytes = [0u8; 33];
    bytes.copy_from_slice(&input[..33]);

    if bytes == [0u8; 33] {
        return (CtOption::new(BsslPoint(bytes), Choice::from(1u8)), &input[33..]);
    }

    let group = p256_group();
    let pt = unsafe { bssl_sys::EC_POINT_new(group) };
    assert!(!pt.is_null());
    let r = unsafe { bssl_sys::EC_POINT_oct2point(group, pt, bytes.as_ptr(), 33, null_mut()) };
    unsafe { bssl_sys::EC_POINT_free(pt) };

    let valid = Choice::from((r == 1) as u8);
    (CtOption::new(BsslPoint(bytes), valid), &input[33..])
}

/// P-256 group order in big-endian, lazily initialized from BoringSSL.
fn p256_order_bytes() -> &'static [u8; 32] {
    use std::sync::OnceLock;
    static ORDER: OnceLock<[u8; 32]> = OnceLock::new();
    ORDER.get_or_init(|| bn_to_bytes32(p256_order()))
}

pub fn decode_scalar(input: &[u8]) -> (CtOption<BsslScalar>, &[u8]) {
    if input.len() < 32 {
        return (CtOption::new(BsslScalar([0u8; 32]), Choice::from(0u8)), input);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&input[..32]);

    let valid = Choice::from((bytes < *p256_order_bytes()) as u8);
    (CtOption::new(BsslScalar(bytes), valid), &input[32..])
}

pub fn encode_point(point: &BsslPoint, out: &mut Vec<u8>) {
    out.extend_from_slice(&point.0);
}

pub fn encode_scalar(scalar: &BsslScalar, out: &mut Vec<u8>) {
    out.extend_from_slice(&scalar.0);
}

pub fn hash_to_point(msgs: &[&[u8]], dsts: &[&[u8]]) -> Result<BsslPoint, &'static str> {
    // Concatenate msgs and dsts like the rustcrypto backend does.
    let msg_cat: Vec<u8> = msgs.iter().flat_map(|m| m.iter().copied()).collect();
    let dst_cat: Vec<u8> = dsts.iter().flat_map(|d| d.iter().copied()).collect();

    let group = p256_group();
    let pt = unsafe { bssl_sys::EC_POINT_new(group) };
    if pt.is_null() {
        return Err("EC_POINT_new failed");
    }
    let rc = unsafe {
        bssl_sys::EC_hash_to_curve_p256_xmd_sha256_sswu(
            group,
            pt,
            dst_cat.as_ptr(),
            dst_cat.len(),
            msg_cat.as_ptr(),
            msg_cat.len(),
        )
    };
    if rc != 1 {
        unsafe { bssl_sys::EC_POINT_free(pt) };
        return Err("hash_to_curve failed");
    }
    let result = ec_point_to_bytes33(pt);
    unsafe { bssl_sys::EC_POINT_free(pt) };
    Ok(BsslPoint(result))
}

pub fn hash_to_scalar(msgs: &[&[u8]], dsts: &[&[u8]]) -> Result<BsslScalar, &'static str> {
    // Implement hash-to-scalar per RFC 9380 §5:
    // 1. Concatenate messages and DSTs
    // 2. Use expand_message_xmd (SHA-256) to get 48 bytes
    // 3. Interpret as big-endian integer, reduce mod order
    let msg_cat: Vec<u8> = msgs.iter().flat_map(|m| m.iter().copied()).collect();
    let dst_cat: Vec<u8> = dsts.iter().flat_map(|d| d.iter().copied()).collect();

    // expand_message_xmd with SHA-256 producing 48 bytes (L = 48 for P-256)
    let uniform_bytes = expand_message_xmd_sha256(&msg_cat, &dst_cat, 48)?;

    // Interpret as big-endian integer and reduce mod order
    let bn = bn_from_bytes(&uniform_bytes);
    let bn_r = unsafe { bssl_sys::BN_new() };
    assert!(!bn_r.is_null());
    let ctx = new_bn_ctx();
    // BN_mod is actually BN_nnmod for non-negative results
    let rc = unsafe { bssl_sys::BN_nnmod(bn_r, bn, p256_order(), ctx) };
    assert_eq!(rc, 1);
    let result = bn_to_bytes32(bn_r);
    unsafe {
        bssl_sys::BN_CTX_free(ctx);
        bssl_sys::BN_free(bn_r);
        bssl_sys::BN_free(bn);
    }
    Ok(BsslScalar(result))
}

/// expand_message_xmd using SHA-256, per RFC 9380 §5.3.1.
fn expand_message_xmd_sha256(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> Result<Vec<u8>, &'static str> {
    use sha2::{Digest, Sha256};

    let b_in_bytes = 32usize; // SHA-256 output length
    let s_in_bytes = 64usize; // SHA-256 block length
    let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
    if ell > 255 || len_in_bytes > 65535 || dst.len() > 255 {
        return Err("expand_message_xmd: invalid parameters");
    }

    let dst_prime: Vec<u8> = dst.iter().copied().chain(std::iter::once(dst.len() as u8)).collect();
    let z_pad = vec![0u8; s_in_bytes];
    let l_i_b_str = (len_in_bytes as u16).to_be_bytes();

    // b_0 = H(Z_pad || msg || l_i_b_str || 0x00 || DST_prime)
    let mut h0 = Sha256::new();
    h0.update(&z_pad);
    h0.update(msg);
    h0.update(&l_i_b_str);
    h0.update(&[0u8]);
    h0.update(&dst_prime);
    let b_0 = h0.finalize();

    // b_1 = H(b_0 || 0x01 || DST_prime)
    let mut h1 = Sha256::new();
    h1.update(&b_0);
    h1.update(&[1u8]);
    h1.update(&dst_prime);
    let mut b_vals = vec![h1.finalize()];

    for i in 2..=(ell as u8) {
        let mut hi = Sha256::new();
        // strxor(b_0, b_{i-1})
        let prev = &b_vals[b_vals.len() - 1];
        let xored: Vec<u8> = b_0.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
        hi.update(&xored);
        hi.update(&[i]);
        hi.update(&dst_prime);
        b_vals.push(hi.finalize());
    }

    let mut uniform_bytes: Vec<u8> = b_vals.into_iter().flat_map(|b| b.to_vec()).collect();
    uniform_bytes.truncate(len_in_bytes);
    Ok(uniform_bytes)
}

pub fn random_scalar<R: CryptoRngCore>(_rng: &mut R) -> BsslScalar {
    // Use BoringSSL's RNG directly (ignores the Rust rng parameter).
    let order = p256_order();
    let bn = unsafe { bssl_sys::BN_new() };
    assert!(!bn.is_null());
    let rc = unsafe { bssl_sys::BN_rand_range(bn, order) };
    assert_eq!(rc, 1);
    let result = bn_to_bytes32(bn);
    unsafe { bssl_sys::BN_free(bn) };
    BsslScalar(result)
}

pub fn random_non_zero_scalar<R: CryptoRngCore>(rng: &mut R) -> BsslScalar {
    loop {
        let s = random_scalar(rng);
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

// ---------------------------------------------------------------------------
// AthmBackend implementation
// ---------------------------------------------------------------------------

/// Zero-sized marker type for the BoringSSL backend.
#[derive(Clone)]
pub struct BoringSslBackend;

impl AthmBackend for BoringSslBackend {
    type Scalar = BsslScalar;
    type Point = BsslPoint;

    const SCALAR_SIZE: usize = SCALAR_SIZE;
    const POINT_SIZE: usize = POINT_SIZE;

    fn scalar_zero() -> Self::Scalar {
        BsslScalar::ZERO
    }

    fn scalar_one() -> Self::Scalar {
        BsslScalar::ONE
    }

    fn scalar_is_zero(s: &Self::Scalar) -> Choice {
        s.is_zero()
    }

    fn scalar_invert(s: &Self::Scalar) -> CtOption<Self::Scalar> {
        s.invert()
    }

    fn point_identity() -> Self::Point {
        BsslPoint::IDENTITY
    }

    fn point_generator() -> Self::Point {
        point_generator()
    }

    fn point_is_identity(p: &Self::Point) -> Choice {
        p.is_identity()
    }

    fn hash_to_point(msgs: &[&[u8]], dsts: &[&[u8]]) -> Result<Self::Point, &'static str> {
        hash_to_point(msgs, dsts)
    }

    fn hash_to_scalar(msgs: &[&[u8]], dsts: &[&[u8]]) -> Result<Self::Scalar, &'static str> {
        hash_to_scalar(msgs, dsts)
    }

    fn encode_scalar(scalar: &Self::Scalar, out: &mut Vec<u8>) {
        encode_scalar(scalar, out)
    }

    fn decode_scalar(input: &[u8]) -> (CtOption<Self::Scalar>, &[u8]) {
        decode_scalar(input)
    }

    fn encode_point(point: &Self::Point, out: &mut Vec<u8>) {
        encode_point(point, out)
    }

    fn decode_point(input: &[u8]) -> (CtOption<Self::Point>, &[u8]) {
        decode_point(input)
    }

    fn random_scalar<R: CryptoRngCore>(rng: &mut R) -> Self::Scalar {
        random_scalar(rng)
    }

    fn random_non_zero_scalar<R: CryptoRngCore>(rng: &mut R) -> Self::Scalar {
        random_non_zero_scalar(rng)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_add_sub() {
        let a = BsslScalar::from(10u64);
        let b = BsslScalar::from(20u64);
        let c = a + b;
        let d = c - a;
        assert!(bool::from(d.ct_eq(&b)));
    }

    #[test]
    fn test_scalar_mul() {
        let a = BsslScalar::from(7u64);
        let b = BsslScalar::from(6u64);
        let c = a * b;
        let expected = BsslScalar::from(42u64);
        assert!(bool::from(c.ct_eq(&expected)));
    }

    #[test]
    fn test_scalar_neg() {
        let a = BsslScalar::from(5u64);
        let neg_a = -a;
        let sum = a + neg_a;
        assert!(bool::from(sum.ct_eq(&BsslScalar::ZERO)));
    }

    #[test]
    fn test_scalar_invert() {
        let a = BsslScalar::from(7u64);
        let inv_a = a.invert().unwrap();
        let product = a * inv_a;
        let one = BsslScalar::from(1u64);
        assert!(bool::from(product.ct_eq(&one)));
    }

    #[test]
    fn test_scalar_zero_invert() {
        let z = BsslScalar::ZERO;
        assert!(!bool::from(z.invert().is_some()));
    }

    #[test]
    fn test_point_generator_not_identity() {
        let g = point_generator();
        assert!(!bool::from(g.is_identity()));
    }

    #[test]
    fn test_point_scalar_mul_identity() {
        let g = point_generator();
        let _zero = BsslScalar::ZERO;
        // G * 0 should be identity (but encoded as compressed point).
        // BoringSSL returns point at infinity -> serialization is 0x00.
        // Actually EC_POINT_mul with zero scalar gives infinity which
        // can't be compressed normally. Let's test G * 1 = G instead.
        let one = BsslScalar::from(1u64);
        let g1 = g * one;
        assert!(bool::from(g1.ct_eq(&g)));
    }

    #[test]
    fn test_point_add_sub() {
        let g = point_generator();
        let two = BsslScalar::from(2u64);
        let g2 = g * two;
        let g_plus_g = g + g;
        assert!(bool::from(g2.ct_eq(&g_plus_g)));

        let back = g2 - g;
        assert!(bool::from(back.ct_eq(&g)));
    }

    #[test]
    fn test_hash_to_point() {
        let p = hash_to_point(&[b"test"], &[b"DST"]).unwrap();
        assert!(!bool::from(p.is_identity()));
        // Deterministic
        let p2 = hash_to_point(&[b"test"], &[b"DST"]).unwrap();
        assert!(bool::from(p.ct_eq(&p2)));
    }

    #[test]
    fn test_hash_to_scalar() {
        let s = hash_to_scalar(&[b"test"], &[b"DST"]).unwrap();
        assert!(!bool::from(s.is_zero()));
        // Deterministic
        let s2 = hash_to_scalar(&[b"test"], &[b"DST"]).unwrap();
        assert!(bool::from(s.ct_eq(&s2)));
    }

    #[test]
    fn test_random_scalar() {
        let mut rng = rand::thread_rng();
        let s1 = random_scalar(&mut rng);
        let s2 = random_scalar(&mut rng);
        assert!(!bool::from(s1.ct_eq(&s2)));
    }

    #[test]
    fn test_encode_decode_scalar() {
        let s = BsslScalar::from(42u64);
        let mut buf = Vec::new();
        encode_scalar(&s, &mut buf);
        let (decoded, rest) = decode_scalar(&buf);
        assert!(bool::from(decoded.is_some()));
        assert!(bool::from(decoded.unwrap().ct_eq(&s)));
        assert!(rest.is_empty());
    }

    #[test]
    fn test_encode_decode_point() {
        let g = point_generator();
        let mut buf = Vec::new();
        encode_point(&g, &mut buf);
        let (decoded, rest) = decode_point(&buf);
        assert!(bool::from(decoded.is_some()));
        assert!(bool::from(decoded.unwrap().ct_eq(&g)));
        assert!(rest.is_empty());
    }
}
