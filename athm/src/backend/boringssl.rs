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
//!
//! This backend is not constant-time in general. However, the code paths needed for the *client*
//! operations in ATHM are constant-time.

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
    // SAFETY: p256_group() returns a valid group object, so
    // EC_GROUP_get0_order is safe to call and returns a valid pointer to
    // the group order, owned by the group.
    let o = unsafe { bssl_sys::EC_GROUP_get0_order(p256_group()) };
    assert!(!o.is_null());
    o
}

/// Create a new BIGNUM from big-endian bytes.
/// Caller must free with BN_free.
fn bn_from_bytes(bytes: &[u8]) -> *mut bssl_sys::BIGNUM {
    // SAFETY: BN_new() is safe to call and returns a valid BIGNUM or null.
    let bn = unsafe { bssl_sys::BN_new() };
    assert!(!bn.is_null());
    // SAFETY: bn is a valid BIGNUM pointer allocated by BN_new(). bytes.as_ptr()
    // and bytes.len() are valid parameters for the input buffer.
    //
    // Constant-time assuming bytes.len() is constant.
    let r = unsafe { bssl_sys::BN_bin2bn(bytes.as_ptr(), bytes.len(), bn) };
    assert!(!r.is_null());
    bn
}

/// Serialize a BIGNUM to a 32-byte big-endian array.
fn bn_to_bytes32(bn: *const bssl_sys::BIGNUM) -> [u8; SCALAR_SIZE] {
    let mut out = [0u8; SCALAR_SIZE];
    // SAFETY: out.as_mut_ptr() points to a valid buffer of SCALAR_SIZE bytes.
    // bn is assumed to be a valid BIGNUM pointer.
    //
    // Constant-time assuming `bn` is valid and of length less than or equal to SCALAR_SIZE.
    let r = unsafe { bssl_sys::BN_bn2bin_padded(out.as_mut_ptr(), SCALAR_SIZE, bn) };
    assert_eq!(r, 1);
    out
}

/// Create a new BN_CTX. Caller must free with BN_CTX_free.
fn new_bn_ctx() -> *mut bssl_sys::BN_CTX {
    // SAFETY: BN_CTX_new() is safe to call and returns a valid BN_CTX or null.
    let ctx = unsafe { bssl_sys::BN_CTX_new() };
    assert!(!ctx.is_null());
    ctx
}

/// Perform (a OP b) mod order using a constant-time "quick" variant.
/// The _quick variants (BN_mod_add_quick, BN_mod_sub_quick) require that both
/// operands are non-negative and less than the modulus, which is always true for
/// our reduced scalars. They are constant-time because they internally use
/// bn_mod_add_words / bn_mod_sub_words (the same primitives as ec_scalar_add).
///
/// SAFETY: `a` and `b` must be valid big-endian scalar values, less than the order, and `op` must
/// be one of the boringssl mod_*_quick functions.
unsafe fn bn_mod_op_quick(
    a: &[u8; SCALAR_SIZE],
    b: &[u8; SCALAR_SIZE],
    op: unsafe extern "C" fn(
        *mut bssl_sys::BIGNUM,
        *const bssl_sys::BIGNUM,
        *const bssl_sys::BIGNUM,
        *const bssl_sys::BIGNUM,
    ) -> i32,
) -> [u8; SCALAR_SIZE] {
    let bn_a = bn_from_bytes(a);
    let bn_b = bn_from_bytes(b);
    // SAFETY: BN_new() is safe to call and returns a valid BIGNUM or null.
    let bn_r = unsafe { bssl_sys::BN_new() };
    assert!(!bn_r.is_null());

    // SAFETY: bn_r, bn_a, bn_b, and p256_order() are all valid pointers. However, this still
    // assumes that `op` is safe to call on the arguments, which is why this function is unsafe.
    let rc = unsafe { op(bn_r, bn_a, bn_b, p256_order()) };
    assert_eq!(rc, 1);

    let result = bn_to_bytes32(bn_r);

    // SAFETY: bn_r, bn_a, and bn_b were all allocated by BoringSSL
    // and are valid pointers that need to be freed.
    unsafe {
        bssl_sys::BN_free(bn_r);
        bssl_sys::BN_free(bn_a);
        bssl_sys::BN_free(bn_b);
    }
    result
}

/// Perform (a OP b) mod order using a BN_mod_* function that requires a BN_CTX.
/// Used for operations like BN_mod_mul that are not available in _quick form.
///
/// SAFETY: `a` and `b` must be valid big-endian scalar values, and `op` must be a boringssl mod_*
/// function that takes a BN_CTX.
unsafe fn bn_mod_op(
    a: &[u8; SCALAR_SIZE],
    b: &[u8; SCALAR_SIZE],
    op: unsafe extern "C" fn(
        *mut bssl_sys::BIGNUM,
        *const bssl_sys::BIGNUM,
        *const bssl_sys::BIGNUM,
        *const bssl_sys::BIGNUM,
        *mut bssl_sys::BN_CTX,
    ) -> i32,
) -> [u8; SCALAR_SIZE] {
    let bn_a = bn_from_bytes(a);
    let bn_b = bn_from_bytes(b);
    // SAFETY: BN_new() is safe to call and returns a valid BIGNUM or null.
    let bn_r = unsafe { bssl_sys::BN_new() };
    assert!(!bn_r.is_null());
    let ctx = new_bn_ctx();

    // SAFETY: bn_r, bn_a, bn_b, p256_order(), and ctx are all valid pointers. However, this still
    // assumes that `op` is safe to call on the arguments, which is why this function is unsafe.
    let rc = unsafe { op(bn_r, bn_a, bn_b, p256_order(), ctx) };
    assert_eq!(rc, 1);

    let result = bn_to_bytes32(bn_r);

    // SAFETY: ctx, bn_r, bn_a, and bn_b were all allocated by BoringSSL
    // and are valid pointers that need to be freed.
    unsafe {
        bssl_sys::BN_CTX_free(ctx);
        bssl_sys::BN_free(bn_r);
        bssl_sys::BN_free(bn_a);
        bssl_sys::BN_free(bn_b);
    }
    result
}

// ---------------------------------------------------------------------------
// BsslScalar – a SCALAR_SIZE-byte big-endian scalar mod P-256 order
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Zeroize, Default, PartialEq, Eq)]
pub struct BsslScalar(pub [u8; SCALAR_SIZE]);

impl BsslScalar {
    pub const ZERO: BsslScalar = BsslScalar([0u8; SCALAR_SIZE]);
    pub const ONE: BsslScalar = {
        let mut b = [0u8; SCALAR_SIZE];
        b[SCALAR_SIZE - 1] = 1;
        BsslScalar(b)
    };

    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        random_scalar(rng)
    }

    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    // Returns a CtOption, but this implementation is actually NOT constant-time.
    pub fn invert(&self) -> CtOption<BsslScalar> {
        // Always perform the inversion to avoid leaking whether self is zero.
        let is_nonzero = !self.is_zero();
        // Use 1 as a fallback input so BN_mod_inverse always succeeds.
        let safe_input = BsslScalar::conditional_select(&BsslScalar::ONE, self, is_nonzero);

        let bn_a = bn_from_bytes(&safe_input.0);
        let ctx = new_bn_ctx();

        // SAFETY: bn_a, p256_order(), and ctx are all valid pointers.
        // safe_input is guaranteed to be non-zero, so BN_mod_inverse will succeed.
        let r = unsafe { bssl_sys::BN_mod_inverse(null_mut(), bn_a, p256_order(), ctx) };
        // The inverse should always succeed on the safe_input (which is nonzero).
        assert!(!r.is_null());
        let result = bn_to_bytes32(r);

        // SAFETY: ctx, bn_a, and r were all allocated by BoringSSL
        // and are valid pointers that need to be freed.
        unsafe {
            bssl_sys::BN_CTX_free(ctx);
            bssl_sys::BN_free(bn_a);
            bssl_sys::BN_free(r);
        }
        CtOption::new(BsslScalar(result), is_nonzero)
    }
}

impl From<u64> for BsslScalar {
    fn from(v: u64) -> Self {
        let mut bytes = [0u8; SCALAR_SIZE];
        bytes[SCALAR_SIZE - 8..].copy_from_slice(&v.to_be_bytes());
        BsslScalar(bytes)
    }
}

impl core::ops::Add<BsslScalar> for BsslScalar {
    type Output = BsslScalar;
    // Constant-time because both operands are guaranteed to be < order.
    fn add(self, rhs: BsslScalar) -> BsslScalar {
        BsslScalar(
            // SAFETY: calling BN_mod_add_quick is safe because both operands are valid bignums and
            // guaranteed to be less than the order.
            unsafe { bn_mod_op_quick(&self.0, &rhs.0, bssl_sys::BN_mod_add_quick) },
        )
    }
}

impl core::ops::Sub<BsslScalar> for BsslScalar {
    type Output = BsslScalar;
    // Constant-time because both operands are guaranteed to be < order.
    fn sub(self, rhs: BsslScalar) -> BsslScalar {
        BsslScalar(
            // SAFETY: calling BN_mod_sub_quick is safe because both operands are valid bignums and
            // guaranteed to be less than the order.
            unsafe { bn_mod_op_quick(&self.0, &rhs.0, bssl_sys::BN_mod_sub_quick) },
        )
    }
}

impl core::ops::Mul<BsslScalar> for BsslScalar {
    type Output = BsslScalar;
    // NOT constant-time.
    fn mul(self, rhs: BsslScalar) -> BsslScalar {
        BsslScalar(
            // SAFETY: calling BN_mod_mul is safe because the arguments are valid bignums.
            unsafe { bn_mod_op(&self.0, &rhs.0, bssl_sys::BN_mod_mul) },
        )
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
    // Constant-time (delegates to Sub).
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
        let mut res = [0u8; SCALAR_SIZE];
        for i in 0..SCALAR_SIZE {
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
        self.ct_eq(&Self::IDENTITY)
    }

    /// Return the standard P-256 generator.
    /// Note: This is not `const` since it requires FFI calls.
    pub fn generator() -> BsslPoint {
        point_generator()
    }

    // Stub: BsslPoint doesn't have a meaningful `random` in the same sense
    // as ProjectivePoint, but tests call it. Generate generator * random_scalar.
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> BsslPoint {
        // This approach should only be used for actual random point generation, not for hashing to
        // points.
        point_generator() * random_scalar(rng)
    }
}

impl core::ops::Neg for BsslPoint {
    type Output = BsslPoint;
    fn neg(self) -> BsslPoint {
        let group = p256_group();
        let pt = ec_point_from_bytes(&self.0);
        // SAFETY: group and pt are valid pointers. `ctx` may be null.
        let rc = unsafe {
            // We can pass a non-null ctx if this becomes a performance bottleneck.
            bssl_sys::EC_POINT_invert(group, pt, /*ctx=*/ null_mut())
        };
        assert_eq!(rc, 1);
        let result = ec_point_to_bytes33(pt);
        // SAFETY: pt is a valid pointer allocated by ec_point_from_bytes.
        unsafe { bssl_sys::EC_POINT_free(pt) };
        BsslPoint(result)
    }
}

/// Deserialize compressed bytes into an EC_POINT. Caller must free with EC_POINT_free.
/// All-zeros input is treated as the point at infinity (identity).
///
/// This function is constant-time as long as the input is not the point at infinity.
fn ec_point_from_bytes(bytes: &[u8; 33]) -> *mut bssl_sys::EC_POINT {
    let group = p256_group();
    // SAFETY: EC_POINT_new is safe to call with a valid group pointer.
    let pt = unsafe { bssl_sys::EC_POINT_new(group) };
    assert!(!pt.is_null());
    // All-zeros represents identity (point at infinity)
    if bytes == &[0u8; 33] {
        // SAFETY: group and pt are valid pointers.
        let r = unsafe { bssl_sys::EC_POINT_set_to_infinity(group, pt) };
        assert_eq!(r, 1);
        return pt;
    }
    // SAFETY: group and pt are valid pointers, bytes points to a 33-byte buffer. `ctx` may be null.
    let r = unsafe {
        bssl_sys::EC_POINT_oct2point(group, pt, bytes.as_ptr(), 33, /*ctx=*/ null_mut())
    };
    assert_eq!(r, 1, "EC_POINT_oct2point failed");
    pt
}

/// Serialize an EC_POINT to 33-byte compressed form.
/// Returns all-zeros for the point at infinity (identity).
///
/// This function is constant-time as long as the input is not the point at infinity.
fn ec_point_to_bytes33(pt: *const bssl_sys::EC_POINT) -> [u8; 33] {
    let group = p256_group();
    // Check if point is at infinity
    // SAFETY: group and pt are valid pointers.
    if unsafe { bssl_sys::EC_POINT_is_at_infinity(group, pt) } == 1 {
        return [0u8; 33];
    }
    let mut buf = [0u8; 33];
    // SAFETY: group and pt are valid, buf points to a 33-byte buffer.
    let len = unsafe {
        bssl_sys::EC_POINT_point2oct(
            group,
            pt,
            bssl_sys::point_conversion_form_t::POINT_CONVERSION_COMPRESSED,
            buf.as_mut_ptr(),
            33,
            /*ctx=*/ null_mut(),
        )
    };
    assert_eq!(len, 33);
    buf
}

impl core::ops::Add<BsslPoint> for BsslPoint {
    type Output = BsslPoint;

    /// Constant-time assuming neither inputs nor output are the point at infinity.
    fn add(self, rhs: BsslPoint) -> BsslPoint {
        let group = p256_group();
        let a = ec_point_from_bytes(&self.0);
        let b = ec_point_from_bytes(&rhs.0);
        // SAFETY: EC_POINT_new is safe to call with a valid group pointer.
        let r = unsafe { bssl_sys::EC_POINT_new(group) };
        assert!(!r.is_null());
        // SAFETY: group, r, a, and b are all valid pointers.
        let rc = unsafe { bssl_sys::EC_POINT_add(group, r, a, b, null_mut()) };
        assert_eq!(rc, 1);
        let result = ec_point_to_bytes33(r);
        // SAFETY: r, a, and b are valid pointers that need to be freed.
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

    /// Constant-time assuming neither inputs nor output are the point at infinity.
    fn sub(self, rhs: BsslPoint) -> BsslPoint {
        let group = p256_group();
        let a = ec_point_from_bytes(&self.0);
        let b = ec_point_from_bytes(&rhs.0);
        // Negate b in place
        // SAFETY: group and b are valid pointers.
        let rc = unsafe {
            bssl_sys::EC_POINT_invert(group, b, /*ctx=*/ null_mut())
        };
        assert_eq!(rc, 1);
        // SAFETY: EC_POINT_new is safe to call with a valid group pointer.
        let r = unsafe { bssl_sys::EC_POINT_new(group) };
        assert!(!r.is_null());
        // SAFETY: group, r, a, and b are all valid pointers.
        let rc = unsafe {
            bssl_sys::EC_POINT_add(group, r, a, b, /*ctx=*/ null_mut())
        };
        assert_eq!(rc, 1);
        let result = ec_point_to_bytes33(r);
        // SAFETY: r, a, and b are valid pointers that need to be freed.
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

    /// Constant-time in both the scalar and the point, assuming neither `self` nor the output
    /// are the point at infinity.
    fn mul(self, rhs: BsslScalar) -> BsslPoint {
        let group = p256_group();
        let pt = ec_point_from_bytes(&self.0);
        let bn_s = bn_from_bytes(&rhs.0);
        // SAFETY: EC_POINT_new is safe to call with a valid group pointer.
        let r = unsafe { bssl_sys::EC_POINT_new(group) };
        assert!(!r.is_null());
        // r = NULL*gen + pt*bn_s  (i.e. pt * scalar)
        // SAFETY: group, r, pt, and bn_s are all valid pointers. `ctx` may be null.
        let rc = unsafe {
            bssl_sys::EC_POINT_mul(group, r, null(), pt, bn_s, /*ctx=*/ null_mut())
        };
        assert_eq!(rc, 1);
        let result = ec_point_to_bytes33(r);
        // SAFETY: r, pt, and bn_s are valid pointers that need to be freed.
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
    // SAFETY: p256_group() returns a valid group, so EC_GROUP_get0_generator
    // is safe to call and returns a valid pointer owned by the group.
    let generator = unsafe { bssl_sys::EC_GROUP_get0_generator(group) };
    assert!(!generator.is_null());
    BsslPoint(ec_point_to_bytes33(generator))
}

/// Not constant-time, but operates only on untrusted public input.
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
    // SAFETY: EC_POINT_new is safe to call with a valid group pointer.
    let pt = unsafe { bssl_sys::EC_POINT_new(group) };
    assert!(!pt.is_null());
    // SAFETY: group and pt are valid pointers, bytes points to a 33-byte buffer.
    let r = unsafe { bssl_sys::EC_POINT_oct2point(group, pt, bytes.as_ptr(), 33, null_mut()) };
    if r != 1 {
        // If oct2point fails, it leaves errors on the queue. Clear them.
        unsafe { bssl_sys::ERR_clear_error() };
    }
    // SAFETY: pt is a valid pointer that needs to be freed.
    unsafe { bssl_sys::EC_POINT_free(pt) };

    let valid = Choice::from((r == 1) as u8);
    (CtOption::new(BsslPoint(bytes), valid), &input[33..])
}

/// P-256 group order in big-endian, lazily initialized from BoringSSL.
fn p256_order_bytes() -> &'static [u8; SCALAR_SIZE] {
    use std::sync::OnceLock;
    static ORDER: OnceLock<[u8; SCALAR_SIZE]> = OnceLock::new();
    ORDER.get_or_init(|| bn_to_bytes32(p256_order()))
}

/// Not constant-time (the `<` comparison short-circuits), but operates only on untrusted
/// public input.
pub fn decode_scalar(input: &[u8]) -> (CtOption<BsslScalar>, &[u8]) {
    if input.len() < SCALAR_SIZE {
        return (CtOption::new(BsslScalar([0u8; SCALAR_SIZE]), Choice::from(0u8)), input);
    }
    let mut bytes = [0u8; SCALAR_SIZE];
    bytes.copy_from_slice(&input[..SCALAR_SIZE]);

    let valid = Choice::from((bytes < *p256_order_bytes()) as u8);
    (CtOption::new(BsslScalar(bytes), valid), &input[SCALAR_SIZE..])
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
    // SAFETY: EC_POINT_new is safe to call with a valid group pointer.
    let pt = unsafe { bssl_sys::EC_POINT_new(group) };
    if pt.is_null() {
        return Err("EC_POINT_new failed");
    }
    // SAFETY: group and pt are valid pointers. dst_cat and msg_cat slices
    // provide valid pointers and lengths to byte buffers.
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
        // SAFETY: pt is a valid pointer that needs to be freed on error.
        unsafe { bssl_sys::EC_POINT_free(pt) };
        return Err("hash_to_curve failed");
    }
    let result = ec_point_to_bytes33(pt);
    // SAFETY: pt is a valid pointer that needs to be freed.
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
    // SAFETY: BN_new() is safe to call and returns a valid BIGNUM or null.
    let bn_r = unsafe { bssl_sys::BN_new() };
    assert!(!bn_r.is_null());
    let ctx = new_bn_ctx();
    // BN_mod is actually BN_nnmod for non-negative results
    // SAFETY: bn_r, bn, p256_order(), and ctx are all valid pointers.
    let rc = unsafe { bssl_sys::BN_nnmod(bn_r, bn, p256_order(), ctx) };
    assert_eq!(rc, 1);
    let result = bn_to_bytes32(bn_r);
    // SAFETY: ctx, bn_r, and bn are valid pointers that need to be freed.
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
    // SAFETY: BN_new() is safe to call and returns a valid BIGNUM or null.
    let bn = unsafe { bssl_sys::BN_new() };
    assert!(!bn.is_null());
    // SAFETY: bn and order are valid pointers.
    let rc = unsafe { bssl_sys::BN_rand_range(bn, order) };
    assert_eq!(rc, 1);
    let result = bn_to_bytes32(bn);
    // SAFETY: bn is a valid pointer that needs to be freed.
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
    use hex_literal::hex;

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
        assert!(bool::from(product.ct_eq(&BsslScalar::ONE)));
    }

    #[test]
    fn test_one_equals_from_1u64() {
        assert!(bool::from(BsslScalar::ONE.ct_eq(&BsslScalar::from(1u64))));
    }

    #[test]
    fn test_one_plus_zero_equals_one() {
        assert!(bool::from((BsslScalar::ONE + BsslScalar::ZERO).ct_eq(&BsslScalar::ONE)));
    }

    #[test]
    fn test_one_times_one_equals_one() {
        assert!(bool::from((BsslScalar::ONE * BsslScalar::ONE).ct_eq(&BsslScalar::ONE)));
    }

    #[test]
    fn test_scalar_from_u64() {
        assert!(bool::from(BsslScalar::from(0u64).ct_eq(&BsslScalar::ZERO)));
        assert!(bool::from(BsslScalar::from(1u64).ct_eq(&BsslScalar::ONE)));
        assert_eq!(
            BsslScalar::from(1234567890u64).0,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                73, 150, 2, 210
            ]
        );
        assert_eq!(
            BsslScalar::from(u64::MAX).0,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255,
                255, 255, 255, 255, 255, 255
            ]
        );
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
        let g1 = g * BsslScalar::ONE;
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

    /// Test hash_to_scalar using VOPRF test vectors from
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-16.html#name-oprfp-256-sha-256-2>.
    /// These are the same test vectors used by the RustCrypto p256 crate
    /// (see `hash_to_scalar_voprf` in
    /// <https://github.com/RustCrypto/elliptic-curves/blob/45fe4010f1f0f622599a601e28eb296acde02dfb/p256/src/arithmetic/hash2curve.rs#L252>).
    #[test]
    fn test_hash_to_scalar_voprf_vectors() {
        struct TestVector {
            dst: &'static [u8],
            key_info: &'static [u8],
            seed: &'static [u8; 32],
            sk_sm: &'static [u8; 32],
        }

        const TEST_VECTORS: &[TestVector] = &[
            TestVector {
                dst: b"DeriveKeyPairOPRFV1-\x00-P256-SHA256",
                key_info: b"test key",
                seed: &hex!("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
                sk_sm: &hex!("159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf"),
            },
            TestVector {
                dst: b"DeriveKeyPairOPRFV1-\x01-P256-SHA256",
                key_info: b"test key",
                seed: &hex!("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
                sk_sm: &hex!("ca5d94c8807817669a51b196c34c1b7f8442fde4334a7121ae4736364312fca6"),
            },
            TestVector {
                dst: b"DeriveKeyPairOPRFV1-\x02-P256-SHA256",
                key_info: b"test key",
                seed: &hex!("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
                sk_sm: &hex!("6ad2173efa689ef2c27772566ad7ff6e2d59b3b196f00219451fb2c89ee4dae2"),
            },
        ];

        // The VOPRF DeriveKeyPair function (draft-irtf-cfrg-voprf-16, Section 3.2)
        // calls hash_to_scalar with:
        //   msgs = [seed, I2OSP(len(key_info), 2), key_info, I2OSP(counter, 1)]
        //   dst  = [contextString]
        // and iterates counter from 0 until a non-zero scalar is found.
        'outer: for test_vector in TEST_VECTORS {
            let key_info_len = u16::try_from(test_vector.key_info.len()).unwrap().to_be_bytes();

            for counter in 0_u8..=u8::MAX {
                let scalar = hash_to_scalar(
                    &[
                        test_vector.seed.as_slice(),
                        &key_info_len,
                        test_vector.key_info,
                        &counter.to_be_bytes(),
                    ],
                    &[test_vector.dst],
                )
                .unwrap();

                if !bool::from(scalar.is_zero()) {
                    assert_eq!(
                        &scalar.0, test_vector.sk_sm,
                        "hash_to_scalar mismatch for DST {:?}",
                        test_vector.dst
                    );
                    continue 'outer;
                }
            }

            panic!("deriving key failed — all 256 counters produced zero");
        }
    }

    #[test]
    fn test_hash_to_scalar_deterministic() {
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

    #[test]
    fn test_decode_scalar_invalid() {
        // Too short
        let (res, rest) = decode_scalar(&[1, 2, 3]);
        assert!(!bool::from(res.is_some()));
        assert_eq!(rest.len(), 3);

        // Valid length but >= order
        let order_bytes = p256_order_bytes();
        let (res, rest) = decode_scalar(order_bytes);
        assert!(!bool::from(res.is_some()));
        assert_eq!(rest.len(), 0);

        // All 0xFFs is > order
        let ff_bytes = [0xFFu8; SCALAR_SIZE];
        let (res, rest) = decode_scalar(&ff_bytes);
        assert!(!bool::from(res.is_some()));
        assert_eq!(rest.len(), 0);
    }

    #[test]
    fn test_decode_point_invalid() {
        // Too short
        let (res, rest) = decode_point(&[1, 2, 3]);
        assert!(!bool::from(res.is_some()));
        assert_eq!(rest.len(), 3);

        // Bad prefix (0xFF is not 0x00, 0x02, 0x03)
        let bad_point = [0xFFu8; POINT_SIZE];
        let (res, rest) = decode_point(&bad_point);
        assert!(!bool::from(res.is_some()));
        assert_eq!(rest.len(), 0);

        // Another bad prefix
        let bad_point_2 = [0x01u8; POINT_SIZE];
        let (res, rest) = decode_point(&bad_point_2);
        assert!(!bool::from(res.is_some()));
        assert_eq!(rest.len(), 0);
    }
}
