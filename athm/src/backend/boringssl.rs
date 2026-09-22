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
//! Scalar arithmetic (add, sub, mul, neg, invert) is constant-time. `BsslPoint` holds an owned
//! BoringSSL `EC_POINT` in Jacobian coordinates so that point compression and decompression
//! only occur at wire serialization boundaries.

use super::AthmBackend;
use core::ptr::{null, null_mut, NonNull};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

pub const SCALAR_SIZE: usize = 32;
pub const POINT_SIZE: usize = 33; // Compressed P-256 point

// ---------------------------------------------------------------------------
// RAII wrappers for BoringSSL types
// ---------------------------------------------------------------------------

/// Owns a `BIGNUM` through `NonNull` and frees it on drop via `BN_free`.
struct BnWrapper(NonNull<bssl_sys::BIGNUM>);

impl BnWrapper {
    /// Allocate a new zero-valued BIGNUM. Panics if allocation fails.
    fn new() -> Self {
        // SAFETY: BN_new() is safe to call and returns a valid BIGNUM or null.
        let ptr = unsafe { bssl_sys::BN_new() };
        Self(NonNull::new(ptr).expect("BN_new returned null"))
    }

    /// Create a BIGNUM from big-endian bytes.
    fn from_bytes(bytes: &[u8]) -> Self {
        let bn = Self::new();
        // SAFETY: bn is a valid BIGNUM pointer. bytes.as_ptr() and bytes.len()
        // are valid parameters for the input buffer.
        //
        // Constant-time assuming bytes.len() is constant.
        let r = unsafe { bssl_sys::BN_bin2bn(bytes.as_ptr(), bytes.len(), bn.as_mut_ptr()) };
        assert!(!r.is_null());
        bn
    }

    /// Serialize this BIGNUM to a 32-byte big-endian array.
    fn to_bytes32(&self) -> [u8; SCALAR_SIZE] {
        Self::raw_to_bytes32(self.as_ptr())
    }

    /// Serialize a BIGNUM pointer to a 32-byte big-endian array.
    /// This is useful for borrowed pointers (e.g. from EC_GROUP_get0_order)
    /// that are not owned by a BnWrapper.
    ///
    /// Constant-time assuming `bn` is valid and of length less than or equal to SCALAR_SIZE.
    fn raw_to_bytes32(bn: *const bssl_sys::BIGNUM) -> [u8; SCALAR_SIZE] {
        let mut out = [0u8; SCALAR_SIZE];
        // SAFETY: out.as_mut_ptr() points to a valid buffer of SCALAR_SIZE bytes.
        // bn is assumed to be a valid BIGNUM pointer.
        let r = unsafe { bssl_sys::BN_bn2bin_padded(out.as_mut_ptr(), SCALAR_SIZE, bn) };
        assert_eq!(r, 1);
        out
    }

    fn as_ptr(&self) -> *const bssl_sys::BIGNUM {
        self.0.as_ptr()
    }

    fn as_mut_ptr(&self) -> *mut bssl_sys::BIGNUM {
        self.0.as_ptr()
    }
}

impl Drop for BnWrapper {
    fn drop(&mut self) {
        // SAFETY: self.0 was allocated by BN_new/BN_bin2bn and is a valid non-null pointer.
        unsafe { bssl_sys::BN_free(self.0.as_ptr()) };
    }
}

/// Owns a `BN_CTX` through `NonNull` and frees it on drop via `BN_CTX_free`.
struct BnCtxWrapper(NonNull<bssl_sys::BN_CTX>);

impl BnCtxWrapper {
    /// Allocate a new BN_CTX. Panics if allocation fails.
    fn new() -> Self {
        // SAFETY: BN_CTX_new() is safe to call and returns a valid BN_CTX or null.
        let ptr = unsafe { bssl_sys::BN_CTX_new() };
        Self(NonNull::new(ptr).expect("BN_CTX_new returned null"))
    }

    fn as_mut_ptr(&self) -> *mut bssl_sys::BN_CTX {
        self.0.as_ptr()
    }
}

impl Drop for BnCtxWrapper {
    fn drop(&mut self) {
        // SAFETY: self.0 was allocated by BN_CTX_new and is a valid non-null pointer.
        unsafe { bssl_sys::BN_CTX_free(self.0.as_ptr()) };
    }
}

/// Owns a `BN_MONT_CTX` through `NonNull` and frees it on drop via `BN_MONT_CTX_free`.
struct BnMontCtxWrapper(NonNull<bssl_sys::BN_MONT_CTX>);

impl BnMontCtxWrapper {
    /// Create a Montgomery context for the given modulus.
    /// Panics if the context cannot be created.
    fn new_for_modulus(modulus: *const bssl_sys::BIGNUM) -> Self {
        // SAFETY: modulus is a valid BIGNUM pointer. Passing null for ctx makes BoringSSL
        // allocate one internally.
        let ptr = unsafe { bssl_sys::BN_MONT_CTX_new_for_modulus(modulus, null_mut()) };
        Self(NonNull::new(ptr).expect("BN_MONT_CTX_new_for_modulus returned null"))
    }

    fn as_ptr(&self) -> *const bssl_sys::BN_MONT_CTX {
        self.0.as_ptr()
    }
}

// SAFETY: BN_MONT_CTX is a precomputed read-only structure after creation and is safe to share
// across threads.
unsafe impl Send for BnMontCtxWrapper {}
unsafe impl Sync for BnMontCtxWrapper {}

impl Drop for BnMontCtxWrapper {
    fn drop(&mut self) {
        // SAFETY: self.0 was allocated by BN_MONT_CTX_new_for_modulus and is a valid non-null
        // pointer.
        unsafe { bssl_sys::BN_MONT_CTX_free(self.0.as_ptr()) };
    }
}

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

/// Returns a reference to a lazily-initialized Montgomery context for the P-256 order.
/// The context is created once and cached for the lifetime of the process.
fn p256_order_mont_ctx() -> &'static BnMontCtxWrapper {
    use std::sync::OnceLock;
    static MONT: OnceLock<BnMontCtxWrapper> = OnceLock::new();
    MONT.get_or_init(|| BnMontCtxWrapper::new_for_modulus(p256_order()))
}

/// The P-256 order minus 2, used for Fermat inversion: a^{-1} = a^{order-2} (mod order).
/// Lazily computed and cached.
fn p256_order_minus_2() -> &'static [u8; SCALAR_SIZE] {
    use std::sync::OnceLock;
    static ORDER_M2: OnceLock<[u8; SCALAR_SIZE]> = OnceLock::new();
    ORDER_M2.get_or_init(|| {
        let result = BnWrapper::new();
        // SAFETY: result.as_mut_ptr() and p256_order() are valid BIGNUM pointers.
        let rc = unsafe { bssl_sys::BN_copy(result.as_mut_ptr(), p256_order()) };
        assert!(!rc.is_null());
        // SAFETY: result.as_mut_ptr() is a valid BIGNUM pointer.
        let rc = unsafe { bssl_sys::BN_sub_word(result.as_mut_ptr(), 2) };
        assert_eq!(rc, 1);
        result.to_bytes32()
    })
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
    let bn_a = BnWrapper::from_bytes(a);
    let bn_b = BnWrapper::from_bytes(b);
    let bn_r = BnWrapper::new();

    // SAFETY: bn_r, bn_a, bn_b, and p256_order() are all valid pointers. However, this still
    // assumes that `op` is safe to call on the arguments, which is why this function is unsafe.
    let rc = unsafe { op(bn_r.as_mut_ptr(), bn_a.as_ptr(), bn_b.as_ptr(), p256_order()) };
    assert_eq!(rc, 1);

    bn_r.to_bytes32()
    // bn_a, bn_b, bn_r freed automatically on drop.
}

/// Constant-time multiplication of two scalars mod the P-256 order, using Montgomery
/// multiplication.
///
/// The operands are converted to Montgomery form, multiplied, and the result is converted back.
/// All operations are constant-time for secret scalar values.
fn bn_mod_mul_mont(a: &[u8; SCALAR_SIZE], b: &[u8; SCALAR_SIZE]) -> [u8; SCALAR_SIZE] {
    let bn_a = BnWrapper::from_bytes(a);
    let bn_b = BnWrapper::from_bytes(b);
    let mont_a = BnWrapper::new();
    let bn_r = BnWrapper::new();
    let ctx = BnCtxWrapper::new();
    let mont = p256_order_mont_ctx();

    // Compute a * b = MulMont(ToMont(a), b). This saves two montgomery reductions compared to computing
    // FromMont(MulMont(ToMont(a), ToMont(b))).

    // Convert a to Montgomery form.
    // SAFETY: All BIGNUM and MONT_CTX pointers are valid.
    let rc = unsafe {
        bssl_sys::BN_to_montgomery(
            mont_a.as_mut_ptr(),
            bn_a.as_ptr(),
            mont.as_ptr(),
            ctx.as_mut_ptr(),
        )
    };
    assert_eq!(rc, 1);

    // Multiply in Montgomery domain (constant-time).
    // SAFETY: All pointers are valid.
    let rc = unsafe {
        bssl_sys::BN_mod_mul_montgomery(
            bn_r.as_mut_ptr(),
            mont_a.as_ptr(),
            bn_b.as_ptr(),
            mont.as_ptr(),
            ctx.as_mut_ptr(),
        )
    };
    assert_eq!(rc, 1);

    bn_r.to_bytes32()
    // All BnWrappers and BnCtxWrapper freed automatically on drop.
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

    pub fn random() -> Self {
        random_scalar()
    }

    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Constant-time modular inversion using Fermat's little theorem:
    /// a^{-1} = a^{order-2} (mod order) for prime order.
    ///
    /// Uses `BN_mod_exp_mont`, which treats the base as secret.
    /// Returns `None` (as a `CtOption`) if `self` is zero.
    pub fn invert(&self) -> CtOption<BsslScalar> {
        // Always perform the inversion to avoid leaking whether self is zero.
        let is_nonzero = !self.is_zero();
        // Use 1 as a fallback input so the exponentiation always succeeds.
        let safe_input = BsslScalar::conditional_select(&BsslScalar::ONE, self, is_nonzero);

        let bn_a = BnWrapper::from_bytes(&safe_input.0);
        let bn_exp = BnWrapper::from_bytes(p256_order_minus_2());
        let bn_r = BnWrapper::new();
        let ctx = BnCtxWrapper::new();
        let mont = p256_order_mont_ctx();

        // Compute safe_input^{order-2} mod order.
        //
        // SAFETY: All pointers are valid. bn_a is in [0, order) as required by
        // BN_mod_exp_mont (see https://boringssl.googlesource.com/boringssl/+/8aacd0c97fb1f06c8d10e0a6ab034cd4c4d102b4/include/openssl/bn.h?pli=1#815).
        // BN_mod_exp_mont treats the base (bn_a) as secret.
        let rc = unsafe {
            bssl_sys::BN_mod_exp_mont(
                bn_r.as_mut_ptr(),
                bn_a.as_ptr(),
                bn_exp.as_ptr(),
                p256_order(),
                ctx.as_mut_ptr(),
                mont.as_ptr(),
            )
        };
        assert_eq!(rc, 1);

        let result = bn_r.to_bytes32();
        CtOption::new(BsslScalar(result), is_nonzero)
        // bn_a, bn_exp, bn_r, ctx freed automatically on drop.
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
    // Constant-time via Montgomery multiplication.
    fn mul(self, rhs: BsslScalar) -> BsslScalar {
        BsslScalar(bn_mod_mul_mont(&self.0, &rhs.0))
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
// BsslPoint – an owned BoringSSL EC_POINT on P-256
// ---------------------------------------------------------------------------

/// Owns an `EC_POINT` on P-256 through `NonNull` and frees it on drop via `EC_POINT_free`.
pub struct BsslPoint(NonNull<bssl_sys::EC_POINT>);

// SAFETY: BsslPoint exclusively owns its heap-allocated EC_POINT, and the underlying
// P-256 EC_GROUP is a process-static immutable structure (EC_GROUP_dup/EC_GROUP_free
// are no-ops on built-in static groups). There is no thread-local or shared mutable state.
unsafe impl Send for BsslPoint {}

impl Drop for BsslPoint {
    fn drop(&mut self) {
        // SAFETY: self.0 was allocated by EC_POINT_new and is a valid non-null pointer.
        unsafe { bssl_sys::EC_POINT_free(self.0.as_ptr()) };
    }
}

impl Clone for BsslPoint {
    fn clone(&self) -> Self {
        let dst = Self::new(p256_group());
        // SAFETY: dst and self are valid EC_POINT pointers on the same group.
        let rc = unsafe { bssl_sys::EC_POINT_copy(dst.as_mut_ptr(), self.as_ptr()) };
        assert_eq!(rc, 1, "EC_POINT_copy failed");
        dst
    }
}

impl Default for BsslPoint {
    fn default() -> Self {
        Self::identity()
    }
}

impl core::fmt::Debug for BsslPoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("BsslPoint").field(&self.to_bytes33()).finish()
    }
}

impl Zeroize for BsslPoint {
    fn zeroize(&mut self) {
        let group = p256_group();
        // SAFETY: group and self are valid pointers. EC_POINT_set_to_infinity
        // calls ec_GFp_simple_point_init, which zeroes X, Y, and Z via OPENSSL_memset.
        let rc = unsafe { bssl_sys::EC_POINT_set_to_infinity(group, self.as_mut_ptr()) };
        assert_eq!(rc, 1);
    }
}

impl BsslPoint {
    /// Allocate a new EC_POINT on the given group. Panics if allocation fails.
    fn new(group: *const bssl_sys::EC_GROUP) -> Self {
        // SAFETY: EC_POINT_new is safe to call with a valid group pointer.
        let ptr = unsafe { bssl_sys::EC_POINT_new(group) };
        Self(NonNull::new(ptr).expect("EC_POINT_new returned null"))
    }

    fn as_ptr(&self) -> *const bssl_sys::EC_POINT {
        self.0.as_ptr()
    }

    fn as_mut_ptr(&self) -> *mut bssl_sys::EC_POINT {
        self.0.as_ptr()
    }

    /// Return the identity element (point at infinity).
    pub fn identity() -> BsslPoint {
        let group = p256_group();
        let pt = Self::new(group);
        // SAFETY: group and pt are valid pointers.
        let rc = unsafe { bssl_sys::EC_POINT_set_to_infinity(group, pt.as_mut_ptr()) };
        assert_eq!(rc, 1);
        pt
    }

    pub fn is_identity(&self) -> Choice {
        let group = p256_group();
        // SAFETY: group and self are valid pointers. EC_POINT_is_at_infinity
        // checks Z == 0 using constant-time word masks (ec_felem_non_zero_mask).
        let rc = unsafe { bssl_sys::EC_POINT_is_at_infinity(group, self.as_ptr()) };
        Choice::from((rc == 1) as u8)
    }

    /// Serialize this EC_POINT to 33-byte compressed form.
    /// Returns all-zeros for the point at infinity (identity).
    ///
    /// This function is only called at serialization boundaries.
    fn to_bytes33(&self) -> [u8; POINT_SIZE] {
        let group = p256_group();
        // SAFETY: group and self are valid pointers.
        if unsafe { bssl_sys::EC_POINT_is_at_infinity(group, self.as_ptr()) } == 1 {
            return [0u8; POINT_SIZE];
        }
        let mut buf = [0u8; POINT_SIZE];
        // SAFETY: group and self are valid, buf points to a 33-byte buffer.
        let len = unsafe {
            bssl_sys::EC_POINT_point2oct(
                group,
                self.as_ptr(),
                bssl_sys::point_conversion_form_t::POINT_CONVERSION_COMPRESSED,
                buf.as_mut_ptr(),
                POINT_SIZE,
                /*ctx=*/ null_mut(),
            )
        };
        assert_eq!(len, POINT_SIZE);
        buf
    }

    /// Return the standard P-256 generator.
    /// Note: This is not `const` since it requires FFI calls.
    pub fn generator() -> BsslPoint {
        point_generator()
    }

    // Stub: BsslPoint doesn't have a meaningful `random` in the same sense
    // as ProjectivePoint, but tests call it. Generate generator * random_scalar.
    pub fn random() -> BsslPoint {
        // This approach should only be used for actual random point generation, not for hashing to
        // points.
        point_generator() * random_scalar()
    }
}

impl core::ops::Neg for BsslPoint {
    type Output = BsslPoint;
    fn neg(self) -> BsslPoint {
        let group = p256_group();
        // SAFETY: group and self are valid pointers.
        let rc = unsafe {
            bssl_sys::EC_POINT_invert(group, self.as_mut_ptr(), /*ctx=*/ null_mut())
        };
        assert_eq!(rc, 1);
        self
    }
}

impl core::ops::Neg for &BsslPoint {
    type Output = BsslPoint;
    fn neg(self) -> BsslPoint {
        -self.clone()
    }
}

impl core::ops::Add<BsslPoint> for BsslPoint {
    type Output = BsslPoint;

    fn add(self, rhs: BsslPoint) -> BsslPoint {
        &self + &rhs
    }
}

impl core::ops::Add<&BsslPoint> for BsslPoint {
    type Output = BsslPoint;
    fn add(self, rhs: &BsslPoint) -> BsslPoint {
        &self + rhs
    }
}

impl core::ops::Add<BsslPoint> for &BsslPoint {
    type Output = BsslPoint;
    fn add(self, rhs: BsslPoint) -> BsslPoint {
        self + &rhs
    }
}

impl core::ops::Add<&BsslPoint> for &BsslPoint {
    type Output = BsslPoint;
    fn add(self, rhs: &BsslPoint) -> BsslPoint {
        let group = p256_group();
        let r = BsslPoint::new(group);
        // SAFETY: group, r, self, and rhs are all valid pointers.
        let rc = unsafe {
            bssl_sys::EC_POINT_add(
                group,
                r.as_mut_ptr(),
                self.as_ptr(),
                rhs.as_ptr(),
                /*ctx=*/ null_mut(),
            )
        };
        assert_eq!(rc, 1);
        r
    }
}

impl core::ops::Sub<BsslPoint> for BsslPoint {
    type Output = BsslPoint;

    fn sub(self, rhs: BsslPoint) -> BsslPoint {
        let group = p256_group();
        // Negate rhs in place since we own it.
        // SAFETY: group and rhs are valid pointers.
        let rc = unsafe {
            bssl_sys::EC_POINT_invert(group, rhs.as_mut_ptr(), /*ctx=*/ null_mut())
        };
        assert_eq!(rc, 1);
        &self + &rhs
    }
}

impl core::ops::Sub<&BsslPoint> for BsslPoint {
    type Output = BsslPoint;
    fn sub(self, rhs: &BsslPoint) -> BsslPoint {
        self - rhs.clone()
    }
}

impl core::ops::Sub<BsslPoint> for &BsslPoint {
    type Output = BsslPoint;
    fn sub(self, rhs: BsslPoint) -> BsslPoint {
        let group = p256_group();
        // SAFETY: group and rhs are valid pointers.
        let rc = unsafe {
            bssl_sys::EC_POINT_invert(group, rhs.as_mut_ptr(), /*ctx=*/ null_mut())
        };
        assert_eq!(rc, 1);
        self + &rhs
    }
}

impl core::ops::Sub<&BsslPoint> for &BsslPoint {
    type Output = BsslPoint;
    fn sub(self, rhs: &BsslPoint) -> BsslPoint {
        self - rhs.clone()
    }
}

impl core::ops::Mul<BsslScalar> for BsslPoint {
    type Output = BsslPoint;

    fn mul(self, rhs: BsslScalar) -> BsslPoint {
        &self * &rhs
    }
}

impl core::ops::Mul<&BsslScalar> for BsslPoint {
    type Output = BsslPoint;
    fn mul(self, rhs: &BsslScalar) -> BsslPoint {
        &self * rhs
    }
}

impl core::ops::Mul<BsslScalar> for &BsslPoint {
    type Output = BsslPoint;
    fn mul(self, rhs: BsslScalar) -> BsslPoint {
        self * &rhs
    }
}

impl core::ops::Mul<&BsslScalar> for &BsslPoint {
    type Output = BsslPoint;
    fn mul(self, rhs: &BsslScalar) -> BsslPoint {
        let group = p256_group();
        let bn_s = BnWrapper::from_bytes(&rhs.0);
        let r = BsslPoint::new(group);
        // r = NULL*gen + self*bn_s  (i.e. self * scalar)
        // SAFETY: group, r, self, and bn_s are all valid pointers.
        let rc = unsafe {
            bssl_sys::EC_POINT_mul(
                group,
                r.as_mut_ptr(),
                null(),
                self.as_ptr(),
                bn_s.as_ptr(),
                /*ctx=*/ null_mut(),
            )
        };
        assert_eq!(rc, 1);
        r
        // bn_s freed automatically on drop.
    }
}

impl ConstantTimeEq for BsslPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let group = p256_group();
        // SAFETY: group, self, and other are valid pointers on the same group.
        // EC_POINT_cmp delegates to ec_GFp_simple_points_equal, which compares
        // Jacobian coordinates in constant time and returns 0 for equality, 1 for inequality.
        let rc = unsafe {
            bssl_sys::EC_POINT_cmp(group, self.as_ptr(), other.as_ptr(), /*ctx=*/ null_mut())
        };
        assert!(rc >= 0, "EC_POINT_cmp failed");
        Choice::from((rc == 0) as u8)
    }
}

impl PartialEq for BsslPoint {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for BsslPoint {}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

pub fn point_generator() -> BsslPoint {
    let group = p256_group();
    // SAFETY: p256_group() returns a valid group, so EC_GROUP_get0_generator
    // is safe to call and returns a valid pointer owned by the group.
    let generator = unsafe { bssl_sys::EC_GROUP_get0_generator(group) };
    assert!(!generator.is_null());
    let pt = BsslPoint::new(group);
    // SAFETY: pt and generator are valid EC_POINT pointers on the same group.
    let rc = unsafe { bssl_sys::EC_POINT_copy(pt.as_mut_ptr(), generator) };
    assert_eq!(rc, 1, "EC_POINT_copy failed");
    pt
}

/// Not constant-time, but operates only on untrusted public input.
pub fn decode_point(input: &[u8]) -> (CtOption<BsslPoint>, &[u8]) {
    if input.len() < POINT_SIZE {
        return (CtOption::new(BsslPoint::identity(), Choice::from(0u8)), input);
    }
    let mut bytes = [0u8; POINT_SIZE];
    bytes.copy_from_slice(&input[..POINT_SIZE]);

    if bytes == [0u8; POINT_SIZE] {
        return (CtOption::new(BsslPoint::identity(), Choice::from(1u8)), &input[POINT_SIZE..]);
    }

    let group = p256_group();
    let pt = BsslPoint::new(group);
    // SAFETY: group and pt are valid pointers, bytes points to a 33-byte buffer.
    let r = unsafe {
        bssl_sys::EC_POINT_oct2point(group, pt.as_mut_ptr(), bytes.as_ptr(), POINT_SIZE, null_mut())
    };
    if r != 1 {
        // If oct2point fails, it leaves errors on the queue. Clear them and reset pt to identity.
        unsafe {
            bssl_sys::ERR_clear_error();
            bssl_sys::EC_POINT_set_to_infinity(group, pt.as_mut_ptr());
        }
    }

    let valid = Choice::from((r == 1) as u8);
    (CtOption::new(pt, valid), &input[POINT_SIZE..])
}

/// P-256 group order in big-endian, lazily initialized from BoringSSL.
fn p256_order_bytes() -> &'static [u8; SCALAR_SIZE] {
    use std::sync::OnceLock;
    static ORDER: OnceLock<[u8; SCALAR_SIZE]> = OnceLock::new();
    ORDER.get_or_init(|| BnWrapper::raw_to_bytes32(p256_order()))
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
    out.extend_from_slice(&point.to_bytes33());
}

pub fn encode_scalar(scalar: &BsslScalar, out: &mut Vec<u8>) {
    out.extend_from_slice(&scalar.0);
}

pub fn hash_to_point(msgs: &[&[u8]], dsts: &[&[u8]]) -> Result<BsslPoint, &'static str> {
    // Concatenate msgs and dsts like the rustcrypto backend does.
    let msg_cat: Vec<u8> = msgs.iter().flat_map(|m| m.iter().copied()).collect();
    let dst_cat: Vec<u8> = dsts.iter().flat_map(|d| d.iter().copied()).collect();

    let group = p256_group();
    let pt = BsslPoint::new(group);
    // SAFETY: group and pt are valid pointers. dst_cat and msg_cat slices
    // provide valid pointers and lengths to byte buffers.
    let rc = unsafe {
        bssl_sys::EC_hash_to_curve_p256_xmd_sha256_sswu(
            group,
            pt.as_mut_ptr(),
            dst_cat.as_ptr(),
            dst_cat.len(),
            msg_cat.as_ptr(),
            msg_cat.len(),
        )
    };
    if rc != 1 {
        return Err("hash_to_curve failed");
    }
    Ok(pt)
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
    let bn = BnWrapper::from_bytes(&uniform_bytes);
    let bn_r = BnWrapper::new();
    let ctx = BnCtxWrapper::new();
    // BN_nnmod computes non-negative remainder.
    // SAFETY: bn_r, bn, p256_order(), and ctx are all valid pointers.
    let rc = unsafe {
        bssl_sys::BN_nnmod(bn_r.as_mut_ptr(), bn.as_ptr(), p256_order(), ctx.as_mut_ptr())
    };
    assert_eq!(rc, 1);
    Ok(BsslScalar(bn_r.to_bytes32()))
    // bn, bn_r, ctx freed automatically on drop.
}

struct Sha256(bssl_sys::SHA256_CTX);

impl Sha256 {
    fn new() -> Self {
        let mut ctx = core::mem::MaybeUninit::<bssl_sys::SHA256_CTX>::uninit();
        // SAFETY: `SHA256_Init` fully initializes `ctx` and returns 1
        let r = unsafe { bssl_sys::SHA256_Init(ctx.as_mut_ptr()) };
        assert_eq!(r, 1);
        // SAFETY: `SHA256_Init` initialized every field of `ctx`.
        Self(unsafe { ctx.assume_init() })
    }

    fn update(&mut self, data: &[u8]) {
        // SAFETY: `self.0` is a valid initialized SHA256_CTX.
        // `data` is a valid (possibly empty) slice of `data.len()` bytes.
        let r = unsafe {
            bssl_sys::SHA256_Update(
                &mut self.0,
                data.as_ptr().cast::<core::ffi::c_void>(),
                data.len(),
            )
        };
        assert_eq!(r, 1);
    }

    fn finalize(mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        // SAFETY: `out` has SHA256_DIGEST_LENGTH (=32) bytes and `self.0` is a valid initialized SHA256_CTX.
        let r = unsafe { bssl_sys::SHA256_Final(out.as_mut_ptr(), &mut self.0) };
        assert_eq!(r, 1);
        out
    }
}

/// expand_message_xmd using SHA-256, per RFC 9380 §5.3.1.
fn expand_message_xmd_sha256(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> Result<Vec<u8>, &'static str> {
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

pub fn random_scalar() -> BsslScalar {
    // Use BoringSSL's built-in CSPRNG.
    let order = p256_order();
    let bn = BnWrapper::new();
    // SAFETY: bn and order are valid pointers.
    let rc = unsafe { bssl_sys::BN_rand_range(bn.as_mut_ptr(), order) };
    assert_eq!(rc, 1);
    BsslScalar(bn.to_bytes32())
    // bn freed automatically on drop.
}

pub fn random_non_zero_scalar() -> BsslScalar {
    loop {
        let s = random_scalar();
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
        BsslPoint::identity()
    }

    fn point_generator() -> Self::Point {
        point_generator()
    }

    fn point_is_identity(p: &Self::Point) -> Choice {
        p.is_identity()
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
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

    fn random_scalar() -> Self::Scalar {
        random_scalar()
    }

    fn random_non_zero_scalar() -> Self::Scalar {
        random_non_zero_scalar()
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
        let g0 = &g * BsslScalar::ZERO;
        assert!(bool::from(g0.is_identity()));
        assert!(bool::from(g0.ct_eq(&BsslPoint::identity())));
        let g1 = &g * BsslScalar::ONE;
        assert!(bool::from(g1.ct_eq(&g)));
    }

    #[test]
    fn test_point_add_sub() {
        let g = point_generator();
        let two = BsslScalar::from(2u64);
        let g2 = &g * two;
        let g_plus_g = &g + &g;
        assert!(bool::from(g2.ct_eq(&g_plus_g)));

        let back = &g2 - &g;
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
    fn test_sha256() {
        assert_eq!(
            BoringSslBackend::sha256(b""),
            hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            BoringSslBackend::sha256(b"hello world"),
            hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        );
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
        let s1 = random_scalar();
        let s2 = random_scalar();
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
