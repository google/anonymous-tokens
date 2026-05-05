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
//! This module defines traits for scalar and point operations on P-256,
//! allowing the ATHM protocol to be backed by different ECC implementations.
//!
//! Available backends (selected via Cargo features):
//! - `rustcrypto` (default): Uses the `p256` and `elliptic-curve` crates.
//! - `boringssl`: Uses BoringSSL via `bssl-sys`.

#[cfg(feature = "rustcrypto")]
pub mod rustcrypto;

// Re-export the active backend's types for use in the rest of the crate.
// Exactly one of these features must be enabled.

#[cfg(feature = "rustcrypto")]
pub use rustcrypto::RustCryptoPoint as Point;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto::RustCryptoScalar as Scalar;
