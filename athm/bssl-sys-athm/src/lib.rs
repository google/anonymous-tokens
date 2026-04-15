// Copyright 2021 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file is derived from the upstream bssl-sys crate in the BoringSSL
// repository. It provides the same FFI bindings interface, with the bssl_enum
// macro inlined to avoid a dependency on the bssl-macros crate.

#![no_std]
#![allow(non_snake_case)]

use core::ffi::c_ulong;

// Wrap the bindgen output in a module and re-export it, so we can override it
// as needed.
mod bindgen {
    #[cfg(not(bindgen_rs_file))]
    include!(concat!(env!("OUT_DIR"), "/bindgen.rs"));
    // Some static build systems (e.g. bazel) do not support the `OUT_DIR`
    // configuration used by Cargo. They can specify a complete path to the
    // generated bindings as an environment variable.
    #[cfg(bindgen_rs_file)]
    include!(env!("BINDGEN_RS_FILE"));
}
pub use bindgen::*;

// bindgen does not handle C constants correctly. See
// https://github.com/rust-lang/rust-bindgen/issues/923. Work around this bug by
// redefining some constants with the correct type. Once the bindgen bug has
// been fixed, remove this.
pub const ASN1_STRFLGS_ESC_2253: c_ulong = bindgen::ASN1_STRFLGS_ESC_2253 as c_ulong;
pub const ASN1_STRFLGS_ESC_CTRL: c_ulong = bindgen::ASN1_STRFLGS_ESC_CTRL as c_ulong;
pub const ASN1_STRFLGS_ESC_MSB: c_ulong = bindgen::ASN1_STRFLGS_ESC_MSB as c_ulong;
pub const ASN1_STRFLGS_ESC_QUOTE: c_ulong = bindgen::ASN1_STRFLGS_ESC_QUOTE as c_ulong;
pub const ASN1_STRFLGS_UTF8_CONVERT: c_ulong = bindgen::ASN1_STRFLGS_UTF8_CONVERT as c_ulong;
pub const ASN1_STRFLGS_IGNORE_TYPE: c_ulong = bindgen::ASN1_STRFLGS_IGNORE_TYPE as c_ulong;
pub const ASN1_STRFLGS_SHOW_TYPE: c_ulong = bindgen::ASN1_STRFLGS_SHOW_TYPE as c_ulong;
pub const ASN1_STRFLGS_DUMP_ALL: c_ulong = bindgen::ASN1_STRFLGS_DUMP_ALL as c_ulong;
pub const ASN1_STRFLGS_DUMP_UNKNOWN: c_ulong = bindgen::ASN1_STRFLGS_DUMP_UNKNOWN as c_ulong;
pub const ASN1_STRFLGS_DUMP_DER: c_ulong = bindgen::ASN1_STRFLGS_DUMP_DER as c_ulong;
pub const ASN1_STRFLGS_RFC2253: c_ulong = bindgen::ASN1_STRFLGS_RFC2253 as c_ulong;
pub const XN_FLAG_COMPAT: c_ulong = bindgen::XN_FLAG_COMPAT as c_ulong;
pub const XN_FLAG_SEP_MASK: c_ulong = bindgen::XN_FLAG_SEP_MASK as c_ulong;
pub const XN_FLAG_SEP_COMMA_PLUS: c_ulong = bindgen::XN_FLAG_SEP_COMMA_PLUS as c_ulong;
pub const XN_FLAG_SEP_CPLUS_SPC: c_ulong = bindgen::XN_FLAG_SEP_CPLUS_SPC as c_ulong;
pub const XN_FLAG_SEP_SPLUS_SPC: c_ulong = bindgen::XN_FLAG_SEP_SPLUS_SPC as c_ulong;
pub const XN_FLAG_SEP_MULTILINE: c_ulong = bindgen::XN_FLAG_SEP_MULTILINE as c_ulong;
pub const XN_FLAG_DN_REV: c_ulong = bindgen::XN_FLAG_DN_REV as c_ulong;
pub const XN_FLAG_FN_MASK: c_ulong = bindgen::XN_FLAG_FN_MASK as c_ulong;
pub const XN_FLAG_FN_SN: c_ulong = bindgen::XN_FLAG_FN_SN as c_ulong;
pub const XN_FLAG_SPC_EQ: c_ulong = bindgen::XN_FLAG_SPC_EQ as c_ulong;
pub const XN_FLAG_DUMP_UNKNOWN_FIELDS: c_ulong = bindgen::XN_FLAG_DUMP_UNKNOWN_FIELDS as c_ulong;
pub const XN_FLAG_RFC2253: c_ulong = bindgen::XN_FLAG_RFC2253 as c_ulong;
pub const XN_FLAG_ONELINE: c_ulong = bindgen::XN_FLAG_ONELINE as c_ulong;

pub fn init() {
    // This function does nothing.
}

// Inlined from bssl-macros to avoid depending on the BoringSSL submodule.
macro_rules! bssl_enum {
    (
        $(#[$attr:meta])*
        $vis:vis enum $name:ident : $repr:ty {
            $(
                $(#[$vattr:meta])*
                $item:ident = $e:expr
            ),* $(,)?
        }
    ) => {
        $(#[$attr])*
        #[repr($repr)]
        $vis enum $name {
            $(
                $(#[$vattr])*
                $item = $e,
            )*
        }

        impl ::core::convert::TryFrom<$repr> for $name {
            type Error = $repr;

            fn try_from(value: $repr) -> Result<Self, Self::Error> {
                $(
                    #[allow(non_upper_case_globals)]
                    const $item: $repr = $e;
                )*

                #[allow(non_upper_case_globals)]
                match value {
                    $(
                        $item => ::core::result::Result::Ok(Self::$item),
                    )*
                    _ => ::core::result::Result::Err(value),
                }
            }
        }
    };
}

bssl_enum! {
    /// Library code of the BoringSSL errors.
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum LibCode: i32 {
        /// No module
        None = ERR_LIB_NONE as i32,
        /// Module `SYS`
        Sys = ERR_LIB_SYS as i32,
        /// Module `BN`
        Bn = ERR_LIB_BN as i32,
        /// Module `RSA`
        Rsa = ERR_LIB_RSA as i32,
        /// Module `DH`
        Dh = ERR_LIB_DH as i32,
        /// Module `EVP`
        Evp = ERR_LIB_EVP as i32,
        /// Module `BUF`
        Buf = ERR_LIB_BUF as i32,
        /// Module `OBJ`
        Obj = ERR_LIB_OBJ as i32,
        /// Module `PEM`
        Pem = ERR_LIB_PEM as i32,
        /// Module `DSA`
        Dsa = ERR_LIB_DSA as i32,
        /// Module `X509`
        X509 = ERR_LIB_X509 as i32,
        /// Module `ASN1`
        Asn1 = ERR_LIB_ASN1 as i32,
        /// Module `CONF`
        Conf = ERR_LIB_CONF as i32,
        /// Module `CRYPTO`
        Crypto = ERR_LIB_CRYPTO as i32,
        /// Module `EC`
        Ec = ERR_LIB_EC as i32,
        /// Module `SSL`
        Ssl = ERR_LIB_SSL as i32,
        /// Module `BIO`
        Bio = ERR_LIB_BIO as i32,
        /// Module `PKCS7`
        Pkcs7 = ERR_LIB_PKCS7 as i32,
        /// Module `PKCS8`
        Pkcs8 = ERR_LIB_PKCS8 as i32,
        /// Module `X509V3`
        X509v3 = ERR_LIB_X509V3 as i32,
        /// Module `RAND`
        Rand = ERR_LIB_RAND as i32,
        /// Module `ENGINE`
        Engine = ERR_LIB_ENGINE as i32,
        /// Module `OCSP`
        Ocsp = ERR_LIB_OCSP as i32,
        /// Module `UI`
        Ui = ERR_LIB_UI as i32,
        /// Module `COMP`
        Comp = ERR_LIB_COMP as i32,
        /// Module `ECDSA`
        Ecdsa = ERR_LIB_ECDSA as i32,
        /// Module `ECDH`
        Ecdh = ERR_LIB_ECDH as i32,
        /// Module `HMAC`
        Hmac = ERR_LIB_HMAC as i32,
        /// Module `DIGEST`
        Digest = ERR_LIB_DIGEST as i32,
        /// Module `CIPHER`
        Cipher = ERR_LIB_CIPHER as i32,
        /// Module `HKDF`
        Hkdf = ERR_LIB_HKDF as i32,
        /// Module `TRUST_TOKEN`
        TrustToken = ERR_LIB_TRUST_TOKEN as i32,
        /// Module `CMS`
        Cms = ERR_LIB_CMS as i32,
        /// User sourced
        User = ERR_LIB_USER as i32,
    }
}
