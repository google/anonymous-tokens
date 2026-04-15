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

//! Build script for bssl-sys-athm.
//!
//! This script builds BoringSSL from source using CMake and Ninja, then sets
//! the appropriate linker flags so that the Rust bindings can be used.
//!
//! Prerequisites:
//! - CMake (>= 3.16)
//! - Ninja
//! - Go (>= 1.19)
//! - A C/C++ compiler (gcc or clang)

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

// Keep in sync with the upstream bssl-sys build.rs.
const OSSL_CONF_DEFINES: &[&str] = &[
    "OPENSSL_NO_ASYNC",
    "OPENSSL_NO_BF",
    "OPENSSL_NO_BLAKE2",
    "OPENSSL_NO_BUF_FREELISTS",
    "OPENSSL_NO_CAMELLIA",
    "OPENSSL_NO_CAPIENG",
    "OPENSSL_NO_CAST",
    "OPENSSL_NO_CMS",
    "OPENSSL_NO_COMP",
    "OPENSSL_NO_CT",
    "OPENSSL_NO_DANE",
    "OPENSSL_NO_DEPRECATED",
    "OPENSSL_NO_DGRAM",
    "OPENSSL_NO_DYNAMIC_ENGINE",
    "OPENSSL_NO_EC_NISTP_64_GCC_128",
    "OPENSSL_NO_EC2M",
    "OPENSSL_NO_EGD",
    "OPENSSL_NO_ENGINE",
    "OPENSSL_NO_GMP",
    "OPENSSL_NO_GOST",
    "OPENSSL_NO_HEARTBEATS",
    "OPENSSL_NO_HW",
    "OPENSSL_NO_IDEA",
    "OPENSSL_NO_JPAKE",
    "OPENSSL_NO_KRB5",
    "OPENSSL_NO_MD2",
    "OPENSSL_NO_MDC2",
    "OPENSSL_NO_OCB",
    "OPENSSL_NO_OCSP",
    "OPENSSL_NO_RC2",
    "OPENSSL_NO_RC5",
    "OPENSSL_NO_RFC3779",
    "OPENSSL_NO_RIPEMD",
    "OPENSSL_NO_RMD160",
    "OPENSSL_NO_SCTP",
    "OPENSSL_NO_SEED",
    "OPENSSL_NO_SM2",
    "OPENSSL_NO_SM3",
    "OPENSSL_NO_SM4",
    "OPENSSL_NO_SRP",
    "OPENSSL_NO_SSL_TRACE",
    "OPENSSL_NO_SSL2",
    "OPENSSL_NO_SSL3",
    "OPENSSL_NO_SSL3_METHOD",
    "OPENSSL_NO_STATIC_ENGINE",
    "OPENSSL_NO_STORE",
    "OPENSSL_NO_WHIRLPOOL",
];

fn check_tool(name: &str, args: &[&str]) {
    let status = Command::new(name).args(args).output();
    match status {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            eprintln!(
                "cargo:warning={} found but returned error: {}",
                name,
                String::from_utf8_lossy(&output.stderr)
            );
            panic!(
                "BoringSSL build requires '{}' to work correctly. \
                 Please check your installation.",
                name
            );
        }
        Err(_) => {
            panic!(
                "BoringSSL build requires '{}' but it was not found in PATH. \
                 Please install it and try again.\n\
                 On Ubuntu/Debian: sudo apt-get install cmake ninja-build golang",
                name
            );
        }
    }
}

fn get_boringssl_source_dir() -> PathBuf {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // The BoringSSL submodule is at ../boringssl/ relative to bssl-sys-athm/.
    crate_dir.join("../boringssl")
}

fn get_build_dir(boringssl_dir: &Path) -> PathBuf {
    // Allow overriding via environment variable.
    println!("cargo:rerun-if-env-changed=BORINGSSL_BUILD_DIR");
    if let Some(build_dir) = env::var_os("BORINGSSL_BUILD_DIR") {
        return PathBuf::from(build_dir);
    }
    // Default: build inside the boringssl directory.
    boringssl_dir.join("build")
}

fn build_boringssl(boringssl_dir: &Path, build_dir: &Path, target: &str) {
    // Check if BoringSSL has already been built for this target.
    let bindgen_file = build_dir.join("rust/bssl-sys").join(format!("wrapper_{}.rs", target));
    let crypto_lib = build_dir.join("libcrypto.a");
    let rust_wrapper_lib = build_dir.join("rust/bssl-sys/librust_wrapper.a");

    if bindgen_file.exists() && crypto_lib.exists() && rust_wrapper_lib.exists() {
        return;
    }

    eprintln!("cargo:warning=Building BoringSSL from source (this may take a few minutes)...");

    // Verify that the boringssl submodule is initialized.
    if !boringssl_dir.join("CMakeLists.txt").exists() {
        panic!(
            "BoringSSL source not found at '{}'. \
             Please initialize the git submodule:\n  \
             git submodule update --init boringssl",
            boringssl_dir.display()
        );
    }

    // Check for required build tools.
    check_tool("cmake", &["--version"]);
    check_tool("ninja", &["--version"]);
    check_tool("go", &["version"]);

    // Create build directory.
    std::fs::create_dir_all(build_dir).expect("Failed to create BoringSSL build directory");

    // Run CMake configure.
    let cmake_status = Command::new("cmake")
        .arg("-GNinja")
        .arg(format!("-B{}", build_dir.display()))
        .arg(format!("-DRUST_BINDINGS={}", target))
        .arg(boringssl_dir)
        .status()
        .expect("Failed to run cmake");

    if !cmake_status.success() {
        panic!("CMake configuration failed for BoringSSL");
    }

    // Run Ninja build.
    let ninja_status =
        Command::new("ninja").arg("-C").arg(build_dir).status().expect("Failed to run ninja");

    if !ninja_status.success() {
        panic!("Ninja build failed for BoringSSL");
    }

    eprintln!("cargo:warning=BoringSSL build complete.");
}

fn get_cpp_runtime_lib() -> Option<String> {
    println!("cargo:rerun-if-env-changed=BORINGSSL_RUST_CPPLIB");

    if let Ok(cpp_lib) = env::var("BORINGSSL_RUST_CPPLIB") {
        return Some(cpp_lib);
    }

    if env::var_os("CARGO_CFG_UNIX").is_some() {
        match env::var("CARGO_CFG_TARGET_OS").unwrap().as_ref() {
            "macos" => Some("c++".into()),
            _ => Some("stdc++".into()),
        }
    } else {
        None
    }
}

fn main() {
    let boringssl_dir = get_boringssl_source_dir()
        .canonicalize()
        .expect("Failed to resolve BoringSSL source directory");
    let build_dir = get_build_dir(&boringssl_dir);
    let target = env::var("TARGET").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    let bindgen_out_file = Path::new(&out_dir).join("bindgen.rs");

    // Step 1: Build BoringSSL from source (if not already built).
    build_boringssl(&boringssl_dir, &build_dir, &target);

    // Step 2: Replicate what the upstream bssl-sys/build.rs does.
    let bssl_sys_build_dir = build_dir.join("rust/bssl-sys");

    // Find the bindgen generated target platform bindings file and copy it to
    // OUT_DIR/bindgen.rs.
    let bindgen_source_file = bssl_sys_build_dir.join(format!("wrapper_{}.rs", target));
    std::fs::copy(&bindgen_source_file, &bindgen_out_file).unwrap_or_else(|_| {
        panic!(
            "Could not copy bindings from '{}' to '{}'",
            bindgen_source_file.display(),
            bindgen_out_file.display()
        )
    });
    println!("cargo:rerun-if-changed={}", bindgen_source_file.display());

    // Statically link libraries.
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");

    println!("cargo:rustc-link-search=native={}", bssl_sys_build_dir.display());
    println!("cargo:rustc-link-lib=static=rust_wrapper");

    if let Some(cpp_lib) = get_cpp_runtime_lib() {
        println!("cargo:rustc-link-lib={}", cpp_lib);
    }

    println!("cargo:conf={}", OSSL_CONF_DEFINES.join(","));

    // Rerun if BoringSSL source changes.
    println!("cargo:rerun-if-changed={}", boringssl_dir.join("CMakeLists.txt").display());
}
