# Anonymous Tokens with Hidden Metadata (ATHM)

Privacy-preserving tokens where servers embed metadata invisible to clients.

## Overview

ATHM lets servers embed categorical data (like risk scores or user tiers) in tokens without clients knowing. Useful for anonymous authentication with hidden authorization levels.

## Features

- Tokens can't be linked to their requests
- Metadata is cryptographically hidden from clients
- Built on P-256 elliptic curves
- Constant-time operations prevent timing attacks

## Protocol Flow

1. Server generates keys
2. Client creates blinded request
3. Server embeds metadata and signs
4. Client unblinds to get final token
5. Server verifies token and recovers metadata

## Installation

Add to your `Cargo.toml`:
```toml
[dependencies]
athm = "0.1.0"
```

## Example

```rust
use athm::*;
use rand_core::OsRng;

// Setup with 4 metadata buckets (e.g., risk levels 0-3)
let params = Params::new(4).unwrap();
let (private_key, public_key, proof) = key_gen(&params);

// Client creates blinded request
let mut rng = OsRng;
let (context, request) = token_request(&public_key, &proof, &params, &mut rng).unwrap();

// Server embeds metadata (e.g., risk level 2) and responds
let response = token_response(&private_key, &public_key, &request, 2, &params, &mut rng).unwrap();

// Client unblinds token
let token = finalize_token(&context, &public_key, &request, &response, &params, &mut rng).unwrap();

// Server verifies and recovers metadata
let metadata = verify_token(&private_key, &token, &params).unwrap();
assert_eq!(metadata, 2);
```

## ⚠️ Warning

**EXPERIMENTAL SOFTWARE** - Not audited, not for production use.

## Technical Details

- Uses P-256 elliptic curves and constant-time operations
- Based on the ATHM specification
