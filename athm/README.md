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

// Setup with 4 metadata buckets (e.g., risk levels 0-3)
let params = Params::new(4, b"deployment_id".to_vec()).unwrap();
let mut rng = rand::thread_rng();
let (private_key, public_key, proof) = key_gen(&params, &mut rng);

// Client creates blinded request
let (context, request) = token_request(&public_key, &proof, &params, &mut rng).unwrap();

// Server responds with hidden metadata
let hidden_metadata = 2;
let response = token_response(
    &private_key, &public_key, &request, hidden_metadata, &params, &mut rng
).unwrap();

// Client unblinds token
let token = finalize_token(
    &context, &public_key, &request, &response, &params, &mut rng
).unwrap();

// Server verifies and recovers metadata
let metadata = verify_token(&private_key, &token, &params).unwrap();
assert_eq!(metadata, hidden_metadata);
```

## Technical Details

- Uses P-256 elliptic curves and constant-time operations
- Based on the ATHM specification

## Disclaimers
This is not an officially supported Google product. The software is provided as-is without any guarantees or warranties, express or implied.
