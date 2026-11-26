# tee-auth

Shared Rust crate for TEE challenge-response authentication. Used by **coordinator** and **keystore-worker** to verify that a worker holds a private key generated inside a TEE and registered on-chain via `register-contract`.

## How It Works

```
Worker (TEE)                    Server (coordinator/keystore)
     │                                     │
     │  1. Request challenge               │
     │ ──────────────────────────────────> │
     │                                     │ generate_challenge()
     │  2. Return 32-byte random hex       │
     │ <────────────────────────────────── │
     │                                     │
     │  sign(challenge, tee_private_key)   │
     │                                     │
     │  3. Submit signature + public_key   │
     │ ──────────────────────────────────> │
     │                                     │ verify_signature()
     │                                     │ check_access_key_on_contract()
     │  4. Session token                   │
     │ <────────────────────────────────── │
```

The server verifies two things:
1. **Signature is valid** — worker possesses the private key
2. **Key exists on NEAR** — key was registered via `register_worker_key()` with TDX attestation proof

## Public API

```rust
/// Generate random 32-byte challenge (hex-encoded, 64 chars)
pub fn generate_challenge() -> String

/// Verify ed25519 signature over challenge
/// Accepts public keys as `ed25519:...` (base58) or raw hex (64 chars)
pub fn verify_signature(
    public_key: &str,
    challenge: &str,
    signature: &str,
) -> Result<(), TeeAuthError>

/// Check if public key exists as access key on a NEAR account
pub fn check_access_key_on_contract(
    client: &reqwest::Client,
    rpc_url: &str,
    account_id: &str,  // e.g., "operator.outlayer.near"
    public_key: &str,
) -> Result<bool, TeeAuthError>

/// Same as above but retries 3 times with 3s delay (handles finality lag)
pub fn check_access_key_with_retry(
    rpc_url: &str,
    account_id: &str,
    public_key: &str,
) -> Result<bool, TeeAuthError>
```

## Dependencies

- `ed25519-dalek` — ed25519 signing/verification
- `bs58` — base58 encoding (NEAR key format)
- `reqwest` — NEAR RPC calls
- `tokio` — async runtime

## Usage

Used as a workspace dependency:

```toml
[dependencies]
tee-auth = { path = "../tee-auth" }
```

Consumers: `coordinator`, `keystore-worker`

## custody-core

`custody-core/` is a second crate in this repository: the bytes that are
signed for a wallet contract of the two-key standard (Agent On-chain custody),
and the rules about it that are pure. It does no I/O: no HTTP, no RPC, no
clock, no randomness. The keystore, the coordinator and the owner's recovery
tool build on it, so each byte format has one implementation.

| Module | What it holds |
|---|---|
| `message` | the wallet contract's request, its Borsh encoding, its hash and its JSON forms |
| `moves` | the request for each move a wallet contract makes |
| `halves` | the agent's and the TEE's half of a request, the pair of public keys, the proof |
| `agent_request` | an HTTPS request signed by the agent's key |
| `keys` | the TEE's key of a wallet from the owner's master; the agent's key from the owner's signature |
| `admit` | what an account has to show to be served as a wallet contract |
| `text` | the one spelling of bytes (lowercase hex) and of a number (decimal digits) |

`custody-core/vectors/` are the test vectors other implementations check
against (`halves.json` is the contract's own file, byte for byte);
`tests/against_the_contract.rs` hashes and verifies against the contract's
code. The model: `docs/ON_CHAIN_CUSTODY.md` in `out-layer/near-offshore`.
