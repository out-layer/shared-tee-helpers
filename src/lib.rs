//! TEE Auth - shared challenge-response authentication for TEE workers
//!
//! Used by coordinator and keystore-worker to verify that a worker
//! possesses a private key registered on the register-contract via TDX attestation.
//!
//! Flow:
//! 1. Server generates random challenge via `generate_challenge()`
//! 2. Worker signs challenge with TEE private key
//! 3. Server verifies signature via `verify_signature()`
//! 4. Server checks key exists on register-contract via `check_access_key_on_contract()`

use near_crypto::{KeyType, PublicKey, Signature};
use rand::RngCore;
use std::str::FromStr;

pub mod wallet_policy;

/// Which signature schemes the server is willing to accept for TEE session auth.
///
/// The worker announces its scheme in the `public_key`/`signature` strings (NEAR canonical
/// form, e.g. `ml-dsa-65:...`). The server decides — via this allowlist, driven by an env var —
/// whether that scheme is acceptable. There is deliberately NO auto-detect fallback to the old
/// hex-ed25519 wire format: every worker is redeployed with the NEAR-canonical form, so a legacy
/// path would only be a latent regression surface.
#[derive(Debug, Clone, Copy)]
pub struct AllowedKeyTypes {
    pub ed25519: bool,
    pub ml_dsa_65: bool,
}

impl AllowedKeyTypes {
    /// Parse from a comma-separated env value, e.g. `"ed25519,ml-dsa-65"`.
    /// Unknown tokens are ignored; unset/empty yields an all-deny set (caller must opt in).
    pub fn from_csv(s: &str) -> Self {
        let mut a = AllowedKeyTypes { ed25519: false, ml_dsa_65: false };
        for tok in s.split(',') {
            match tok.trim().to_ascii_lowercase().as_str() {
                "ed25519" => a.ed25519 = true,
                "ml-dsa-65" | "ml_dsa_65" | "mldsa65" | "ml-dsa" => a.ml_dsa_65 = true,
                "" => {}
                _ => {}
            }
        }
        a
    }

    fn allows(&self, kt: KeyType) -> bool {
        match kt {
            KeyType::ED25519 => self.ed25519,
            KeyType::MLDSA65 => self.ml_dsa_65,
            _ => false,
        }
    }
}

/// Whether `chain` is an EVM (secp256k1) network.
///
/// Single source of truth shared by the keystore (address derivation + signing)
/// and the coordinator (request gating) so the two can't drift on which chains
/// are EVM. Accepts canonical long names and 1Click-style short aliases; all of
/// these resolve to ONE derived secp256k1 address.
pub fn is_evm_chain(chain: &str) -> bool {
    matches!(
        chain,
        "ethereum" | "eth" | "polygon" | "pol" | "matic" | "base" | "arbitrum" | "arb"
            | "optimism" | "op" | "bsc" | "avalanche" | "avax"
    )
}

/// Whether `chain` is Solana (ed25519, seed `wallet:{id}:solana`).
///
/// Same single-source-of-truth role as [`is_evm_chain`]: shared by the
/// keystore (signing) and the coordinator (request gating). Accepts the
/// canonical name and the 1Click-style short alias; both resolve to the ONE
/// derived ed25519 key on the canonical `solana` seed suffix.
pub fn is_solana_chain(chain: &str) -> bool {
    matches!(chain, "solana" | "sol")
}

/// Whether `s` has the shape of a NEAR **implicit account**: 64 lowercase hex.
///
/// Single source of truth for the same reason as [`is_evm_chain`], and with a
/// sharper edge: this shape is what decides whether a secret is an AGENT's.
///
/// The keystore fires its agent-secret rule on it — a secret whose profile
/// looks like an account may be read only by that account, and only if that
/// account stored it — and the coordinator uses it to decide whether to address
/// a secret at all. If the two ever disagreed, the coordinator would ask for a
/// secret under a name the keystore does not police, or refuse to ask for one
/// the keystore would have guarded. Both are silent failures.
///
/// **Lowercase only**, because that is the only form an implicit account takes:
/// the chain rejects any other spelling, so accepting one here would create a
/// second name for something that has exactly one.
pub fn is_implicit_account(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Generate a random 32-byte challenge as hex string (64 chars).
pub fn generate_challenge() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Verify a challenge signature in NEAR canonical form, gated by an allowlist.
///
/// Handles ed25519 and ml-dsa-65 (FIPS-204) uniformly via near-crypto. The key type is taken
/// from the `public_key`/`signature` strings themselves (their scheme prefix), then checked
/// against `allowed` — so the server, not the worker, decides which schemes are acceptable.
///
/// # Arguments
/// * `public_key` - NEAR canonical form, e.g. `ed25519:<base58>` or `ml-dsa-65:<base58>`
/// * `challenge` - hex-encoded challenge string (as returned by `generate_challenge`)
/// * `signature` - NEAR canonical form, e.g. `ed25519:<base58>` or `ml-dsa-65:<base58>`
/// * `allowed` - which schemes this server accepts (from env; see [`AllowedKeyTypes`])
pub fn verify_signature(
    public_key: &str,
    challenge: &str,
    signature: &str,
    allowed: AllowedKeyTypes,
) -> Result<(), TeeAuthError> {
    let pk = PublicKey::from_str(public_key)
        .map_err(|e| TeeAuthError::InvalidPublicKey(format!("parse error: {}", e)))?;

    // Server-side policy: reject a scheme this deployment has not opted into, BEFORE spending
    // cycles on verification.
    if !allowed.allows(pk.key_type()) {
        return Err(TeeAuthError::KeyTypeNotAllowed(format!("{}", pk.key_type())));
    }

    let sig = Signature::from_str(signature)
        .map_err(|e| TeeAuthError::InvalidSignature(format!("parse error: {}", e)))?;

    // Verify the raw challenge bytes (not the hex string).
    let challenge_bytes = hex::decode(challenge)
        .map_err(|e| TeeAuthError::InvalidChallenge(format!("hex decode error: {}", e)))?;

    if sig.verify(&challenge_bytes, &pk) {
        Ok(())
    } else {
        Err(TeeAuthError::SignatureVerificationFailed)
    }
}

/// Check if a public key exists as an access key on a NEAR account via RPC.
///
/// Uses `view_access_key` RPC query to check if the key is registered
/// on the register-contract account (proving it was TEE-attested).
///
/// # Arguments
/// * `client` - reqwest HTTP client
/// * `rpc_url` - NEAR RPC URL (e.g., "https://rpc.mainnet.near.org")
/// * `account_id` - operator account where register-contract is deployed (e.g., "worker.outlayer.near")
/// * `public_key` - "ed25519:..." format
pub async fn check_access_key_on_contract(
    client: &reqwest::Client,
    rpc_url: &str,
    account_id: &str,
    public_key: &str,
) -> Result<bool, TeeAuthError> {
    // NEAR RPC wants the canonical `<scheme>:<base58>` form. Any key already carrying a scheme
    // prefix (ed25519:, secp256k1:, ml-dsa-65:) is passed through untouched; a bare 64-char hex
    // string is treated as a legacy raw ed25519 key.
    let near_key = if public_key.contains(':') {
        public_key.to_string()
    } else {
        let bytes = hex::decode(public_key)
            .map_err(|e| TeeAuthError::InvalidPublicKey(format!("hex decode: {}", e)))?;
        format!("ed25519:{}", bs58::encode(&bytes).into_string())
    };

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "tee-auth",
        "method": "query",
        "params": {
            "request_type": "view_access_key",
            "finality": "optimistic",
            "account_id": account_id,
            "public_key": near_key
        }
    });

    let response = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| TeeAuthError::NearRpcError(format!("request failed: {}", e)))?;

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| TeeAuthError::NearRpcError(format!("response parse failed: {}", e)))?;

    // If there's an error field, the key doesn't exist
    if let Some(error) = json.get("error") {
        // Check structured error first: error.cause.name == "UNKNOWN_ACCESS_KEY"
        let is_unknown_key = error
            .get("cause")
            .and_then(|c| c.get("name"))
            .and_then(|n| n.as_str())
            .map(|name| name == "UNKNOWN_ACCESS_KEY")
            .unwrap_or(false);

        if is_unknown_key {
            return Ok(false);
        }

        // Fallback: check error.data string for older RPC versions
        let error_data = error
            .get("data")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        if error_data.contains("does not exist") || error_data.contains("doesn't exist") {
            return Ok(false);
        }

        return Err(TeeAuthError::NearRpcError(format!("RPC error: {}", error)));
    }

    // Check that result exists and has permission field (valid access key)
    if json.get("result").and_then(|r| r.get("permission")).is_some() {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check if a public key exists on a NEAR account, with retry for finality lag.
///
/// Creates its own HTTP client to avoid reqwest version conflicts between crates.
/// Retries up to 3 times with 3s delay when key is not found (may not be visible yet).
///
/// # Arguments
/// * `rpc_url` - NEAR RPC URL (e.g., "https://rpc.mainnet.near.org")
/// * `account_id` - operator account (e.g., "worker.outlayer.near")
/// * `public_key` - "ed25519:..." format
pub async fn check_access_key_with_retry(
    rpc_url: &str,
    account_id: &str,
    public_key: &str,
) -> Result<bool, TeeAuthError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| TeeAuthError::NearRpcError(format!("HTTP client error: {}", e)))?;

    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(3);

    for attempt in 1..=MAX_RETRIES {
        match check_access_key_on_contract(&client, rpc_url, account_id, public_key).await {
            Ok(true) => return Ok(true),
            Ok(false) if attempt < MAX_RETRIES => {
                tracing::info!(
                    attempt = attempt,
                    public_key = %public_key,
                    account_id = %account_id,
                    "Key not yet visible on-chain, retrying in {}s...",
                    RETRY_DELAY.as_secs()
                );
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Ok(false) => return Ok(false),
            Err(e) if attempt < MAX_RETRIES => {
                tracing::warn!(
                    attempt = attempt,
                    error = %e,
                    "NEAR RPC check failed, retrying..."
                );
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(false)
}

#[derive(Debug, thiserror::Error)]
pub enum TeeAuthError {
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("invalid challenge: {0}")]
    InvalidChallenge(String),
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("key type not allowed by this server: {0}")]
    KeyTypeNotAllowed(String),
    #[error("NEAR RPC error: {0}")]
    NearRpcError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_crypto::SecretKey;

    const BOTH: AllowedKeyTypes = AllowedKeyTypes { ed25519: true, ml_dsa_65: true };

    /// The shape that decides whether a secret belongs to an agent.
    ///
    /// Both halves are load-bearing and in opposite directions. Too WIDE and an
    /// ordinary profile starts being treated as an account, so a human's secret
    /// falls under a rule written for agents. Too NARROW and a real agent's
    /// secret slips past the rule entirely — which is the half that leaks a
    /// connector credential.
    #[test]
    fn an_implicit_account_is_exactly_sixty_four_lowercase_hex() {
        const AGENT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

        assert!(is_implicit_account(AGENT));
        assert!(is_implicit_account(&"0".repeat(64)));
        assert!(is_implicit_account(&"f".repeat(64)));

        assert!(!is_implicit_account(&AGENT[..63]), "one short");
        assert!(!is_implicit_account(&format!("{AGENT}a")), "one long");
        assert!(
            !is_implicit_account(&AGENT.to_uppercase()),
            "the chain rejects this spelling, so accepting it would create a second \
             name for one account"
        );
        assert!(!is_implicit_account(&format!("{}g", &AGENT[..63])), "not hex");
        assert!(!is_implicit_account("alice.near"));
        assert!(!is_implicit_account(""));
    }

    fn sign_ok(sk: &SecretKey) {
        let challenge = generate_challenge();
        let challenge_bytes = hex::decode(&challenge).unwrap();
        let sig = sk.sign(&challenge_bytes);
        verify_signature(&sk.public_key().to_string(), &challenge, &sig.to_string(), BOTH).unwrap();
    }

    #[test]
    fn test_verify_ed25519() {
        sign_ok(&SecretKey::from_random(KeyType::ED25519));
    }

    #[test]
    fn test_verify_ml_dsa_65() {
        sign_ok(&SecretKey::from_random(KeyType::MLDSA65));
    }

    #[test]
    fn test_key_type_not_allowed() {
        // ml-dsa signature is valid, but this server only accepts ed25519.
        let sk = SecretKey::from_random(KeyType::MLDSA65);
        let challenge = generate_challenge();
        let sig = sk.sign(&hex::decode(&challenge).unwrap());
        let only_ed = AllowedKeyTypes { ed25519: true, ml_dsa_65: false };
        let err = verify_signature(&sk.public_key().to_string(), &challenge, &sig.to_string(), only_ed)
            .unwrap_err();
        assert!(matches!(err, TeeAuthError::KeyTypeNotAllowed(_)), "got {err:?}");
    }

    #[test]
    fn test_verify_wrong_signature() {
        let sk = SecretKey::from_random(KeyType::ED25519);
        let other = SecretKey::from_random(KeyType::ED25519);
        let challenge = generate_challenge();
        let sig = other.sign(&hex::decode(&challenge).unwrap()); // signed by the wrong key
        let err = verify_signature(&sk.public_key().to_string(), &challenge, &sig.to_string(), BOTH)
            .unwrap_err();
        assert!(matches!(err, TeeAuthError::SignatureVerificationFailed), "got {err:?}");
    }

    #[test]
    fn test_from_csv() {
        let a = AllowedKeyTypes::from_csv("ed25519, ml-dsa-65");
        assert!(a.ed25519 && a.ml_dsa_65);
        let b = AllowedKeyTypes::from_csv("ed25519");
        assert!(b.ed25519 && !b.ml_dsa_65);
        let c = AllowedKeyTypes::from_csv("");
        assert!(!c.ed25519 && !c.ml_dsa_65);
    }

    #[test]
    fn test_is_evm_chain() {
        for c in [
            "ethereum", "eth", "polygon", "pol", "matic", "base", "arbitrum", "arb", "optimism",
            "op", "bsc", "avalanche", "avax",
        ] {
            assert!(is_evm_chain(c), "{c} should be EVM");
        }
        for c in ["near", "solana", "sol", "bitcoin", "btc", ""] {
            assert!(!is_evm_chain(c), "{c} must not be EVM");
        }
    }

    #[test]
    fn test_challenge_generation() {
        let c1 = generate_challenge();
        let c2 = generate_challenge();
        assert_eq!(c1.len(), 64); // 32 bytes = 64 hex chars
        assert_ne!(c1, c2); // Should be random
    }

}
