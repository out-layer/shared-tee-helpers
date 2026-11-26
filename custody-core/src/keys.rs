//! The two keys of a wallet contract's pair, and where each comes from.
//!
//! The TEE's key is a function of the owner's master and the wallet's id, by the
//! keystore's one derivation: the Ed25519 key whose seed is
//! `HMAC-SHA256(owner master, derivation string)`. The enclave derives it when
//! it signs; an owner who has left with their master derives the same key
//! with this function.

use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The root of the derivation string. No other key of the keystore is derived
/// from a string that starts with it.
pub const TEE_KEY_ROOT: &str = "wallet-contract:";

/// The derivation string of the TEE's key for the wallet `wallet_id`.
pub fn tee_key_seed(wallet_id: &str) -> String {
    format!("{TEE_KEY_ROOT}{wallet_id}")
}

/// The TEE's key for the wallet `wallet_id` under `owner_master`.
pub fn tee_key(owner_master: &[u8; 32], wallet_id: &str) -> SigningKey {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(owner_master)
        .expect("HMAC takes a key of any size");
    mac.update(tee_key_seed(wallet_id).as_bytes());
    SigningKey::from_bytes(&mac.finalize().into_bytes().into())
}

/// The agent's key comes from one signature of the owner's own key: a
/// NEP-413 signature over [`agent_key_message`] for the recipient
/// [`AGENT_KEY_RECIPIENT`] with the nonce [`AGENT_KEY_NONCE`]. Ed25519
/// signatures are deterministic, so the owner's wallet makes the same
/// signature again whenever it is asked, and the same key follows: the agent's
/// key needs no backup, and an owner who has left holds it together with the
/// TEE's.
///
/// Whoever is given that signature holds the agent's key. The message says so,
/// and names the one site that asks for it.
pub const AGENT_KEY_RECIPIENT: &str = "outlayer-agent-key";

/// The fixed NEP-413 nonce of the signature the agent's key comes from: the
/// same request has to give the same signature.
pub const AGENT_KEY_NONCE: [u8; 32] = *b"outlayer/agent-key/v1/nonce\0\0\0\0\0";

const AGENT_KEY_DOMAIN: &[u8] = b"outlayer/agent-key/v1";

/// The message the owner signs for the agent's key of the wallet `wallet_id`.
pub fn agent_key_message(owner: &str, wallet_id: &str) -> String {
    format!(
        "This signature is the key of your OutLayer agent. Sign it only on app.outlayer.ai, \
         when you set up or recover an agent.\nOwner: {owner}\nWallet: {wallet_id}"
    )
}

/// The agent's key from the owner's signature over [`agent_key_message`].
pub fn agent_key(signature: &[u8; 64], owner: &str, wallet_id: &str) -> SigningKey {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(AGENT_KEY_DOMAIN)
        .expect("HMAC takes a key of any size");
    mac.update(signature);
    mac.update(agent_key_message(owner, wallet_id).as_bytes());
    SigningKey::from_bytes(&mac.finalize().into_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A change here moves the TEE's key of every wallet contract, and the
    /// contract's state holds the old one.
    #[test]
    fn the_derivation_is_pinned() {
        let key = tee_key(&[9; 32], "a1b2c3");
        assert_eq!(tee_key_seed("a1b2c3"), "wallet-contract:a1b2c3");
        assert_eq!(
            hex::encode(key.verifying_key().to_bytes()),
            "c8740ba0a76d56b72bb38e980bf740febd23cac922523c4e6731622f5c9ee1b1"
        );
    }

    #[test]
    fn another_master_or_another_wallet_is_another_key() {
        let key = tee_key(&[9; 32], "a1b2c3").to_bytes();
        assert_ne!(key, tee_key(&[8; 32], "a1b2c3").to_bytes());
        assert_ne!(key, tee_key(&[9; 32], "a1b2c4").to_bytes());
    }

    #[test]
    fn the_agent_key_follows_from_the_signature_the_owner_and_the_wallet() {
        let key = agent_key(&[7; 64], "alice.near", "a1b2c3").to_bytes();
        assert_eq!(key, agent_key(&[7; 64], "alice.near", "a1b2c3").to_bytes());
        assert_ne!(key, agent_key(&[8; 64], "alice.near", "a1b2c3").to_bytes());
        assert_ne!(key, agent_key(&[7; 64], "bob.near", "a1b2c3").to_bytes());
        assert_ne!(key, agent_key(&[7; 64], "alice.near", "a1b2c4").to_bytes());
        assert_eq!(AGENT_KEY_NONCE.len(), 32);
        assert!(agent_key_message("alice.near", "a1b2c3").ends_with("Owner: alice.near\nWallet: a1b2c3"));
    }
}
