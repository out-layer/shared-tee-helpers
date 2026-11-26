//! The TEE's key of a wallet contract.
//!
//! It is a function of the owner's master and the wallet's id, by the
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
}
