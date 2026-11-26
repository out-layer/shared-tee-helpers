//! The two signatures of a move, and the pair of keys they are checked
//! against.
//!
//! A half is an Ed25519 signature over a role prefix and the request's hash.
//! No function here signs a bare hash: a half is made over a
//! [`RequestMessage`], so the one who signs has the message.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{decode_hex, message::RequestMessage, AGENT_PREFIX, TEE_PREFIX};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Agent,
    Tee,
}

impl Role {
    const fn prefix(self) -> &'static [u8] {
        match self {
            Self::Agent => AGENT_PREFIX,
            Self::Tee => TEE_PREFIX,
        }
    }
}

fn signed_bytes(role: Role, hash: &[u8; 32]) -> Vec<u8> {
    [role.prefix(), hash].concat()
}

/// The half of `role` over `msg`.
pub fn sign_half(role: Role, key: &SigningKey, msg: &RequestMessage) -> [u8; 64] {
    key.sign(&signed_bytes(role, &msg.hash())).to_bytes()
}

fn verify_half_over_hash(
    role: Role,
    public_key: &[u8; 32],
    hash: &[u8; 32],
    half: &[u8; 64],
) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    // `verify_strict` refuses a key of low order
    key.verify_strict(&signed_bytes(role, hash), &Signature::from_bytes(half)).is_ok()
}

/// Whether `half` is the signature of `role` over `msg` by `public_key`.
pub fn verify_half(
    role: Role,
    public_key: &[u8; 32],
    msg: &RequestMessage,
    half: &[u8; 64],
) -> bool {
    verify_half_over_hash(role, public_key, &msg.hash(), half)
}

/// The proof the contract takes: `agent ‖ tee`, 256 characters of lowercase
/// hex.
pub fn proof(agent: &[u8; 64], tee: &[u8; 64]) -> String {
    hex::encode([agent.as_slice(), tee].concat())
}

/// The pair of public keys in a wallet contract's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyPair {
    pub agent: [u8; 32],
    pub tee: [u8; 32],
}

impl PublicKeyPair {
    /// From the contract's text form, `agent ‖ tee` as 128 characters of
    /// lowercase hex, as `w_public_key()` returns it and `w_init` takes it.
    /// `None` for any other text, for two equal keys, and for a key that is
    /// not a point of the curve or is of low order.
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = decode_hex::<64>(text)?;
        let pair = Self {
            agent: bytes[..32].try_into().ok()?,
            tee: bytes[32..].try_into().ok()?,
        };
        pair.is_valid().then_some(pair)
    }

    fn is_valid(&self) -> bool {
        self.agent != self.tee
            && [&self.agent, &self.tee]
                .into_iter()
                .all(|key| VerifyingKey::from_bytes(key).is_ok_and(|key| !key.is_weak()))
    }

    fn verify_over_hash(&self, hash: &[u8; 32], proof: &str) -> bool {
        let Some(bytes) = decode_hex::<128>(proof) else {
            return false;
        };
        let (Ok(agent), Ok(tee)) = (bytes[..64].try_into(), bytes[64..].try_into()) else {
            return false;
        };
        self.is_valid()
            && verify_half_over_hash(Role::Agent, &self.agent, hash, agent)
            && verify_half_over_hash(Role::Tee, &self.tee, hash, tee)
    }

    /// Whether the contract holding this pair accepts `proof` for `msg`.
    pub fn verify(&self, msg: &RequestMessage, proof: &str) -> bool {
        self.verify_over_hash(&msg.hash(), proof)
    }
}

impl fmt::Display for PublicKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", hex::encode(self.agent), hex::encode(self.tee))
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use sha2::{Digest, Sha256};

    use super::*;

    const VECTORS: &str = include_str!("../vectors/halves.json");

    #[derive(Deserialize)]
    struct Vectors {
        agent_prefix: String,
        tee_prefix: String,
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        name: String,
        public_key: String,
        public_key_valid: bool,
        hash: String,
        proof: String,
        valid: bool,
    }

    /// The file is byte-identical to the one in the contract's repository
    /// (`contracts/wallet/signatures/two-key/vectors/halves.json`), where a
    /// test holds the same hash.
    #[test]
    fn the_vectors_are_the_contracts() {
        assert_eq!(
            hex::encode(Sha256::digest(VECTORS)),
            "759bf4f31742717e1d7fa919e3a9ba9ad76810fcc725bf75e5dc13295e07fd60"
        );
    }

    #[test]
    fn vectors_verify_as_stated() {
        let vectors: Vectors = serde_json::from_str(VECTORS).unwrap();
        assert_eq!(vectors.agent_prefix.as_bytes(), AGENT_PREFIX);
        assert_eq!(vectors.tee_prefix.as_bytes(), TEE_PREFIX);
        assert!(vectors.cases.iter().any(|case| case.valid));

        for case in vectors.cases {
            let bytes = decode_hex::<64>(&case.public_key).expect(&case.name);
            let pair = PublicKeyPair {
                agent: bytes[..32].try_into().unwrap(),
                tee: bytes[32..].try_into().unwrap(),
            };
            let hash = decode_hex::<32>(&case.hash).expect(&case.name);

            assert_eq!(pair.verify_over_hash(&hash, &case.proof), case.valid, "{}", case.name);
            assert_eq!(
                PublicKeyPair::parse(&case.public_key).is_some(),
                case.public_key_valid,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn the_pair_round_trips_through_its_text() {
        let pair = PublicKeyPair {
            agent: SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
            tee: SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes(),
        };
        let text = pair.to_string();
        assert_eq!(PublicKeyPair::parse(&text), Some(pair));

        for refused in [
            text.to_uppercase(),
            format!("0x{text}"),
            format!("{text}00"),
            text[..126].to_string(),
            format!("{},{}", &text[..64], &text[64..]),
            String::new(),
        ] {
            assert_eq!(PublicKeyPair::parse(&refused), None, "{refused}");
        }
    }
}
