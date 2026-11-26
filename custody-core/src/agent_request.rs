//! An HTTPS request signed by the agent's key.
//!
//! The agent's key signs two things, in two byte formats: a request to the
//! API (here), and its half of a move ([`crate::halves`]). The bytes of a
//! request start with their own domain, so a signature over one is never
//! valid as the other.

use borsh::BorshSerialize;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// The first bytes of what the agent's key signs for a request.
pub const AGENT_REQUEST_DOMAIN: &[u8] = b"OUTLAYER_AGENT_REQUEST/V1";

/// How far a request's timestamp may be from the verifier's clock, either
/// way, in seconds.
pub const MAX_CLOCK_DISTANCE_SECS: u64 = 120;

/// The request that asks for an operation of the wallet contract: `POST` to
/// this path, the body the operation in JSON.
pub const OPERATION_METHOD: &str = "POST";
pub const OPERATION_PATH: &str = "/wallet/contract/v1/operations";

/// What a signature over a request covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRequest<'a> {
    /// The wallet contract's account: the agent the request is made as.
    pub wallet_contract: &'a str,
    /// In capitals: `POST`.
    pub method: &'a str,
    /// The path with its query, as sent: `/wallet/contract/v1/operations`.
    pub path: &'a str,
    /// The body as sent; empty when there is none.
    pub body: &'a [u8],
    /// Seconds since the Unix epoch, by the agent's clock.
    pub timestamp: u64,
    /// The agent's choice; a verifier accepts each once.
    pub nonce: [u8; 16],
}

impl AgentRequest<'_> {
    /// The bytes the agent's key signs: the domain, then the Borsh encoding
    /// of the account, the method, the path, the body's SHA-256, the
    /// timestamp and the nonce.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut bytes = AGENT_REQUEST_DOMAIN.to_vec();
        let body: [u8; 32] = Sha256::digest(self.body).into();
        (self.wallet_contract, self.method, self.path, body, self.timestamp, self.nonce)
            .serialize(&mut bytes)
            .expect("borsh: writing to a Vec does not fail");
        bytes
    }

    pub fn sign(&self, key: &SigningKey) -> [u8; 64] {
        key.sign(&self.signed_bytes()).to_bytes()
    }

    /// Whether `signature` is the agent's over this request, and the
    /// request's timestamp is within [`MAX_CLOCK_DISTANCE_SECS`] of `now`
    /// (seconds since the Unix epoch). That the nonce is new is the caller's
    /// to check.
    pub fn verify(&self, agent: &[u8; 32], signature: &[u8; 64], now: u64) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(agent) else {
            return false;
        };
        self.timestamp.abs_diff(now) <= MAX_CLOCK_DISTANCE_SECS
            && key.verify_strict(&self.signed_bytes(), &Signature::from_bytes(signature)).is_ok()
    }
}

/// A signed request as one service hands it to another: the parts the agent
/// sent, with the account it names left to the receiver, which knows the
/// wallet contract it is serving.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAgentRequest {
    pub method: String,
    pub path: String,
    /// The body, byte for byte as the agent sent it.
    pub body: String,
    pub timestamp: u64,
    /// 16 bytes in lowercase hex.
    pub nonce: String,
    /// 64 bytes in lowercase hex.
    pub signature: String,
}

/// Why a [`SignedAgentRequest`] is not the agent's.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotSigned {
    /// The field is not the bytes it should be, in lowercase hex.
    Field(&'static str),
    /// The signature is not the agent's over this request, or the request's
    /// timestamp is not the current time.
    Signature,
}

#[cfg(feature = "serde")]
impl std::fmt::Display for NotSigned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Field("nonce") => f.write_str("the request's nonce is not 16 bytes in lowercase hex"),
            Self::Field(field) => write!(f, "the request's {field} is not 64 bytes in lowercase hex"),
            Self::Signature => f.write_str(
                "the request is not signed by the agent's key of this wallet contract, or its \
                 timestamp is not the current time",
            ),
        }
    }
}

#[cfg(feature = "serde")]
impl SignedAgentRequest {
    /// The request, when it was signed by `agent` as `wallet_contract` and its
    /// timestamp is within [`MAX_CLOCK_DISTANCE_SECS`] of `now`. That the
    /// nonce is new is the caller's to check.
    pub fn verified<'a>(
        &'a self,
        wallet_contract: &'a str,
        agent: &[u8; 32],
        now: u64,
    ) -> Result<AgentRequest<'a>, NotSigned> {
        let request = AgentRequest {
            wallet_contract,
            method: &self.method,
            path: &self.path,
            body: self.body.as_bytes(),
            timestamp: self.timestamp,
            nonce: crate::text::hex(&self.nonce).ok_or(NotSigned::Field("nonce"))?,
        };
        let signature = crate::text::hex(&self.signature).ok_or(NotSigned::Field("signature"))?;
        if !request.verify(agent, &signature, now) {
            return Err(NotSigned::Signature);
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        halves::{verify_half, Role},
        message::{Action, Promise, RequestMessage},
        AGENT_PREFIX, TEE_PREFIX,
    };

    const NOW: u64 = 1_800_000_000;

    fn request() -> AgentRequest<'static> {
        AgentRequest {
            wallet_contract: "trader.alice.near",
            method: OPERATION_METHOD,
            path: OPERATION_PATH,
            body: br#"{"kind":"transfer","to":"bob.near","amount":"1"}"#,
            timestamp: NOW,
            nonce: [7; 16],
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[5; 32])
    }

    #[test]
    fn a_signed_request_verifies() {
        let signature = request().sign(&key());
        assert!(request().verify(&key().verifying_key().to_bytes(), &signature, NOW));
    }

    #[test]
    fn a_change_of_any_field_fails() {
        let agent = key().verifying_key().to_bytes();
        let signature = request().sign(&key());

        let changed = [
            AgentRequest { wallet_contract: "trader.bob.near", ..request() },
            AgentRequest { method: "GET", ..request() },
            AgentRequest { path: "/wallet/contract/v1/operations?x=1", ..request() },
            AgentRequest { body: br#"{"kind":"transfer","to":"bob.near","amount":"2"}"#, ..request() },
            AgentRequest { body: b"", ..request() },
            AgentRequest { timestamp: NOW + 1, ..request() },
            AgentRequest { nonce: [8; 16], ..request() },
        ];
        for request in changed {
            assert!(!request.verify(&agent, &signature, NOW), "{request:?}");
        }

        let other = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
        assert!(!request().verify(&other, &signature, NOW));
    }

    #[test]
    fn fields_do_not_run_into_each_other() {
        let a = AgentRequest { method: "POST", path: "/a", ..request() };
        let b = AgentRequest { method: "POST/", path: "a", ..request() };
        assert_ne!(a.signed_bytes(), b.signed_bytes());
    }

    #[test]
    fn a_request_is_valid_only_near_its_timestamp() {
        let agent = key().verifying_key().to_bytes();
        let signature = request().sign(&key());

        for (now, valid) in [
            (NOW, true),
            (NOW + MAX_CLOCK_DISTANCE_SECS, true),
            (NOW - MAX_CLOCK_DISTANCE_SECS, true),
            (NOW + MAX_CLOCK_DISTANCE_SECS + 1, false),
            (NOW - MAX_CLOCK_DISTANCE_SECS - 1, false),
            (0, false),
            (u64::MAX, false),
        ] {
            assert_eq!(request().verify(&agent, &signature, now), valid, "{now}");
        }
    }

    /// A signature over a request is not a half of a move, whatever the
    /// request says: the bytes start with another domain and are longer than
    /// any half's.
    #[test]
    fn a_request_is_never_a_half() {
        let longest_half = AGENT_PREFIX.len().max(TEE_PREFIX.len()) + 32;
        let smallest = AgentRequest {
            wallet_contract: "",
            method: "",
            path: "",
            body: b"",
            timestamp: 0,
            nonce: [0; 16],
        };
        for request in [request(), smallest] {
            let bytes = request.signed_bytes();
            assert!(!bytes.starts_with(AGENT_PREFIX) && !bytes.starts_with(TEE_PREFIX));
            assert!(bytes.len() > longest_half);
        }

        let msg = RequestMessage {
            chain_id: "mainnet".to_string(),
            signer_id: "trader.alice.near".to_string(),
            nonce: 0,
            created_at_ns: NOW * 1_000_000_000,
            promise: Promise {
                receiver_id: "bob.near".to_string(),
                action: Action::Transfer { amount: 1 },
            },
        };
        let signature = request().sign(&key());
        let agent = key().verifying_key().to_bytes();
        assert!(!verify_half(Role::Agent, &agent, &msg, &signature));
        assert!(!verify_half(Role::Tee, &agent, &msg, &signature));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_handed_on_request_is_verified_from_its_text() {
        let agent = key().verifying_key().to_bytes();
        let request = || AgentRequest { nonce: [0xab; 16], ..request() };
        let handed = SignedAgentRequest {
            method: OPERATION_METHOD.to_string(),
            path: OPERATION_PATH.to_string(),
            body: String::from_utf8(request().body.to_vec()).unwrap(),
            timestamp: NOW,
            nonce: hex::encode(request().nonce),
            signature: hex::encode(request().sign(&key())),
        };
        assert_eq!(handed.verified("trader.alice.near", &agent, NOW), Ok(request()));

        // as another wallet contract, by another key, at another time
        assert_eq!(handed.verified("trader.bob.near", &agent, NOW), Err(NotSigned::Signature));
        assert_eq!(handed.verified("trader.alice.near", &[9; 32], NOW), Err(NotSigned::Signature));
        assert_eq!(
            handed.verified("trader.alice.near", &agent, NOW + MAX_CLOCK_DISTANCE_SECS + 1),
            Err(NotSigned::Signature)
        );

        // the same bytes in another spelling are not the request
        let capitals = SignedAgentRequest { nonce: handed.nonce.to_uppercase(), ..handed.clone() };
        assert_eq!(capitals.verified("trader.alice.near", &agent, NOW), Err(NotSigned::Field("nonce")));
        let capitals = SignedAgentRequest { signature: handed.signature.to_uppercase(), ..handed.clone() };
        assert_eq!(capitals.verified("trader.alice.near", &agent, NOW), Err(NotSigned::Field("signature")));
        let short = SignedAgentRequest { nonce: handed.nonce[2..].to_string(), ..handed };
        assert_eq!(short.verified("trader.alice.near", &agent, NOW), Err(NotSigned::Field("nonce")));
    }
}
