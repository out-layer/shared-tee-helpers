//! Agent On-chain custody: the bytes that are signed for a wallet contract of
//! the two-key standard, and the rules about it that are pure.
//!
//! Nothing here does I/O: no HTTP, no RPC, no clock, no randomness. The
//! keystore, the coordinator, the CLI and the owner's recovery tool all build
//! on this crate, so there is one implementation of each byte format.

pub mod admit;
pub mod agent_request;
pub mod deterministic;
pub mod halves;
pub mod keys;
pub mod message;
pub mod moves;
pub mod text;

/// What the agent's key signs for a move: this prefix, then the 32 bytes of
/// the request's hash. The same constant is in the contract.
pub const AGENT_PREFIX: &[u8] = b"NEAR_WALLET_TWO_KEY/V1/AGENT";

/// What the TEE's key signs for a move: this prefix, then the 32 bytes of the
/// request's hash. The same constant is in the contract.
pub const TEE_PREFIX: &[u8] = b"NEAR_WALLET_TWO_KEY/V1/TEE";

/// The wallet contract's prefix of a request's canonical hash.
pub const REQUEST_DOMAIN: &[u8] = b"NEAR_WALLET_CONTRACT/V1";

/// How long a request stays valid after `created_at`, in seconds. Every
/// request carries it, and the wallet contract accepts a request for the
/// shorter of this and its own timeout (an hour). Ten minutes: a half the
/// enclave gave out cannot be taken back, so a freeze or a change of policy
/// leaves a prepared request usable for no longer than this; it is also how
/// long a 1Click quote waits for its deposit.
pub const TIMEOUT_SECS: u32 = 600;

/// The codes the enclave attaches to a refusal that is not the policy's, so
/// the API in front of it can answer each as what it is.
pub mod refusal {
    /// The owner froze the wallet.
    pub const WALLET_FROZEN: &str = "wallet_frozen";
    /// A signature is not what it has to be: the agent's over its request, or
    /// the two halves over the wallet contract's request.
    pub const INVALID_SIGNATURE: &str = "invalid_signature";
    /// The account is not served as this wallet's wallet contract: it runs
    /// no approved build, has an extension, has signatures switched off, or
    /// its pair does not hold this wallet's key.
    pub const WALLET_CONTRACT_REFUSED: &str = "wallet_contract_refused";
}
