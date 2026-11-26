//! Agent On-chain custody: the bytes that are signed for a wallet contract of
//! the two-key standard, and the rules about it that are pure.
//!
//! Nothing here does I/O: no HTTP, no RPC, no clock, no randomness. The
//! keystore, the coordinator, the CLI and the owner's recovery tool all build
//! on this crate, so there is one implementation of each byte format.

pub mod halves;
pub mod message;

/// What the agent's key signs for a move: this prefix, then the 32 bytes of
/// the request's hash. The same constant is in the contract.
pub const AGENT_PREFIX: &[u8] = b"NEAR_WALLET_TWO_KEY/V1/AGENT";

/// What the TEE's key signs for a move: this prefix, then the 32 bytes of the
/// request's hash. The same constant is in the contract.
pub const TEE_PREFIX: &[u8] = b"NEAR_WALLET_TWO_KEY/V1/TEE";

/// The wallet contract's prefix of a request's canonical hash.
pub const REQUEST_DOMAIN: &[u8] = b"NEAR_WALLET_CONTRACT/V1";

/// How long a request stays valid after `created_at`, in seconds: the
/// contract's default timeout, which `w_init` of the two-key standard sets.
pub const TIMEOUT_SECS: u32 = 3600;

/// Strict lowercase hex of exactly `N` bytes.
pub(crate) fn decode_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(s, &mut bytes).ok()?;
    Some(bytes)
}
