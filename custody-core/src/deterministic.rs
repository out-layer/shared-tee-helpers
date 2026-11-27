//! A wallet contract at its deterministic address (NEP-616).
//!
//! An account created by a `DeterministicStateInit` action is named after its
//! first state: `"0s" + hex(keccak256(borsh(state_init))[12..32])`, where
//! `state_init` names the global contract by its code hash and holds the
//! contract's storage. Such an account has no access key; its code and its
//! state are what the address commits to.
//!
//! The state here is the two-key contract's `State::new(pair)`: signatures on,
//! sub-wallet 0, the pair, the contract's default timeout, no nonce yet, no
//! extension. So an account whose address is [`deterministic_account`] of a
//! pair was created as a fresh wallet contract of that pair and nothing else:
//! no extension in its first state, no other signer. That is what the setup
//! takes such an account for. What the account holds later is read from the
//! chain by `admit`, as for every wallet contract.
//!
//! The bytes are held to the fork's own `State` and to near-kit's
//! `derive_deterministic_account_id` by `vectors/deterministic.json`, which
//! includes a wallet contract created this way on testnet.

use sha3::{Digest, Keccak256};

use crate::halves::PublicKeyPair;

/// The two-key contract's default timeout, in seconds: what `State::new`
/// writes, the same as `w_init`. A request still carries
/// [`crate::TIMEOUT_SECS`]; the contract takes the smaller of the two.
pub const CONTRACT_DEFAULT_TIMEOUT_SECS: u32 = 3600;

/// The contract's storage key of its state.
const STATE_KEY: &[u8] = b"";

/// The Borsh of the two-key contract's `State::new(pair)`.
pub fn state_bytes(pair: &PublicKeyPair) -> Vec<u8> {
    let mut out = Vec::with_capacity(93);
    out.push(1); // signature_enabled
    out.extend_from_slice(&0u32.to_le_bytes()); // subwallet_id
    out.extend_from_slice(&pair.agent);
    out.extend_from_slice(&pair.tee);
    out.extend_from_slice(&CONTRACT_DEFAULT_TIMEOUT_SECS.to_le_bytes()); // nonces.timeout
    out.extend_from_slice(&0u64.to_le_bytes()); // nonces.last_cleaned_at
    out.extend_from_slice(&0u32.to_le_bytes()); // nonces.old: empty
    out.extend_from_slice(&0u32.to_le_bytes()); // nonces.current: empty
    out.extend_from_slice(&0u32.to_le_bytes()); // extensions: none
    out
}

/// The Borsh of `StateInit::V1 { code: CodeHash(code_hash), data: { "": state } }`:
/// the bytes the address is the hash of, and the `state_init` of the action.
pub fn state_init_bytes(code_hash: &[u8; 32], pair: &PublicKeyPair) -> Vec<u8> {
    let state = state_bytes(pair);
    let mut out = Vec::with_capacity(46 + state.len());
    out.push(0); // StateInit::V1
    out.push(0); // GlobalContractId::CodeHash
    out.extend_from_slice(code_hash);
    out.extend_from_slice(&1u32.to_le_bytes()); // one storage entry
    out.extend_from_slice(&(STATE_KEY.len() as u32).to_le_bytes());
    out.extend_from_slice(STATE_KEY);
    out.extend_from_slice(&(state.len() as u32).to_le_bytes());
    out.extend_from_slice(&state);
    out
}

/// The `0s` account of a fresh wallet contract of `pair` on the build
/// `code_hash`.
pub fn deterministic_account(code_hash: &[u8; 32], pair: &PublicKeyPair) -> String {
    let hash: [u8; 32] = Keccak256::digest(state_init_bytes(code_hash, pair)).into();
    format!("0s{}", hex::encode(&hash[12..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Case {
        name: String,
        pair: String,
        state: String,
        state_init: String,
        account_id: String,
    }
    #[derive(serde::Deserialize)]
    struct Vectors {
        code_hash_hex: String,
        cases: Vec<Case>,
    }

    fn vectors() -> Vectors {
        serde_json::from_str(include_str!("../vectors/deterministic.json")).expect("the vector file")
    }

    /// The pair as bytes: the live account's are random bytes, not points.
    fn raw(pair: &str) -> PublicKeyPair {
        let bytes: [u8; 64] = crate::text::hex(pair).expect("64 bytes in hex");
        PublicKeyPair { agent: bytes[..32].try_into().unwrap(), tee: bytes[32..].try_into().unwrap() }
    }

    fn code_hash() -> [u8; 32] {
        crate::text::hex(&vectors().code_hash_hex).expect("32 bytes in hex")
    }

    #[test]
    fn the_vectors_are_the_forks_state_and_near_kits_address() {
        let v = vectors();
        assert_eq!(v.cases.len(), 3);
        for case in &v.cases {
            let pair = raw(&case.pair);
            assert_eq!(hex::encode(state_bytes(&pair)), case.state, "{}: state", case.name);
            assert_eq!(hex::encode(state_init_bytes(&code_hash(), &pair)), case.state_init, "{}: state_init", case.name);
            assert_eq!(deterministic_account(&code_hash(), &pair), case.account_id, "{}: address", case.name);
        }
        assert!(v.cases.iter().any(|c| c.account_id == "0scaf38f4da73c18308919d2f94e5445cd4131e2a5"));
    }

    /// The state is the contract's own: the fork's `State::new` of the pair,
    /// in the two-key standard's key type, for the vectors whose pair is two
    /// keys.
    #[test]
    fn the_state_is_the_contracts_state_new() {
        for case in vectors().cases.iter().filter(|c| !c.name.contains("random bytes")) {
            let pair = PublicKeyPair::parse(&case.pair).expect("two keys");
            let key: defuse_wallet_two_key::TwoKeyPublicKey = case.pair.parse().expect("the two-key text form");
            let contracts = borsh::to_vec(&defuse_wallet::State::new(key)).unwrap();
            assert_eq!(contracts, state_bytes(&pair), "{}", case.name);
        }
    }

    /// Every field the address commits to changes it: another pair, another
    /// build, or any other first state (signatures off, an extension) is
    /// another account.
    #[test]
    fn the_address_commits_to_the_build_and_the_whole_first_state() {
        let pair = PublicKeyPair::parse(&vectors().cases[0].pair).expect("two keys");
        let base = deterministic_account(&code_hash(), &pair);

        let swapped = PublicKeyPair { agent: pair.tee, tee: pair.agent };
        assert_ne!(deterministic_account(&code_hash(), &swapped), base);
        let mut other_build = code_hash();
        other_build[0] ^= 1;
        assert_ne!(deterministic_account(&other_build, &pair), base);

        let hash_of = |state_init: &[u8]| -> String {
            let h: [u8; 32] = Keccak256::digest(state_init).into();
            format!("0s{}", hex::encode(&h[12..]))
        };
        let standard = state_init_bytes(&code_hash(), &pair);
        assert_eq!(hash_of(&standard), base);
        // the state starts at byte 46, after the tags, the code hash, the
        // entry count, the empty key and the value's length
        let mut off = standard.clone();
        off[46] = 0; // signatures off
        assert_ne!(hash_of(&off), base);
        let mut with_extension = standard[..standard.len() - 4].to_vec();
        with_extension.extend_from_slice(&1u32.to_le_bytes());
        with_extension.extend_from_slice(&4u32.to_le_bytes());
        with_extension.extend_from_slice(b"evil");
        with_extension[42..46].copy_from_slice(&(93u32 + 8).to_le_bytes());
        assert_ne!(hash_of(&with_extension), base);
    }
}
