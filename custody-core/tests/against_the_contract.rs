//! This crate's bytes against the contract's own code: the same message
//! hashes the same on both sides, and the contract's verifier accepts the
//! proof made here and nothing less.

use std::time::Duration;

use custody_core::{
    halves::{proof, sign_half, verify_half, PublicKeyPair, Role},
    message::{Action, Promise, RequestMessage},
    TIMEOUT_SECS,
};
use defuse_wallet::{
    actions::FunctionCall, AccountId, Gas, NearPromise, NearToken, Request, SignatureSchema,
    Timestamp,
};
use defuse_wallet_two_key::{crypto::ed25519::Ed25519PublicKey, TwoKeyPublicKey, WalletTwoKey};
use ed25519_dalek::SigningKey;

/// The contract's message for the same request.
fn upstream(msg: &RequestMessage) -> defuse_wallet::RequestMessage {
    let promise = NearPromise::new(msg.promise.receiver_id.parse::<AccountId>().unwrap());
    let promise = match &msg.promise.action {
        Action::FunctionCall { function_name, args, deposit, gas } => {
            promise.function_call(FunctionCall {
                function_name: function_name.clone(),
                args: args.clone(),
                deposit: NearToken::from_yoctonear(*deposit),
                gas: Gas::from_gas(*gas),
                gas_weight: 0,
            })
        }
        Action::Transfer { amount } => promise.transfer(NearToken::from_yoctonear(*amount)),
    };
    defuse_wallet::RequestMessage {
        pay_for_gas: false,
        chain_id: msg.chain_id.clone(),
        signer_id: msg.signer_id.parse().unwrap(),
        nonce: msg.nonce,
        created_at: Timestamp::from_nanos(msg.created_at_ns.into()).unwrap(),
        timeout: Duration::from_secs(TIMEOUT_SECS.into()),
        request: Request::new().external([promise]),
    }
}

/// A deterministic stream of numbers, so the messages differ and a failure
/// repeats.
struct Numbers(u64);

impl Numbers {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }

    fn account(&mut self) -> String {
        match self.next() % 3 {
            0 => format!("a{}.near", self.next() % 1_000_000),
            1 => format!("sub-{}.owner_{}.testnet", self.next() % 100, self.next() % 100),
            _ => format!("{:064x}", u128::from(self.next()) * u128::from(self.next())),
        }
    }

    fn message(&mut self) -> RequestMessage {
        let action = if self.next().is_multiple_of(3) {
            Action::Transfer { amount: u128::from(self.next()) * u128::from(self.next()) }
        } else {
            Action::FunctionCall {
                function_name: format!("method_{}", self.next() % 50),
                args: (0..self.next() % 300).map(|_| self.next() as u8).collect(),
                deposit: u128::from(self.next() % 3) * u128::from(self.next()),
                gas: self.next() % 300_000_000_000_000,
            }
        };
        RequestMessage {
            chain_id: ["mainnet", "testnet"][(self.next() % 2) as usize].to_string(),
            signer_id: self.account(),
            nonce: self.next() as u32,
            created_at_ns: self.next() * 1_000,
            promise: Promise { receiver_id: self.account(), action },
        }
    }
}

fn messages() -> Vec<RequestMessage> {
    let mut numbers = Numbers(7);
    let mut messages: Vec<_> = (0..500).map(|_| numbers.message()).collect();
    // the edges of each field
    messages.push(RequestMessage {
        chain_id: String::new(),
        signer_id: "aa".to_string(),
        nonce: 0,
        created_at_ns: 0,
        promise: Promise { receiver_id: "bb".to_string(), action: Action::Transfer { amount: 0 } },
    });
    messages.push(RequestMessage {
        chain_id: "mainnet".to_string(),
        signer_id: "f".repeat(64),
        nonce: u32::MAX,
        created_at_ns: i64::MAX as u64,
        promise: Promise {
            receiver_id: "e".repeat(64),
            action: Action::FunctionCall {
                function_name: String::new(),
                args: Vec::new(),
                deposit: u128::MAX,
                gas: u64::MAX,
            },
        },
    });
    messages
}

#[test]
fn a_message_encodes_and_hashes_as_the_contracts() {
    for msg in messages() {
        let theirs = upstream(&msg);
        assert_eq!(msg.to_borsh(), borsh::to_vec(&theirs).unwrap(), "{msg:?}");
        assert_eq!(msg.hash(), theirs.hash(), "{msg:?}");
    }
}

#[test]
fn the_contract_accepts_the_proof_made_here_and_no_part_of_it() {
    let agent = SigningKey::from_bytes(&[3; 32]);
    let tee = SigningKey::from_bytes(&[4; 32]);
    let pair = PublicKeyPair {
        agent: agent.verifying_key().to_bytes(),
        tee: tee.verifying_key().to_bytes(),
    };
    let theirs_pair = TwoKeyPublicKey {
        agent: Ed25519PublicKey(pair.agent),
        tee: Ed25519PublicKey(pair.tee),
    };
    assert_eq!(pair.to_string(), theirs_pair.to_string());
    assert_eq!(pair.to_string().parse::<TwoKeyPublicKey>(), Ok(theirs_pair));

    for msg in messages().into_iter().take(50) {
        let theirs = upstream(&msg);
        let a = sign_half(Role::Agent, &agent, &msg);
        let e = sign_half(Role::Tee, &tee, &msg);
        let accepts = |proof: &str| WalletTwoKey::verify_request_msg(&theirs_pair, &theirs, proof);

        let both = proof(&a, &e);
        assert!(accepts(&both));
        assert!(pair.verify(&msg, &both));
        assert!(verify_half(Role::Agent, &pair.agent, &msg, &a));
        assert!(verify_half(Role::Tee, &pair.tee, &msg, &e));

        for refused in [
            proof(&e, &a),
            proof(&a, &a),
            proof(&e, &e),
            hex::encode(a),
            hex::encode(e),
            // each key under the other's role
            proof(&sign_half(Role::Tee, &agent, &msg), &sign_half(Role::Agent, &tee, &msg)),
        ] {
            assert!(!accepts(&refused));
            assert!(!pair.verify(&msg, &refused));
        }
        assert!(!verify_half(Role::Tee, &pair.agent, &msg, &a));
        assert!(!verify_half(Role::Agent, &pair.tee, &msg, &e));

        // a proof of one message is not a proof of another
        let mut other = msg.clone();
        other.nonce = other.nonce.wrapping_add(1);
        assert!(!pair.verify(&other, &both));
        assert!(!WalletTwoKey::verify_request_msg(&theirs_pair, &upstream(&other), &both));
    }
}
