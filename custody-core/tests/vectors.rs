//! The vectors other implementations check themselves against
//! (`vectors/messages.json`, `vectors/agent_request.json`): made by this
//! crate, held in the repository, and compared here on every run. Set
//! `UPDATE_VECTORS=1` to write them after a deliberate change.

use custody_core::{
    agent_request::{AgentRequest, OPERATION_METHOD, OPERATION_PATH},
    halves::{proof, sign_half, PublicKeyPair, Role},
    keys::{agent_key, agent_key_message, tee_key, tee_key_seed, AGENT_KEY_NONCE, AGENT_KEY_RECIPIENT},
    message::RequestMessage,
    moves::{build, Context, Move},
};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

const AGENT_SEED: [u8; 32] = [0xa1; 32];
const TEE_SEED: [u8; 32] = [0xe2; 32];

fn held(name: &str, made: &Value) {
    let path = format!("{}/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = format!("{}\n", serde_json::to_string_pretty(made).unwrap());
    if std::env::var_os("UPDATE_VECTORS").is_some() {
        std::fs::write(&path, &text).unwrap();
    }
    let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(on_disk, text, "{name} is not what this crate makes; run with UPDATE_VECTORS=1 if the change is meant");
}

fn ctx(nonce: u32) -> Context {
    Context {
        chain_id: "mainnet".to_string(),
        wallet_contract: "trader.alice.near".to_string(),
        intents_contract: "intents.near".to_string(),
        nonce,
        created_at_ns: 1_800_000_000_123_456_789,
    }
}

fn moves() -> Vec<(&'static str, Move)> {
    vec![
        ("a transfer of NEAR", Move::NearTransfer { to: "bob.near".to_string(), amount: 1_000_000_000_000_000_000_000_000 }),
        (
            "a call",
            Move::Call {
                to: "app.near".to_string(),
                method: "do_it".to_string(),
                args: br#"{"x":1}"#.to_vec(),
                gas: 30_000_000_000_000,
                deposit: 1,
            },
        ),
        (
            "a call with empty arguments and the largest numbers",
            Move::Call { to: "f".repeat(64), method: "m".to_string(), args: Vec::new(), gas: 250_000_000_000_000, deposit: u128::MAX },
        ),
        (
            "a transfer inside NEAR Intents",
            Move::IntentsTransfer { to: "0".repeat(64), token_id: "nep141:wrap.near".to_string(), amount: 5_000 },
        ),
        (
            "a withdrawal from NEAR Intents to NEAR",
            Move::IntentsWithdraw { token: "usdt.tether-token.near".to_string(), to: "bob.near".to_string(), amount: 7 },
        ),
    ]
}

#[test]
fn messages() {
    let agent = SigningKey::from_bytes(&AGENT_SEED);
    let tee = SigningKey::from_bytes(&TEE_SEED);
    let pair = PublicKeyPair { agent: agent.verifying_key().to_bytes(), tee: tee.verifying_key().to_bytes() };

    let cases: Vec<Value> = moves()
        .into_iter()
        .enumerate()
        .map(|(i, (name, mv))| {
            let msg: RequestMessage = build(&mv, &ctx(i as u32)).unwrap();
            let (a, e) = (sign_half(Role::Agent, &agent, &msg), sign_half(Role::Tee, &tee, &msg));
            assert!(pair.verify(&msg, &proof(&a, &e)));
            json!({
                "name": name,
                "message": msg,
                "borsh": hex::encode(msg.to_borsh()),
                "hash": hex::encode(msg.hash()),
                "contract_json": msg.to_json(),
                "agent_half": hex::encode(a),
                "tee_half": hex::encode(e),
            })
        })
        .collect();
    held(
        "messages.json",
        &json!({
            "agent_seed": hex::encode(AGENT_SEED),
            "tee_seed": hex::encode(TEE_SEED),
            "public_key": pair.to_string(),
            "cases": cases,
        }),
    );
}

#[test]
fn agent_requests() {
    let agent = SigningKey::from_bytes(&AGENT_SEED);
    let requests = [
        AgentRequest {
            wallet_contract: "trader.alice.near",
            method: OPERATION_METHOD,
            path: OPERATION_PATH,
            body: br#"{"id":"pay-1","op":{"kind":"transfer","to":"bob.near","amount":"5"}}"#,
            timestamp: 1_800_000_000,
            nonce: [7; 16],
        },
        AgentRequest {
            wallet_contract: "trader.alice.near",
            method: "GET",
            path: "/wallet/contract/v1/operations/pay-1",
            body: b"",
            timestamp: 1_800_000_001,
            nonce: [0; 16],
        },
    ];
    let cases: Vec<Value> = requests
        .iter()
        .map(|request| {
            json!({
                "wallet_contract": request.wallet_contract,
                "method": request.method,
                "path": request.path,
                "body": String::from_utf8(request.body.to_vec()).unwrap(),
                "timestamp": request.timestamp,
                "nonce": hex::encode(request.nonce),
                "signed_bytes": hex::encode(request.signed_bytes()),
                "signature": hex::encode(request.sign(&agent)),
            })
        })
        .collect();
    held(
        "agent_request.json",
        &json!({
            "agent_seed": hex::encode(AGENT_SEED),
            "agent_public_key": hex::encode(agent.verifying_key().to_bytes()),
            "cases": cases,
        }),
    );
}

#[test]
fn keys() {
    let (owner, wallet_id) = ("alice.near", "7c9e6679-7425-40de-944b-e07fc1f90ae7");
    let owner_master = [0x4d; 32];
    let signature = [0x51; 64];
    held(
        "keys.json",
        &json!({
            "owner": owner,
            "wallet_id": wallet_id,
            "tee": {
                "owner_master": hex::encode(owner_master),
                "derivation": tee_key_seed(wallet_id),
                "public_key": hex::encode(tee_key(&owner_master, wallet_id).verifying_key().to_bytes()),
            },
            "agent": {
                "nep413_recipient": AGENT_KEY_RECIPIENT,
                "nep413_nonce": hex::encode(AGENT_KEY_NONCE),
                "nep413_message": agent_key_message(owner, wallet_id),
                "signature": hex::encode(signature),
                "seed": hex::encode(agent_key(&signature, owner, wallet_id).to_bytes()),
                "public_key": hex::encode(agent_key(&signature, owner, wallet_id).verifying_key().to_bytes()),
            },
        }),
    );
}
