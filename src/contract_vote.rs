//! Multisig votes, and the votes of approvers that are contract wallets.
//!
//! An approver is a NEAR account. One with access keys votes with a NEP-413
//! signature over [`vote_message`]. One without keys — a NEP-616 wallet
//! contract owned by an EVM key or a passkey — votes with an `authorization`
//! blob its own contract resolves: a view call `w_resolve_auth` on the
//! approver's account that answers the payload the blob authorizes. The vote
//! counts when that payload is, byte for byte, the same [`vote_message`] a key
//! holder would sign.
//!
//! Everything here is pure. The coordinator and the keystore make the RPC
//! calls and hand the answers to [`classify_call`], [`judge_signature_allowed`]
//! and [`judge_resolution`], so both read the chain by one rule.
//!
//! Two shapes exist, one per resolver ([`Shape`]). The coordinator decides the
//! shape from the code the approver runs (its allowlist, a table) and forwards
//! it with the vote; the keystore calls with that shape and judges the answer.
//!
//! What keeps a wrong shape from counting is the CONTRACT, not the judge: each
//! resolver panics on the other's arguments (`{path, authorization}` lacks the
//! EIP-712 `purpose` and `recipient`; `{purpose, recipient, authorization}` is
//! not a NEP-641 call). The judge alone would accept an EIP-712
//! `{"status":"RESOLVED","payload":<the message>}` read as `nep641` — it asks a
//! NEP-641 answer only for its payload and an empty `pending`.

use serde::{Deserialize, Serialize};

/// The largest `w_resolve_auth` answer that is judged at all. A real answer is
/// the payload (well under 300 bytes) in a small JSON object; anything bigger
/// is not one, and is not parsed.
pub const RESOLUTION_MAX_BYTES: usize = 4096;

/// The largest `authorization` blob accepted from a voter. A passkey blob is
/// about 1 KB (a WebAuthn assertion in JSON in JSON); an EVM blob is smaller.
pub const AUTHORIZATION_MAX_BYTES: usize = 8192;

/// Which way a vote goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteVerb {
    Approve,
    Reject,
}

impl VoteVerb {
    pub fn as_str(self) -> &'static str {
        match self {
            VoteVerb::Approve => "approve",
            VoteVerb::Reject => "reject",
        }
    }
}

/// The exact string a vote authorizes, whatever proves it: the NEP-413 message
/// a key holder signs, and the payload a contract wallet's resolver must
/// answer. Binds the vote to the approval, to THIS wallet (a vote collected
/// for wallet A cannot be replayed onto wallet B) and to the canonical request.
pub fn vote_message(verb: VoteVerb, approval_id: &str, wallet_pubkey: &str, request_hash: &str) -> String {
    format!("{}:{}:{}:{}", verb.as_str(), approval_id, wallet_pubkey, request_hash)
}

/// What a policy says about one account as an approver, read over EVERY entry
/// naming it — a policy that lists an account twice, once with a pinned key,
/// is pinned. Reading only the first entry would let the unpinned one bypass
/// the pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproverStanding<'a> {
    /// Not an approver of this policy.
    NotListed,
    /// An approver with no pinned key: its NEP-413 vote is checked against the
    /// account's keys on chain, and its contract vote is allowed.
    Unpinned,
    /// An approver pinned to these keys: a NEP-413 vote counts only when signed
    /// by one of them, and a contract vote never counts.
    Pinned(Vec<&'a str>),
}

impl ApproverStanding<'_> {
    /// Whether a NEP-413 vote signed by `public_key` may count (key ownership
    /// on chain is still checked for an unpinned approver).
    pub fn admits_key(&self, public_key: &str) -> bool {
        match self {
            ApproverStanding::NotListed => false,
            ApproverStanding::Unpinned => true,
            ApproverStanding::Pinned(keys) => keys.contains(&public_key),
        }
    }

    /// Whether a contract vote may count.
    pub fn admits_contract_vote(&self) -> bool {
        matches!(self, ApproverStanding::Unpinned)
    }
}

pub fn approver_standing<'a>(policy: &'a crate::wallet_policy::Policy, id: &str) -> ApproverStanding<'a> {
    let mut listed = false;
    let mut pins: Vec<&'a str> = Vec::new();
    for ap in policy
        .approval
        .as_ref()
        .and_then(|a| a.approvers.as_ref())
        .into_iter()
        .flatten()
    {
        if ap.id.as_deref() != Some(id) {
            continue;
        }
        listed = true;
        if let Some(key) = ap.pubkey.as_deref() {
            pins.push(key);
        }
    }
    match (listed, pins.is_empty()) {
        (false, _) => ApproverStanding::NotListed,
        (true, true) => ApproverStanding::Unpinned,
        (true, false) => ApproverStanding::Pinned(pins),
    }
}

/// The resolver a contract wallet runs, which fixes the arguments of
/// `w_resolve_auth` and the shape of its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Shape {
    /// EIP-712 owner (`near/intents` `contracts/wallet/src/signature/eip712.rs`).
    /// Args `{purpose: "PROVE_OWNERSHIP", recipient, authorization}`; answers
    /// `{"status":"RESOLVED","payload":…}`, or `{"status":"INVALID",…}` as a
    /// successful view. Does NOT check `is_signature_allowed` itself.
    Eip712,
    /// NEP-641 resolver (`near/intents` `contracts/wallet/src/contract.rs`),
    /// the passkey wallet. Args `{path: [], authorization}`; answers
    /// `{"payload":…}` plus `pending` for an extension-scoped blob; panics on
    /// a bad one.
    Nep641,
}

impl Shape {
    pub fn as_str(self) -> &'static str {
        match self {
            Shape::Eip712 => "eip712",
            Shape::Nep641 => "nep641",
        }
    }

    /// The stored spelling back to a shape; any other spelling is no shape.
    pub fn parse(s: &str) -> Option<Shape> {
        match s {
            "eip712" => Some(Shape::Eip712),
            "nep641" => Some(Shape::Nep641),
            _ => None,
        }
    }
}

/// The `w_resolve_auth` arguments for `shape`. `recipient` is the caller's OWN
/// contract id — the keystore's from its config, never one it was sent: the
/// EIP-712 resolver checks the blob was signed for this recipient, and that is
/// only worth something if the recipient is ours.
pub fn resolve_args(shape: Shape, recipient: &str, authorization: &str) -> serde_json::Value {
    match shape {
        Shape::Eip712 => serde_json::json!({
            "purpose": "PROVE_OWNERSHIP",
            "recipient": recipient,
            "authorization": authorization,
        }),
        Shape::Nep641 => serde_json::json!({
            "path": [],
            "authorization": authorization,
        }),
    }
}

/// What one `call_function` query answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallAnswer {
    /// The contract returned these bytes, read at this block.
    Answered { bytes: Vec<u8>, block_hash: String },
    /// A fact about the account: it does not exist, runs no code, has no such
    /// method, or its code panicked. Asking again changes nothing.
    Refused(String),
    /// The node could not answer — transport, timeout, a block it does not
    /// have, an envelope nobody has seen. Says nothing about the account.
    Unreachable(String),
}

/// Top-level RPC errors that state a fact about the account. Everything else
/// at the top level is about the node.
const ACCOUNT_FACT_ERRORS: [&str; 4] = [
    "UNKNOWN_ACCOUNT",
    "NO_CONTRACT_CODE",
    "CONTRACT_EXECUTION_ERROR",
    "INVALID_ACCOUNT",
];

/// Classify a JSON-RPC `query` / `call_function` response.
///
/// The VM's verdict arrives in two shapes: the modern top-level
/// `CONTRACT_EXECUTION_ERROR`, and the legacy `result.error` string
/// `wasm execution failed with error: …` (panic, missing method, no code),
/// which is what the RPC we use sends. Only those exact shapes are facts; an
/// unknown one is `Unreachable`, which never counts a vote either.
pub fn classify_call(response: &serde_json::Value) -> CallAnswer {
    if let Some(error) = response.get("error") {
        let name = error
            .get("cause")
            .and_then(|c| c.get("name"))
            .and_then(|n| n.as_str())
            .or_else(|| error.get("name").and_then(|n| n.as_str()));
        let text = format!("RPC error: {error}");
        return match name {
            Some(n) if ACCOUNT_FACT_ERRORS.contains(&n) => CallAnswer::Refused(text),
            _ => CallAnswer::Unreachable(text),
        };
    }
    let Some(result) = response.get("result") else {
        return CallAnswer::Unreachable("response has neither result nor error".to_string());
    };
    if let Some(vm) = result.get("error").and_then(|e| e.as_str()) {
        return if vm.contains("wasm execution failed") {
            CallAnswer::Refused(vm.to_string())
        } else {
            CallAnswer::Unreachable(format!("result carries an error that is not the VM's: {vm}"))
        };
    }
    let block_hash = match result.get("block_hash").and_then(|h| h.as_str()) {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => return CallAnswer::Unreachable("answer names no block".to_string()),
    };
    let Some(raw) = result.get("result").and_then(|r| r.as_array()) else {
        return CallAnswer::Unreachable("answer carries no result bytes".to_string());
    };
    let mut bytes = Vec::with_capacity(raw.len());
    for b in raw {
        match b.as_u64() {
            Some(v) if v <= 255 => bytes.push(v as u8),
            _ => return CallAnswer::Unreachable("result is not a byte array".to_string()),
        }
    }
    CallAnswer::Answered { bytes, block_hash }
}

/// Why a contract vote does not count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotCounted {
    /// The wallet does not accept signatures (`w_is_signature_allowed` is not
    /// `true`).
    SignaturesDisabled,
    /// The contract refused the blob (it panicked, or the account runs no such
    /// method). Carries the contract's own words.
    Refused(String),
    /// The EIP-712 resolver answered something other than `RESOLVED`. Carries
    /// its `error_message` when it gave one.
    NotResolved(String),
    /// The resolver authorized a different payload.
    PayloadMismatch,
    /// A NEP-641 answer with sub-authorizations still to resolve: an
    /// extension-scoped blob, whose authority is another account's.
    PendingSubAuthorization,
    /// Not an answer of the shape asked for.
    Malformed(String),
}

impl NotCounted {
    /// One sentence for the voter.
    pub fn reason(&self) -> String {
        match self {
            NotCounted::SignaturesDisabled => "the approver's wallet does not accept signatures".to_string(),
            NotCounted::Refused(why) => format!("the approver's wallet refused the authorization: {why}"),
            NotCounted::NotResolved(why) => format!("the approver's wallet did not resolve the authorization: {why}"),
            NotCounted::PayloadMismatch => {
                "the authorization is valid but for a different payload than this vote".to_string()
            }
            NotCounted::PendingSubAuthorization => {
                "the authorization delegates to another account; only the wallet's own signature counts".to_string()
            }
            NotCounted::Malformed(why) => format!("the approver's wallet answered in an unexpected form: {why}"),
        }
    }
}

/// Judge a `w_is_signature_allowed()` answer: only a literal `true` lets a
/// signature-based authorization count. The EIP-712 resolver does not check
/// this flag itself, so the caller must.
pub fn judge_signature_allowed(bytes: &[u8]) -> Result<(), NotCounted> {
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(serde_json::Value::Bool(true)) => Ok(()),
        Ok(serde_json::Value::Bool(false)) => Err(NotCounted::SignaturesDisabled),
        _ => Err(NotCounted::Malformed("w_is_signature_allowed is not a boolean".to_string())),
    }
}

/// Judge a `w_resolve_auth` answer against the exact message this vote must
/// authorize.
pub fn judge_resolution(shape: Shape, bytes: &[u8], expected: &str) -> Result<(), NotCounted> {
    if bytes.len() > RESOLUTION_MAX_BYTES {
        return Err(NotCounted::Malformed(format!(
            "the answer is {} bytes, more than {RESOLUTION_MAX_BYTES}",
            bytes.len()
        )));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| NotCounted::Malformed("the answer is not JSON".to_string()))?;
    let obj = value
        .as_object()
        .ok_or_else(|| NotCounted::Malformed("the answer is not an object".to_string()))?;
    match shape {
        Shape::Eip712 => match obj.get("status").and_then(|s| s.as_str()) {
            Some("RESOLVED") => {}
            Some(other) => {
                let said = obj
                    .get("error_message")
                    .and_then(|m| m.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| other.to_string());
                return Err(NotCounted::NotResolved(said));
            }
            None => return Err(NotCounted::Malformed("no status".to_string())),
        },
        Shape::Nep641 => match obj.get("pending") {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Array(p)) if p.is_empty() => {}
            Some(serde_json::Value::Array(_)) => return Err(NotCounted::PendingSubAuthorization),
            Some(_) => return Err(NotCounted::Malformed("pending is not a list".to_string())),
        },
    }
    match obj.get("payload").and_then(|p| p.as_str()) {
        Some(p) if p == expected => Ok(()),
        Some(_) => Err(NotCounted::PayloadMismatch),
        None => Err(NotCounted::Malformed("no payload".to_string())),
    }
}

/// A call's answer as a judgement input: answered bytes, or why there are none.
/// `Refused` is a verdict (the vote does not count); `Unreachable` is not one
/// and is returned as `Err` for the caller to fail on.
pub fn answered_bytes(answer: CallAnswer) -> Result<Result<(Vec<u8>, String), NotCounted>, String> {
    match answer {
        CallAnswer::Answered { bytes, block_hash } => Ok(Ok((bytes, block_hash))),
        CallAnswer::Refused(why) => Ok(Err(NotCounted::Refused(contract_words(&why)))),
        CallAnswer::Unreachable(why) => Err(why),
    }
}

/// The block a read is made at: the latest final one, or the one an earlier
/// read of the same vote answered from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum At {
    Final,
    Block(String),
}

/// The `query` params of one `call_function` view.
pub fn call_params(account_id: &str, method: &str, args: &serde_json::Value, at: &At) -> serde_json::Value {
    use base64::Engine;
    let mut params = serde_json::json!({
        "request_type": "call_function",
        "account_id": account_id,
        "method_name": method,
        "args_base64": base64::engine::general_purpose::STANDARD.encode(args.to_string()),
    });
    match at {
        At::Final => params["finality"] = serde_json::json!("final"),
        At::Block(hash) => params["block_id"] = serde_json::json!(hash),
    }
    params
}

/// Resolve one contract vote: `w_is_signature_allowed()` and then
/// `w_resolve_auth`, BOTH at one block — the first read picks it (at `at`),
/// the second is pinned to the block the first answered from, so the flag and
/// the resolution describe the same state of the wallet.
///
/// `query` sends `query` params to the RPC and returns the whole JSON-RPC
/// response; a transport failure is `Err`. The result:
/// * `Ok(Ok(()))` — the vote counts;
/// * `Ok(Err(reason))` — the chain answered, and the vote does not count;
/// * `Err(why)` — the chain could not be asked; nothing is concluded.
///
/// With `At::Final` the first read picks the block, and a node behind a load
/// balancer may not have it yet when the pinned second read arrives
/// (`UNKNOWN_BLOCK`). That is a node's state, not the wallet's, and for the
/// keystore an `Err` fails the whole approved operation — so the pair is read
/// once more from `final`, without waiting. A caller that names the block
/// (`At::Block`) has pinned other reads to it and gets the `Err` instead.
pub async fn resolve_contract_vote<Q, F>(
    query: Q,
    approver_id: &str,
    shape: Shape,
    recipient: &str,
    authorization: &str,
    expected: &str,
    at: At,
) -> Result<Result<(), NotCounted>, String>
where
    Q: Fn(serde_json::Value) -> F,
    F: std::future::Future<Output = Result<serde_json::Value, String>>,
{
    let attempts = if at == At::Final { 2 } else { 1 };
    let mut attempt = 1;
    loop {
        match resolve_pair(&query, approver_id, shape, recipient, authorization, expected, &at).await {
            Err(PairError::BlockUnknown(_)) if attempt < attempts => attempt += 1,
            Err(PairError::BlockUnknown(why) | PairError::Unreachable(why)) => return Err(why),
            Ok(verdict) => return Ok(verdict),
        }
    }
}

enum PairError {
    /// The pinned read reached a node without the block.
    BlockUnknown(String),
    Unreachable(String),
}

fn names_unknown_block(response: &serde_json::Value) -> bool {
    response
        .get("error")
        .map(|e| {
            e.get("cause").and_then(|c| c.get("name")).and_then(|n| n.as_str()) == Some("UNKNOWN_BLOCK")
                || e.get("name").and_then(|n| n.as_str()) == Some("UNKNOWN_BLOCK")
        })
        .unwrap_or(false)
}

async fn resolve_pair<Q, F>(
    query: &Q,
    approver_id: &str,
    shape: Shape,
    recipient: &str,
    authorization: &str,
    expected: &str,
    at: &At,
) -> Result<Result<(), NotCounted>, PairError>
where
    Q: Fn(serde_json::Value) -> F,
    F: std::future::Future<Output = Result<serde_json::Value, String>>,
{
    let allowed = query(call_params(approver_id, "w_is_signature_allowed", &serde_json::json!({}), at))
        .await
        .map_err(PairError::Unreachable)?;
    let (bytes, block) = match answered_bytes(classify_call(&allowed)).map_err(PairError::Unreachable)? {
        Ok(v) => v,
        Err(not) => return Ok(Err(not)),
    };
    if let Err(not) = judge_signature_allowed(&bytes) {
        return Ok(Err(not));
    }
    let args = resolve_args(shape, recipient, authorization);
    let resolved = query(call_params(approver_id, "w_resolve_auth", &args, &At::Block(block)))
        .await
        .map_err(PairError::Unreachable)?;
    if names_unknown_block(&resolved) {
        return Err(PairError::BlockUnknown(format!("RPC error: {}", resolved["error"])));
    }
    let (bytes, _) = match answered_bytes(classify_call(&resolved)).map_err(PairError::Unreachable)? {
        Ok(v) => v,
        Err(not) => return Ok(Err(not)),
    };
    Ok(judge_resolution(shape, &bytes, expected))
}

/// The contract's own sentence out of a VM error, when there is one:
/// `… GuestPanic { panic_msg: "invalid signature" } …` → `invalid signature`.
fn contract_words(vm_error: &str) -> String {
    vm_error
        .split("panic_msg: \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .map(str::to_string)
        .unwrap_or_else(|| vm_error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EXPECTED: &str = "approve:example-approval-id:ed25519:example-wallet-key:example-request-hash";

    #[test]
    fn the_vote_message_is_one_string_for_every_proof() {
        assert_eq!(
            vote_message(VoteVerb::Approve, "example-approval-id", "ed25519:example-wallet-key", "example-request-hash"),
            EXPECTED
        );
        assert_eq!(
            vote_message(VoteVerb::Reject, "a", "ed25519:w", "h"),
            "reject:a:ed25519:w:h"
        );
    }

    #[test]
    fn a_pin_on_any_entry_pins_the_approver() {
        let policy: crate::wallet_policy::Policy = serde_json::from_value(json!({
            "approval": {"threshold": {"required": 1}, "approvers": [
                {"id": "open.near"},
                {"id": "pinned.near", "pubkey": "ed25519:K1"},
                {"id": "twice.near"},
                {"id": "twice.near", "pubkey": "ed25519:K2"}
            ]}
        }))
        .unwrap();
        assert_eq!(approver_standing(&policy, "stranger.near"), ApproverStanding::NotListed);
        assert_eq!(approver_standing(&policy, "open.near"), ApproverStanding::Unpinned);
        assert_eq!(approver_standing(&policy, "pinned.near"), ApproverStanding::Pinned(vec!["ed25519:K1"]));
        assert_eq!(
            approver_standing(&policy, "twice.near"),
            ApproverStanding::Pinned(vec!["ed25519:K2"]),
            "the unpinned entry must not undo the pinned one"
        );

        let open = approver_standing(&policy, "open.near");
        assert!(open.admits_key("ed25519:any") && open.admits_contract_vote());
        let twice = approver_standing(&policy, "twice.near");
        assert!(twice.admits_key("ed25519:K2") && !twice.admits_key("ed25519:other"));
        assert!(!twice.admits_contract_vote());
        let stranger = approver_standing(&policy, "stranger.near");
        assert!(!stranger.admits_key("ed25519:any") && !stranger.admits_contract_vote());
        let none = crate::wallet_policy::Policy::default();
        assert_eq!(approver_standing(&none, "open.near"), ApproverStanding::NotListed);
    }

    #[test]
    fn a_shape_has_two_spellings_and_no_others() {
        assert_eq!(Shape::parse("eip712"), Some(Shape::Eip712));
        assert_eq!(Shape::parse("nep641"), Some(Shape::Nep641));
        for bad in ["EIP712", "Nep641", "passkey", "evm", ""] {
            assert_eq!(Shape::parse(bad), None, "{bad}");
        }
        assert_eq!(serde_json::to_value(Shape::Eip712).unwrap(), json!("eip712"));
        assert!(serde_json::from_value::<Shape>(json!("EIP712")).is_err());
        for s in [Shape::Eip712, Shape::Nep641] {
            assert_eq!(Shape::parse(s.as_str()), Some(s));
        }
    }

    /// The exact arguments the HoS examples (2026-09-29) were resolved with.
    #[test]
    fn the_arguments_are_the_resolvers_own() {
        assert_eq!(
            resolve_args(Shape::Eip712, "outlayer.near", "{blob}").to_string(),
            r#"{"authorization":"{blob}","purpose":"PROVE_OWNERSHIP","recipient":"outlayer.near"}"#
        );
        assert_eq!(
            resolve_args(Shape::Nep641, "outlayer.testnet", "{blob}").to_string(),
            r#"{"authorization":"{blob}","path":[]}"#
        );
    }

    fn envelope(answer: &str) -> serde_json::Value {
        json!({"jsonrpc": "2.0", "id": "dontcare", "result": {
            "block_hash": "5k4z7z4riNh6Vw6rLcNaLb7RAYFFfkn2Df74SCEWauoP",
            "block_height": 271235300u64, "logs": [],
            "result": answer.as_bytes()}})
    }

    /// Recorded 2026-10-02, testnet, keyed FastNEAR.
    #[test]
    fn the_rpc_answer_is_classified_by_what_it_says_about_the_account() {
        let answered = classify_call(&envelope(&format!(r#"{{"payload":"{EXPECTED}"}}"#)));
        let CallAnswer::Answered { bytes, block_hash } = answered else { panic!("{answered:?}") };
        assert_eq!(block_hash, "5k4z7z4riNh6Vw6rLcNaLb7RAYFFfkn2Df74SCEWauoP");
        assert_eq!(judge_resolution(Shape::Nep641, &bytes, EXPECTED), Ok(()));

        // The passkey wallet panics on a bad signature.
        let panicked = json!({"jsonrpc": "2.0", "id": "dontcare", "result": {
            "block_hash": "x", "block_height": 1, "logs": [],
            "error": "wasm execution failed with error: HostError(GuestPanic { panic_msg: \"invalid signature\" })"}});
        let refused = classify_call(&panicked);
        assert!(matches!(refused, CallAnswer::Refused(_)), "{refused:?}");
        assert_eq!(
            answered_bytes(refused).unwrap(),
            Err(NotCounted::Refused("invalid signature".to_string()))
        );

        for vm in [
            "wasm execution failed with error: MethodResolveError(MethodNotFound)",
            "wasm execution failed with error: CompilationError(CodeDoesNotExist { account_id: \"outlayer-alice.testnet\" })",
        ] {
            let r = json!({"result": {"block_hash": "x", "logs": [], "error": vm}});
            assert!(matches!(classify_call(&r), CallAnswer::Refused(_)), "{vm}");
        }
        let unknown = json!({"jsonrpc": "2.0", "id": "dontcare", "error": {"name": "HANDLER_ERROR",
            "cause": {"name": "UNKNOWN_ACCOUNT", "info": {}}, "code": -32000, "message": "Server error"}});
        assert!(matches!(classify_call(&unknown), CallAnswer::Refused(_)));

        // About the node, never the account.
        for (label, r) in [
            ("unknown block", json!({"error": {"name": "HANDLER_ERROR", "cause": {"name": "UNKNOWN_BLOCK"}}})),
            ("timeout", json!({"error": {"name": "HANDLER_ERROR", "cause": {"name": "TIMEOUT_ERROR"}}})),
            ("empty", json!({})),
            ("no bytes", json!({"result": {"block_hash": "x"}})),
            ("no block", json!({"result": {"result": [116, 114, 117, 101]}})),
            ("not bytes", json!({"result": {"block_hash": "x", "result": [300]}})),
            ("other error", json!({"result": {"block_hash": "x", "error": "node is syncing"}})),
        ] {
            assert!(matches!(classify_call(&r), CallAnswer::Unreachable(_)), "{label}");
            assert!(answered_bytes(classify_call(&r)).is_err(), "{label} must not be a verdict");
        }
    }

    /// Every request a fake RPC received.
    type Seen = std::rc::Rc<std::cell::RefCell<Vec<serde_json::Value>>>;

    /// A fake RPC: answers by method name, records every request.
    fn fake_rpc(
        answers: Vec<(&'static str, serde_json::Value)>,
    ) -> (impl Fn(serde_json::Value) -> std::future::Ready<Result<serde_json::Value, String>>, Seen) {
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let log = seen.clone();
        let query = move |params: serde_json::Value| {
            log.borrow_mut().push(params.clone());
            let method = params["method_name"].as_str().unwrap_or_default().to_string();
            let answer = answers
                .iter()
                .find(|(m, _)| *m == method)
                .map(|(_, a)| a.clone())
                .ok_or_else(|| "connection refused".to_string());
            std::future::ready(answer)
        };
        (query, seen)
    }

    fn answer_at(block: &str, body: &str) -> serde_json::Value {
        json!({"result": {"block_hash": block, "block_height": 1, "logs": [], "result": body.as_bytes()}})
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
    }

    #[test]
    fn both_reads_of_a_vote_are_made_at_one_block() {
        let ok = format!(r#"{{"payload":"{EXPECTED}"}}"#);
        let (query, seen) = fake_rpc(vec![
            ("w_is_signature_allowed", answer_at("B1", "true")),
            ("w_resolve_auth", answer_at("B1", &ok)),
        ]);
        let verdict = block_on(resolve_contract_vote(
            query, "0s107c.testnet", Shape::Nep641, "outlayer.testnet", "{blob}", EXPECTED, At::Final,
        ));
        assert_eq!(verdict, Ok(Ok(())));
        let seen = seen.borrow();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0]["finality"], json!("final"));
        assert_eq!(seen[1]["block_id"], json!("B1"), "the resolution must be read at the flag's block");
        assert!(seen[1].get("finality").is_none());
        assert_eq!(seen[1]["account_id"], json!("0s107c.testnet"));

        // A caller that names the block pins both reads to it.
        let (query, seen) = fake_rpc(vec![
            ("w_is_signature_allowed", answer_at("B7", "true")),
            ("w_resolve_auth", answer_at("B7", &ok)),
        ]);
        block_on(resolve_contract_vote(
            query, "a", Shape::Nep641, "r", "x", EXPECTED, At::Block("B7".into()),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(seen.borrow()[0]["block_id"], json!("B7"));
    }

    /// A node behind the balancer without the flag's block answers the pinned
    /// read `UNKNOWN_BLOCK`: the pair is read again from `final`, once.
    #[test]
    fn a_lagging_node_gets_one_fresh_pair_and_no_more() {
        let ok = format!(r#"{{"payload":"{EXPECTED}"}}"#);
        let unknown = json!({"error": {"name": "HANDLER_ERROR", "cause": {"name": "UNKNOWN_BLOCK"}}});
        let resolves = std::cell::Cell::new(0);
        let seen = std::cell::RefCell::new(Vec::new());
        let query = |params: serde_json::Value| {
            seen.borrow_mut().push(params.clone());
            let answer = if params["method_name"] == "w_is_signature_allowed" {
                answer_at("B1", "true")
            } else {
                resolves.set(resolves.get() + 1);
                if resolves.get() == 1 { unknown.clone() } else { answer_at("B1", &ok) }
            };
            std::future::ready(Ok(answer))
        };
        let verdict = block_on(resolve_contract_vote(&query, "a", Shape::Nep641, "r", "x", EXPECTED, At::Final));
        assert_eq!(verdict, Ok(Ok(())));
        let seen = seen.borrow();
        assert_eq!(seen.len(), 4, "flag, lost block, flag again from final, resolution");
        assert_eq!(seen[2]["finality"], json!("final"));
        drop(seen);

        // Twice in a row is an outage, not a lagging node.
        let always = |params: serde_json::Value| {
            std::future::ready(Ok(if params["method_name"] == "w_is_signature_allowed" {
                answer_at("B1", "true")
            } else {
                unknown.clone()
            }))
        };
        assert!(block_on(resolve_contract_vote(always, "a", Shape::Nep641, "r", "x", EXPECTED, At::Final)).is_err());

        // A caller that named the block gets the error, never a read at another block.
        let calls = std::cell::Cell::new(0);
        let pinned = |params: serde_json::Value| {
            calls.set(calls.get() + 1);
            std::future::ready(Ok(if params["method_name"] == "w_is_signature_allowed" {
                answer_at("B7", "true")
            } else {
                unknown.clone()
            }))
        };
        assert!(block_on(resolve_contract_vote(&pinned, "a", Shape::Nep641, "r", "x", EXPECTED, At::Block("B7".into()))).is_err());
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn a_wallet_that_refuses_signatures_never_reaches_the_resolver() {
        let (query, seen) = fake_rpc(vec![("w_is_signature_allowed", answer_at("B1", "false"))]);
        let verdict = block_on(resolve_contract_vote(
            query, "a", Shape::Eip712, "outlayer.near", "x", EXPECTED, At::Final,
        ));
        assert_eq!(verdict, Ok(Err(NotCounted::SignaturesDisabled)));
        assert_eq!(seen.borrow().len(), 1);
    }

    #[test]
    fn an_unreachable_chain_concludes_nothing() {
        let (query, _) = fake_rpc(vec![]);
        let verdict = block_on(resolve_contract_vote(query, "a", Shape::Nep641, "r", "x", EXPECTED, At::Final));
        assert!(verdict.is_err(), "{verdict:?}");

        let (query, _) = fake_rpc(vec![
            ("w_is_signature_allowed", answer_at("B1", "true")),
            ("w_resolve_auth", json!({"error": {"cause": {"name": "UNKNOWN_BLOCK"}}})),
        ]);
        let verdict = block_on(resolve_contract_vote(query, "a", Shape::Nep641, "r", "x", EXPECTED, At::Final));
        assert!(verdict.is_err(), "a node that lost the block is not a refusal: {verdict:?}");
    }

    #[test]
    fn the_eip712_recipient_is_the_one_passed_in() {
        let ok = format!(r#"{{"status":"RESOLVED","payload":"{EXPECTED}"}}"#);
        let (query, seen) = fake_rpc(vec![
            ("w_is_signature_allowed", answer_at("B1", "true")),
            ("w_resolve_auth", answer_at("B1", &ok)),
        ]);
        block_on(resolve_contract_vote(query, "a", Shape::Eip712, "outlayer.near", "{blob}", EXPECTED, At::Final))
            .unwrap()
            .unwrap();
        use base64::Engine;
        let args = base64::engine::general_purpose::STANDARD
            .decode(seen.borrow()[1]["args_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            String::from_utf8(args).unwrap(),
            r#"{"authorization":"{blob}","purpose":"PROVE_OWNERSHIP","recipient":"outlayer.near"}"#
        );
    }

    #[test]
    fn only_a_literal_true_allows_signatures() {
        assert_eq!(judge_signature_allowed(b"true"), Ok(()));
        assert_eq!(judge_signature_allowed(b"false"), Err(NotCounted::SignaturesDisabled));
        for bad in [&b"\"true\""[..], b"1", b"null", b"", b"{}"] {
            assert!(matches!(judge_signature_allowed(bad), Err(NotCounted::Malformed(_))), "{bad:?}");
        }
    }

    /// The EIP-712 answers HoS captured live on mainnet `0s4f4efd07…`, and the
    /// recipient mismatch recorded 2026-10-02.
    #[test]
    fn an_eip712_vote_counts_only_resolved_for_the_exact_message() {
        let ok = format!(r#"{{"status":"RESOLVED","payload":"{EXPECTED}"}}"#);
        assert_eq!(judge_resolution(Shape::Eip712, ok.as_bytes(), EXPECTED), Ok(()));

        let other = r#"{"status":"RESOLVED","payload":"reject:other-approval-id:ed25519:example-wallet-key:example-request-hash"}"#;
        assert_eq!(judge_resolution(Shape::Eip712, other.as_bytes(), EXPECTED), Err(NotCounted::PayloadMismatch));

        let bad_sig = r#"{"status":"INVALID","error_kind":"INVALID_SIGNATURE","error_message":"recovered public key does not match wallet"}"#;
        assert_eq!(
            judge_resolution(Shape::Eip712, bad_sig.as_bytes(), EXPECTED),
            Err(NotCounted::NotResolved("recovered public key does not match wallet".to_string()))
        );
        let wrong_recipient = r#"{"status":"INVALID","error_kind":"INVALID_INPUT","error_message":"recipient mismatch"}"#;
        assert!(matches!(
            judge_resolution(Shape::Eip712, wrong_recipient.as_bytes(), EXPECTED),
            Err(NotCounted::NotResolved(_))
        ));
        let pending = format!(r#"{{"status":"PENDING","payload":"{EXPECTED}"}}"#);
        assert!(matches!(judge_resolution(Shape::Eip712, pending.as_bytes(), EXPECTED), Err(NotCounted::NotResolved(_))));
        let lower = format!(r#"{{"status":"resolved","payload":"{EXPECTED}"}}"#);
        assert!(judge_resolution(Shape::Eip712, lower.as_bytes(), EXPECTED).is_err());
        let no_status = format!(r#"{{"payload":"{EXPECTED}"}}"#);
        assert!(matches!(judge_resolution(Shape::Eip712, no_status.as_bytes(), EXPECTED), Err(NotCounted::Malformed(_))));
        let spaced = format!(r#"{{"status":"RESOLVED","payload":"{EXPECTED} "}}"#);
        assert_eq!(judge_resolution(Shape::Eip712, spaced.as_bytes(), EXPECTED), Err(NotCounted::PayloadMismatch));
        let numeric = r#"{"status":"RESOLVED","payload":7}"#;
        assert!(matches!(judge_resolution(Shape::Eip712, numeric.as_bytes(), EXPECTED), Err(NotCounted::Malformed(_))));
    }

    /// The NEP-641 answers recorded 2026-10-02 on testnet `0s107c8e57…`, and
    /// the extension-scoped shape: payload echoed, one sub-authorization
    /// pending. That one must never count — the extension is the authority.
    #[test]
    fn a_nep641_vote_counts_only_its_own_signature_for_the_exact_message() {
        let ok = format!(r#"{{"payload":"{EXPECTED}"}}"#);
        assert_eq!(judge_resolution(Shape::Nep641, ok.as_bytes(), EXPECTED), Ok(()));
        let empty_pending = format!(r#"{{"payload":"{EXPECTED}","pending":[]}}"#);
        assert_eq!(judge_resolution(Shape::Nep641, empty_pending.as_bytes(), EXPECTED), Ok(()));

        let other = r#"{"payload":"reject:other-approval-id:ed25519:example-wallet-key:example-request-hash"}"#;
        assert_eq!(judge_resolution(Shape::Nep641, other.as_bytes(), EXPECTED), Err(NotCounted::PayloadMismatch));

        let extension = format!(
            r#"{{"payload":"{EXPECTED}","pending":[{{"account_id":"executor.testnet","authorization":"x","expect":"y"}}]}}"#
        );
        assert_eq!(
            judge_resolution(Shape::Nep641, extension.as_bytes(), EXPECTED),
            Err(NotCounted::PendingSubAuthorization)
        );
        let odd = format!(r#"{{"payload":"{EXPECTED}","pending":{{}}}}"#);
        assert!(matches!(judge_resolution(Shape::Nep641, odd.as_bytes(), EXPECTED), Err(NotCounted::Malformed(_))));
    }

    /// The judge is not what stops a wrong shape — see the module doc. An
    /// EIP-712 answer that resolved the message, read as NEP-641, counts: only
    /// the contract's panic on the other shape's arguments keeps this answer from
    /// ever existing. Recorded as a fact so nobody leans on the judge for it.
    #[test]
    fn an_eip712_resolution_read_as_nep641_is_not_refused_by_the_judge() {
        let evm_resolved = format!(r#"{{"status":"RESOLVED","payload":"{EXPECTED}"}}"#);
        assert_eq!(judge_resolution(Shape::Nep641, evm_resolved.as_bytes(), EXPECTED), Ok(()));
    }

    /// The direction the judge does stop: answers that are not a resolution of the
    /// message under the shape asked.
    #[test]
    fn the_wrong_shape_never_counts() {
        let passkey_answer = format!(r#"{{"payload":"{EXPECTED}"}}"#);
        assert!(judge_resolution(Shape::Eip712, passkey_answer.as_bytes(), EXPECTED).is_err());
        let evm_invalid = r#"{"status":"INVALID","error_kind":"INVALID_SIGNATURE","error_message":"x"}"#;
        assert!(judge_resolution(Shape::Nep641, evm_invalid.as_bytes(), EXPECTED).is_err());
    }

    #[test]
    fn an_oversized_or_unreadable_answer_is_not_judged() {
        let big = format!(r#"{{"payload":"{EXPECTED}","pad":"{}"}}"#, "x".repeat(RESOLUTION_MAX_BYTES));
        assert!(matches!(judge_resolution(Shape::Nep641, big.as_bytes(), EXPECTED), Err(NotCounted::Malformed(_))));
        for bad in [&b"not json"[..], b"[]", b"\"payload\"", b""] {
            assert!(matches!(judge_resolution(Shape::Nep641, bad, EXPECTED), Err(NotCounted::Malformed(_))));
        }
    }
}
