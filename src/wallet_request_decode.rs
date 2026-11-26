//! Decoding `w_execute_extension` requests into a canonical set of EFFECTS.
//!
//! The outer fields of such a call describe nothing: the destination is the
//! agent's own wallet-contract account, the deposit is a 1-yocto marker, and
//! the real recipients and amounts are nested in `args_base64`. This module
//! turns those args into ONE [`EffectsSet`] — the atomic policy object every
//! rule evaluates against — identically wherever it runs (keystore,
//! coordinator, tests), because it runs from one implementation.
//!
//! **Mode-blind by construction.** Nothing here knows a binding kind (the
//! guard test in `binding.rs` enforces that). Facts that only SOME mode
//! forbids — a set `refund_to`, a token call sharing its promise, a non-1yocto
//! call deposit — are computed as neutral [`ShapeFact`]s; turning a fact into
//! a refusal is the binding profile's job, in its `admission`.
//!
//! **Frozen wire structs.** `decoder_v1` mirrors the upstream wire format at
//! rev `6095765f` (`near/intents`: `defuse-wallet` `Request`/`WalletOp`,
//! `defuse-near-promise` `NearPromise`/`NearAction`) field for field:
//! adjacently tagged enums (`action`/`payload`, `op`/`payload`, snake_case),
//! base64 `args` omitted when empty, `NearToken`/`Gas` as decimal strings,
//! `refund_to` omitted when absent. Unknown enum VARIANTS fail the decode
//! (fail closed — upstream marks the enums `#[non_exhaustive]`); unknown
//! FIELDS inside a known variant are accepted (upstream serde default), so
//! minor additive upstream changes do not false-refuse. The structs are our
//! own rather than a dependency on the fast-moving upstream crate: two
//! decoder revisions must be able to coexist in one binary, and a git crate
//! inside a measured image is an extra supply-chain surface.
//!
//! Fail-closed rules, decided here and tested here:
//! * args that do not parse as a request → [`DecodeError`] — the caller
//!   refuses, nothing "passes through";
//! * any `internal` operation → `has_internal` (account CONTROL, not
//!   spending — the caller must hard-deny);
//! * a function call whose method this module has no semantics for — or a
//!   KNOWN method whose own args do not parse — lands in
//!   `unknown_fund_moving`, never silently through. That includes
//!   `ft_transfer_call`: its `msg` reaches a third contract that can move
//!   value the arguments do not state, so its effects are not statable.
//!
//! Two shapes a reader would not predict from "field for field", both upstream's
//! own behaviour rather than a divergence of ours:
//! * both fields of `Request` carry serde defaults, so the POSITIONAL array
//!   spelling deserialises as well as the map one — `{"request":[]}` is a valid
//!   empty request, not a parse error. (`Envelope::request` itself is NOT
//!   defaulted: bare `{}` is refused.)
//! * an EMPTY request decodes, states no effects, and is therefore permitted by
//!   every rule — nothing moves and nothing is bypassed, but the signature and
//!   the executor's gas are spent on a no-op.
//!
//! Semantics v1 (what the decoder CAN state):
//! * NEP-141 `ft_transfer` → token, logical recipient, amount in token units;
//! * NEP-171 `nft_transfer` → collection, logical recipient, exact `token_id`
//!   (+ a shape fact when `approval_id` is set);
//! * NEP-145 `storage_deposit` → registration beneficiary + the attached
//!   native deposit (already counted in `native_total`).

use serde::Deserialize;

// ============================================================================
// Frozen wire structs — decoder v1 (upstream rev 6095765f)
// ============================================================================

pub mod decoder_v1 {
    use serde::Deserialize;

    /// The near-sdk argument envelope: `w_execute_extension(request: Request)`
    /// arrives as `{"request": {...}}`. `request` is NOT defaulted — args
    /// without it are not a request and must fail the decode.
    #[derive(Debug, Clone, Deserialize)]
    pub struct Envelope {
        pub request: Request,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    pub struct Request {
        #[serde(default)]
        pub internal: Vec<WalletOp>,
        #[serde(default)]
        pub external: Vec<NearPromise>,
    }

    /// Internal (account-control) operations. Every variant is control, not
    /// spending; callers deny on ANY of them — the variant only names which.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(tag = "op", content = "payload", rename_all = "snake_case")]
    pub enum WalletOp {
        SetSignatureMode { enable: bool },
        AddExtension { account_id: String },
        RemoveExtension { account_id: String },
    }

    impl WalletOp {
        pub fn name(&self) -> &'static str {
            match self {
                WalletOp::SetSignatureMode { .. } => "set_signature_mode",
                WalletOp::AddExtension { .. } => "add_extension",
                WalletOp::RemoveExtension { .. } => "remove_extension",
            }
        }
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct NearPromise {
        pub receiver_id: String,
        #[serde(default)]
        pub refund_to: Option<String>,
        #[serde(default)]
        pub actions: Vec<NearAction>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(tag = "action", content = "payload", rename_all = "snake_case")]
    pub enum NearAction {
        FunctionCall(FunctionCall),
        Transfer(Transfer),
        DeterministicStateInit(DeterministicStateInit),
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct FunctionCall {
        pub function_name: String,
        /// Base64; omitted upstream when empty.
        #[serde(default)]
        pub args: String,
        /// Yocto, decimal string; omitted upstream when zero. Strict on
        /// purpose: upstream's `NearToken` deserializes from a STRING only, so
        /// a bare number here is a request the chain would refuse too.
        #[serde(default = "zero")]
        pub deposit: String,
        /// Gas units, decimal string; omitted upstream when zero.
        ///
        /// Accepts a bare JSON number as well, because upstream's `NearGas`
        /// does: its deserializer is a string-OR-number visitor, so a request
        /// built through the upstream types can legitimately carry either
        /// spelling. Refusing the number form would deny a request the chain
        /// accepts — the one field where upstream is looser than `NearToken`.
        #[serde(default = "zero", deserialize_with = "decimal_string_or_number")]
        pub gas: String,
        /// Not consumed by any policy; accepted in either the string form
        /// upstream serializes or a bare number, so a representational
        /// difference cannot refuse a valid request.
        #[serde(default)]
        pub gas_weight: Option<serde_json::Value>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct Transfer {
        /// Yocto, decimal string. NOT defaulted: a transfer without an amount
        /// is not a transfer.
        pub amount: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct DeterministicStateInit {
        /// Opaque here: the policy meters its deposit and nothing else reads
        /// it in v1.
        #[serde(default)]
        pub state_init: serde_json::Value,
        #[serde(default = "zero")]
        pub deposit: String,
    }

    fn zero() -> String {
        "0".to_string()
    }

    /// A non-negative integer written either way, normalized to its decimal
    /// string. Anything else — a float, a negative, a bool, an object — is a
    /// decode failure, not a coerced value: see [`FunctionCall::gas`] for why
    /// exactly one field needs this.
    fn decimal_string_or_number<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::String(s) => Ok(s),
            serde_json::Value::Number(n) if n.is_u64() => Ok(n.to_string()),
            other => Err(D::Error::custom(format!(
                "expected a decimal string or a non-negative integer, got {other}"
            ))),
        }
    }
}

// ============================================================================
// Decode
// ============================================================================

/// Why args failed to become a request. One string, because every caller does
/// the same thing with it: refuse, quoting the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Parse raw `w_execute_extension` args. Anything short of a fully readable
/// request — bad JSON, a missing `request` field, an unknown action or
/// internal-op variant, a non-numeric amount discovered later in
/// [`effects`] — is a refusal, never a partial result.
pub fn decode(args: &[u8]) -> Result<decoder_v1::Envelope, DecodeError> {
    serde_json::from_slice(args)
        .map_err(|e| DecodeError(format!("w_execute_extension args do not parse: {e}")))
}

// ============================================================================
// Effects
// ============================================================================

/// A fungible amount in the token's own units, or an exact non-fungible item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenAmount {
    Fungible(u128),
    Item(String),
}

/// One decoded token movement: the LOGICAL destination and size that the
/// outer call hides inside its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenMove {
    pub promise_index: usize,
    /// The token/collection contract (the promise's immediate receiver).
    pub token: String,
    /// Where the value actually lands.
    pub recipient: String,
    pub amount: TokenAmount,
    /// `ft_transfer` | `nft_transfer` — for rule names in refusals.
    pub method: String,
}

/// One NEP-145 registration paid from the request's native deposits.
/// `account: None` means self-registration (the wallet account itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRegistration {
    pub promise_index: usize,
    pub token_contract: String,
    pub account: Option<String>,
    pub deposit: u128,
}

/// A function call whose effects this decoder cannot state. The caller must
/// treat the WHOLE request as unstatable (fail closed) — value could move
/// where no rule looked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownCall {
    pub promise_index: usize,
    pub contract: String,
    pub method: String,
    pub deposit: u128,
    /// Why it is here: an unlisted method, or a listed one with unreadable args.
    pub reason: String,
}

/// Mode-neutral FACTS about the request's form. No fact is a violation here:
/// the `hos_lease` profile turns them into refusals (its contract enforces
/// the same form on chain), the `personal_account` profile ignores them (its
/// contract accepts bundles and refunds; only policy limits apply).
///
/// Note what is deliberately NOT a fact: several `transfer` actions in one
/// promise. The "stand alone" rule applies to token CALLS only — a promise
/// carrying nothing but transfers is legal even under a spend grant, and
/// flagging it would false-refuse a legal request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShapeFact {
    /// The promise names a refund destination. Recorded for ANY promise,
    /// including a purely native one: a grant refuses redirected refunds
    /// whatever the promise carries.
    RefundToSet { promise_index: usize },
    /// A function call shares its promise with other actions.
    CallNotStandalone { promise_index: usize },
    /// A function call attaches something other than exactly 1 yocto.
    CallDepositNotOneYocto { promise_index: usize, deposit: u128 },
    /// An `nft_transfer` carries a non-null `approval_id`.
    NftApprovalIdSet { promise_index: usize },
    /// A token call's arguments carry a field outside the NEP-141/171 set
    /// this decoder reads (`memo` IS inside it). Harmless to the semantics —
    /// the recipient and amount still read correctly — but a contract that
    /// parses those arguments with `deny_unknown_fields` cannot read them at
    /// all, so the mode whose contract does that refuses. `msg` on an
    /// `ft_transfer` is the case that matters.
    TokenArgsUnknownField { promise_index: usize, field: String },
}

/// The canonical, atomic policy object: everything one request does, in one
/// place, so a rule that forgets to look somewhere has nowhere to forget.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EffectsSet {
    /// Immediate receiver of each promise, in promise order.
    pub receivers: Vec<String>,
    /// Every named refund destination, with its promise index — address rules
    /// apply to these exactly as to receivers (a deposit on a call engineered
    /// to revert lands here).
    pub refund_tos: Vec<(usize, String)>,
    /// Σ over all actions: transfer amounts + call deposits + state-init
    /// deposits, in yocto.
    pub native_total: u128,
    pub native_per_promise: Vec<u128>,
    pub token_moves: Vec<TokenMove>,
    /// Plain native transfers: `(promise_index, yocto)`. Value lands at that
    /// promise's receiver — the profiles' grant rules need to know WHICH
    /// promises carry naked value, not only the totals.
    pub plain_transfers: Vec<(usize, u128)>,
    /// Promise indexes carrying at least one function call. Lets a profile
    /// meter native spending the way its contract does: the leased mode
    /// charges its native budget per promise WITHOUT a call, while a token
    /// call's 1-yocto marker is a fee of the call, not a spend.
    pub call_promises: Vec<usize>,
    pub storage_registrations: Vec<StorageRegistration>,
    pub unknown_fund_moving: Vec<UnknownCall>,
    /// Promise indexes carrying a `deterministic_state_init` action. The core
    /// meters its deposit like any other; whether the action is PERMITTED at
    /// all is a mode question (the leased mode's grant refuses deploying
    /// code), so the fact is recorded for the profiles.
    pub state_inits: Vec<usize>,
    pub has_internal: bool,
    /// Names of the internal ops, for the refusal message.
    pub internal_ops: Vec<String>,
    pub action_count: usize,
    /// Σ of declared minimum gas across function calls.
    pub total_gas: u64,
    pub request_size: usize,
    pub shape_facts: Vec<ShapeFact>,
}

fn parse_yocto(s: &str, what: &str) -> Result<u128, DecodeError> {
    s.parse::<u128>()
        .map_err(|_| DecodeError(format!("{what} '{s}' is not a decimal amount")))
}

#[derive(Debug, Deserialize)]
struct FtTransferArgs {
    receiver_id: String,
    amount: String,
}

/// Fields NEP-141 `ft_transfer` defines. `memo` is permitted and not read.
const FT_TRANSFER_FIELDS: &[&str] = &["receiver_id", "amount", "memo"];

#[derive(Debug, Deserialize)]
struct NftTransferArgs {
    receiver_id: String,
    token_id: String,
    #[serde(default)]
    approval_id: Option<serde_json::Value>,
}

/// Fields NEP-171 `nft_transfer` defines.
const NFT_TRANSFER_FIELDS: &[&str] = &["receiver_id", "token_id", "approval_id", "memo"];

/// Argument keys outside the standard's own set. This decoder still READS the
/// call (an extra key changes neither recipient nor amount), so the answer is
/// a neutral fact — but a contract parsing the same bytes with
/// `deny_unknown_fields` cannot read them at all, and its profile refuses.
fn unknown_arg_fields(inner: &[u8], known: &[&str]) -> Vec<String> {
    match serde_json::from_slice::<serde_json::Value>(inner) {
        Ok(serde_json::Value::Object(map)) => map
            .keys()
            .filter(|k| !known.contains(&k.as_str()))
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

#[derive(Debug, Deserialize)]
struct StorageDepositArgs {
    #[serde(default)]
    account_id: Option<String>,
}

/// Derive the effects of a decoded request. Errors only on amounts that are
/// not amounts (the request as sent could not execute the way any rule would
/// have read it); a semantically unreadable INNER call degrades to
/// `unknown_fund_moving` instead, so the caller refuses with a precise class
/// rather than a parse error.
pub fn effects(
    envelope: &decoder_v1::Envelope,
    request_size: usize,
) -> Result<EffectsSet, DecodeError> {
    use base64::Engine;
    use decoder_v1::NearAction;

    let mut fx = EffectsSet {
        request_size,
        has_internal: !envelope.request.internal.is_empty(),
        internal_ops: envelope.request.internal.iter().map(|op| op.name().to_string()).collect(),
        ..EffectsSet::default()
    };

    for (promise_index, promise) in envelope.request.external.iter().enumerate() {
        fx.receivers.push(promise.receiver_id.clone());
        if let Some(refund_to) = &promise.refund_to {
            fx.refund_tos.push((promise_index, refund_to.clone()));
            fx.shape_facts.push(ShapeFact::RefundToSet { promise_index });
        }

        let mut promise_native: u128 = 0;
        let action_count = promise.actions.len();
        fx.action_count += action_count;

        for action in &promise.actions {
            match action {
                NearAction::Transfer(t) => {
                    let amount = parse_yocto(&t.amount, "transfer amount")?;
                    promise_native = promise_native.saturating_add(amount);
                    fx.plain_transfers.push((promise_index, amount));
                }
                NearAction::DeterministicStateInit(dsi) => {
                    promise_native = promise_native
                        .saturating_add(parse_yocto(&dsi.deposit, "state-init deposit")?);
                    fx.state_inits.push(promise_index);
                }
                NearAction::FunctionCall(fc) => {
                    if !fx.call_promises.contains(&promise_index) {
                        fx.call_promises.push(promise_index);
                    }
                    let deposit = parse_yocto(&fc.deposit, "call deposit")?;
                    let gas = fc.gas.parse::<u64>().map_err(|_| {
                        DecodeError(format!("call gas '{}' is not a decimal amount", fc.gas))
                    })?;
                    promise_native = promise_native.saturating_add(deposit);
                    fx.total_gas = fx.total_gas.saturating_add(gas);

                    if action_count > 1 {
                        fx.shape_facts.push(ShapeFact::CallNotStandalone { promise_index });
                    }
                    if deposit != 1 {
                        fx.shape_facts
                            .push(ShapeFact::CallDepositNotOneYocto { promise_index, deposit });
                    }

                    let unknown = |reason: &str| UnknownCall {
                        promise_index,
                        contract: promise.receiver_id.clone(),
                        method: fc.function_name.clone(),
                        deposit,
                        reason: reason.to_string(),
                    };

                    // "No arguments" and "arguments we could not read" are
                    // DIFFERENT facts. Folding the second into the first would
                    // let an unreadable `storage_deposit` read as a
                    // self-registration and skip the beneficiary's address
                    // rule — a fail-open branch in a fail-closed module.
                    let inner = match base64::engine::general_purpose::STANDARD.decode(&fc.args) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            fx.unknown_fund_moving.push(unknown(
                                "the call's arguments are not valid base64, so nothing about \
                                 this call can be stated",
                            ));
                            continue;
                        }
                    };

                    match fc.function_name.as_str() {
                        "ft_transfer" => match serde_json::from_slice::<FtTransferArgs>(&inner) {
                            Ok(args) => match args.amount.parse::<u128>() {
                                Ok(amount) => {
                                    for field in unknown_arg_fields(&inner, FT_TRANSFER_FIELDS) {
                                        fx.shape_facts.push(ShapeFact::TokenArgsUnknownField {
                                            promise_index,
                                            field,
                                        });
                                    }
                                    fx.token_moves.push(TokenMove {
                                    promise_index,
                                    token: promise.receiver_id.clone(),
                                    recipient: args.receiver_id,
                                    amount: TokenAmount::Fungible(amount),
                                    method: "ft_transfer".to_string(),
                                    })
                                }
                                Err(_) => fx.unknown_fund_moving.push(unknown(
                                    "ft_transfer amount is not a decimal string",
                                )),
                            },
                            Err(_) => fx.unknown_fund_moving.push(unknown(
                                "ft_transfer args are not readable — an argument the rules \
                                 cannot read could move value they never counted",
                            )),
                        },
                        "nft_transfer" => match serde_json::from_slice::<NftTransferArgs>(&inner) {
                            Ok(args) => {
                                if !matches!(
                                    args.approval_id,
                                    None | Some(serde_json::Value::Null)
                                ) {
                                    fx.shape_facts
                                        .push(ShapeFact::NftApprovalIdSet { promise_index });
                                }
                                for field in unknown_arg_fields(&inner, NFT_TRANSFER_FIELDS) {
                                    fx.shape_facts.push(ShapeFact::TokenArgsUnknownField {
                                        promise_index,
                                        field,
                                    });
                                }
                                fx.token_moves.push(TokenMove {
                                    promise_index,
                                    token: promise.receiver_id.clone(),
                                    recipient: args.receiver_id,
                                    amount: TokenAmount::Item(args.token_id),
                                    method: "nft_transfer".to_string(),
                                });
                            }
                            Err(_) => fx
                                .unknown_fund_moving
                                .push(unknown("nft_transfer args are not readable")),
                        },
                        "storage_deposit" => {
                            match serde_json::from_slice::<StorageDepositArgs>(
                                if inner.is_empty() { b"{}" } else { &inner },
                            ) {
                                Ok(args) => fx.storage_registrations.push(StorageRegistration {
                                    promise_index,
                                    token_contract: promise.receiver_id.clone(),
                                    account: args.account_id,
                                    deposit,
                                }),
                                Err(_) => fx
                                    .unknown_fund_moving
                                    .push(unknown("storage_deposit args are not readable")),
                            }
                        }
                        "ft_transfer_call" => fx.unknown_fund_moving.push(unknown(
                            "ft_transfer_call forwards value to a third contract via `msg`, \
                             which can move it further than the arguments state",
                        )),
                        _ => fx.unknown_fund_moving.push(unknown(
                            "no semantics for this method — its effects cannot be stated",
                        )),
                    }
                }
            }
        }

        fx.native_per_promise.push(promise_native);
        fx.native_total = fx.native_total.saturating_add(promise_native);
    }

    Ok(fx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    fn decode_effects(json: &str) -> Result<EffectsSet, DecodeError> {
        let envelope = decode(json.as_bytes())?;
        effects(&envelope, json.len())
    }

    /// The partner spec's own illustration, with COMPLETE ft args (the doc
    /// abbreviates them): a promise to token.near with refund_to=attacker,
    /// an ft_transfer to bob bundled with a 250 NEAR transfer. The policy
    /// must see bob, attacker AND the 250 NEAR — the triple the outer call
    /// hides entirely.
    /// A refusal to decode says WHICH part it could not read.
    ///
    /// The decoder is fail-closed by construction — both action enums are
    /// internally tagged, so an action we do not know takes the whole request
    /// down rather than being skipped. That is right, and it is only half of
    /// what a caller needs: an agent told "the request does not parse" has an
    /// opaque blob and no next move, while one told which variant, or which
    /// field, fixes it in a minute.
    ///
    /// serde already writes those sentences and `decode` passes them through
    /// whole. This pins that, because the tempting simplification — a tidy
    /// generic message — costs exactly the part that is worth having.
    #[test]
    fn a_request_we_cannot_decode_says_which_part_we_could_not_read() {
        let msg = |wire: &str| match decode(wire.as_bytes()) {
            Ok(_) => panic!("expected a refusal for: {wire}"),
            Err(e) => e.to_string(),
        };

        // An action we do not implement names ITSELF and the set we do.
        let m = msg(
            r#"{"request":{"external":[{"receiver_id":"a.near",
                "actions":[{"action":"stake","payload":{"amount":"1"}}]}]}}"#,
        );
        assert!(m.contains("stake"), "the refused action is not named: {m}");
        for known in ["function_call", "transfer", "deterministic_state_init"] {
            assert!(m.contains(known), "the permitted actions are not listed: {m}");
        }

        // Same for an account-control op — the class that must never be
        // silently dropped, because dropping one is handing over the lane.
        let m = msg(r#"{"request":{"internal":[{"op":"self_destruct","payload":{}}]}}"#);
        assert!(m.contains("self_destruct"), "the refused op is not named: {m}");
        assert!(m.contains("add_extension"), "the permitted ops are not listed: {m}");

        // A missing field names the field.
        let m = msg(r#"{"request":{"external":[{"actions":[]}]}}"#);
        assert!(m.contains("receiver_id"), "the missing field is not named: {m}");

        // An envelope that is not one names what it lacks, rather than
        // reporting a syntax error about JSON that parsed perfectly.
        let m = msg(r#"{"foo":1}"#);
        assert!(m.contains("request"), "the missing envelope field is not named: {m}");

        // A wrong TYPE names the value and what was expected. It does not name
        // the field — serde loses that inside a tagged variant — so it gives a
        // column instead, and that is the one case a caller has to count to.
        // Stated here rather than left to be discovered.
        let m = msg(
            r#"{"request":{"external":[{"receiver_id":"a.near",
                "actions":[{"action":"transfer","payload":{"amount":5}}]}]}}"#,
        );
        assert!(m.contains("integer `5`") && m.contains("expected a string"), "{m}");
        assert!(m.contains("column"), "with no field name, the position is all there is: {m}");

        // And every one of them is prefixed with the method, so a refusal read
        // out of a log says which door it came from.
        for wire in [
            r#"{"request":{"external":[{"receiver_id":"a.near","actions":[{"action":"stake","payload":{}}]}]}}"#,
            r#"{"foo":1}"#,
            "nonsense",
        ] {
            assert!(
                msg(wire).starts_with("w_execute_extension args do not parse:"),
                "the refusal does not say which call it is about: {}",
                msg(wire)
            );
        }

        // An amount that IS a string but not a number is caught later, in
        // `effects`, and that one DOES name the field — the two paths together
        // cover both spellings of the same mistake.
        let envelope = decode(
            r#"{"request":{"external":[{"receiver_id":"a.near",
                "actions":[{"action":"transfer","payload":{"amount":"1.5"}}]}]}}"#
                .as_bytes(),
        )
        .expect("a string amount decodes; it is `effects` that judges it");
        let e = effects(&envelope, 0).expect_err("1.5 is not a yocto amount");
        assert!(
            e.to_string().contains("transfer amount") && e.to_string().contains("1.5"),
            "the unreadable amount is not named: {e}"
        );
    }

    #[test]
    fn the_spec_example_yields_bob_attacker_and_250_near() {
        let ft_args = b64(r#"{"receiver_id":"bob.near","amount":"1000000"}"#);
        let json = format!(
            r#"{{"request":{{"internal":[],"external":[{{
                "receiver_id":"token.near",
                "refund_to":"attacker.near",
                "actions":[
                  {{"action":"function_call","payload":{{
                     "function_name":"ft_transfer","args":"{ft_args}",
                     "deposit":"1","gas":"30000000000000","gas_weight":"0"}}}},
                  {{"action":"transfer","payload":{{"amount":"250000000000000000000000000"}}}}
                ]}}]}}}}"#
        );
        let fx = decode_effects(&json).unwrap();

        assert_eq!(fx.receivers, vec!["token.near"]);
        assert_eq!(fx.refund_tos, vec![(0, "attacker.near".to_string())]);
        assert_eq!(fx.native_total, 250_000_000_000_000_000_000_000_001);
        assert_eq!(fx.token_moves.len(), 1);
        assert_eq!(fx.token_moves[0].recipient, "bob.near");
        assert_eq!(fx.token_moves[0].token, "token.near");
        assert_eq!(fx.token_moves[0].amount, TokenAmount::Fungible(1_000_000));
        assert!(fx.unknown_fund_moving.is_empty());
        // The form facts the hos profile will refuse — and personal will not:
        assert!(fx.shape_facts.contains(&ShapeFact::RefundToSet { promise_index: 0 }));
        assert!(fx.shape_facts.contains(&ShapeFact::CallNotStandalone { promise_index: 0 }));
    }

    #[test]
    fn serde_defaults_match_upstream() {
        // `internal`/`external` omitted; `args`/`deposit`/`gas`/`refund_to`
        // omitted; gas_weight as a bare number — all must read as upstream
        // writes them.
        let fx = decode_effects(
            r#"{"request":{"external":[{
                "receiver_id":"a.near",
                "actions":[{"action":"function_call","payload":{
                    "function_name":"storage_deposit","gas_weight":1}}]}]}}"#,
        )
        .unwrap();
        assert_eq!(fx.receivers, vec!["a.near"]);
        assert!(!fx.has_internal);
        assert!(fx.refund_tos.is_empty());
        // deposit defaulted to 0 → a zero-deposit storage registration.
        assert_eq!(fx.storage_registrations.len(), 1);
        assert_eq!(fx.storage_registrations[0].deposit, 0);
        // No amount anywhere → nothing moved.
        assert_eq!(fx.native_total, 0);
    }

    #[test]
    fn gas_reads_in_both_spellings_but_amounts_only_as_strings() {
        // Upstream's `NearGas` deserializes from a string OR a number, so both
        // spellings reach the chain intact and both must reach us. Refusing
        // the number form denies a request the chain executes.
        for gas in [r#""30000000000000""#, "30000000000000"] {
            let fx = decode_effects(&format!(
                r#"{{"request":{{"external":[{{
                    "receiver_id":"a.near",
                    "actions":[{{"action":"function_call","payload":{{
                        "function_name":"storage_deposit","gas":{gas}}}}}]}}]}}}}"#
            ))
            .unwrap();
            assert_eq!(fx.total_gas, 30_000_000_000_000, "gas={gas}");
        }

        // `NearToken` is string-only, so a bare number is a request the chain
        // refuses — we refuse it too rather than coerce it.
        for bad in [
            r#"{"request":{"external":[{"receiver_id":"a.near",
                "actions":[{"action":"transfer","payload":{"amount":5}}]}]}}"#,
            r#"{"request":{"external":[{"receiver_id":"a.near",
                "actions":[{"action":"function_call","payload":{
                    "function_name":"x","deposit":1}}]}]}}"#,
        ] {
            assert!(decode_effects(bad).is_err(), "{bad}");
        }
        // A gas value that is not a non-negative integer is still a refusal.
        assert!(decode_effects(
            r#"{"request":{"external":[{"receiver_id":"a.near",
                "actions":[{"action":"function_call","payload":{
                    "function_name":"x","gas":-1}}]}]}}"#
        )
        .is_err());
    }

    #[test]
    fn unreadable_arguments_are_unstatable_not_an_empty_call() {
        // Args that are not valid base64 used to decode to NOTHING, which for
        // `storage_deposit` reads as "register myself" — and a self
        // registration has no beneficiary for the address rules to check. The
        // arguments are unknown, so the CALL is unknown.
        let fx = decode_effects(
            r#"{"request":{"external":[{
                "receiver_id":"usdc.near",
                "actions":[{"action":"function_call","payload":{
                    "function_name":"storage_deposit","args":"!!not base64!!",
                    "deposit":"1250000000000000000000"}}]}]}}"#,
        )
        .unwrap();
        assert!(fx.storage_registrations.is_empty(), "{fx:?}");
        assert_eq!(fx.unknown_fund_moving.len(), 1);
        assert!(fx.unknown_fund_moving[0].reason.contains("base64"));
        // The money it carries is still counted — an unstatable call is not a
        // free one.
        assert_eq!(fx.native_total, 1_250_000_000_000_000_000_000);

        // Genuinely ABSENT args keep meaning "no arguments".
        let fx = decode_effects(
            r#"{"request":{"external":[{
                "receiver_id":"usdc.near",
                "actions":[{"action":"function_call","payload":{
                    "function_name":"storage_deposit","deposit":"1"}}]}]}}"#,
        )
        .unwrap();
        assert_eq!(fx.storage_registrations.len(), 1);
        assert_eq!(fx.storage_registrations[0].account, None);
        assert!(fx.unknown_fund_moving.is_empty());
    }

    #[test]
    fn an_unknown_action_variant_fails_the_decode() {
        // Upstream marks NearAction #[non_exhaustive]; a variant this build
        // does not know (e.g. "delegate") must refuse the WHOLE request, not
        // skip the action.
        let err = decode_effects(
            r#"{"request":{"external":[{
                "receiver_id":"a.near",
                "actions":[{"action":"delegate","payload":{}}]}]}}"#,
        )
        .unwrap_err();
        assert!(err.0.contains("do not parse"), "{err}");
    }

    #[test]
    fn an_unknown_field_in_a_known_variant_is_accepted() {
        // Additive upstream changes must not false-refuse (serde default:
        // unknown fields ignored).
        let fx = decode_effects(
            r#"{"request":{"external":[{
                "receiver_id":"a.near",
                "some_future_field": true,
                "actions":[{"action":"transfer","payload":{"amount":"5","note":"hi"}}]}]}}"#,
        )
        .unwrap();
        assert_eq!(fx.native_total, 5);
    }

    #[test]
    fn internal_ops_are_flagged_by_name() {
        for (op, name) in [
            (r#"{"op":"add_extension","payload":{"account_id":"x.near"}}"#, "add_extension"),
            (r#"{"op":"remove_extension","payload":{"account_id":"x.near"}}"#, "remove_extension"),
            (r#"{"op":"set_signature_mode","payload":{"enable":true}}"#, "set_signature_mode"),
        ] {
            let fx = decode_effects(&format!(r#"{{"request":{{"internal":[{op}]}}}}"#)).unwrap();
            assert!(fx.has_internal);
            assert_eq!(fx.internal_ops, vec![name.to_string()]);
        }
        // An unknown internal op is an unknown variant → decode failure.
        assert!(decode_effects(
            r#"{"request":{"internal":[{"op":"replace_owner","payload":{}}]}}"#
        )
        .is_err());
    }

    #[test]
    fn state_init_deposit_counts_toward_the_native_total() {
        // The third leak path ("I'd have missed" — the partner's own words).
        let fx = decode_effects(
            r#"{"request":{"external":[{
                "receiver_id":"new.a.near",
                "actions":[{"action":"deterministic_state_init","payload":{
                    "state_init":{"v":1},"deposit":"7000000000000000000000000"}}]}]}}"#,
        )
        .unwrap();
        assert_eq!(fx.native_total, 7_000_000_000_000_000_000_000_000);
    }

    #[test]
    fn amounts_aggregate_across_promises_and_actions() {
        // Three sub-limit transfers must SUM — splitting a payment must not
        // split the rule that meters it.
        let fx = decode_effects(
            r#"{"request":{"external":[
                {"receiver_id":"a.near","actions":[{"action":"transfer","payload":{"amount":"3"}}]},
                {"receiver_id":"b.near","actions":[
                    {"action":"transfer","payload":{"amount":"4"}},
                    {"action":"transfer","payload":{"amount":"5"}}]}
            ]}}"#,
        )
        .unwrap();
        assert_eq!(fx.native_total, 12);
        assert_eq!(fx.native_per_promise, vec![3, 9]);
        assert_eq!(fx.receivers, vec!["a.near", "b.near"]);
        assert_eq!(fx.action_count, 3);
    }

    #[test]
    fn mangled_known_methods_degrade_to_unknown_fund_moving_not_a_pass() {
        // ft_transfer with no amount / amount as a JSON number: the semantics
        // cannot be stated, so the move lands in unknown_fund_moving — the
        // caller refuses precisely instead of passing an unread argument.
        for args in [
            r#"{"receiver_id":"bob.near"}"#,
            r#"{"receiver_id":"bob.near","amount":5}"#,
        ] {
            let fx = decode_effects(&format!(
                r#"{{"request":{{"external":[{{
                    "receiver_id":"t.near",
                    "actions":[{{"action":"function_call","payload":{{
                        "function_name":"ft_transfer","args":"{}","deposit":"1"}}}}]}}]}}}}"#,
                b64(args)
            ))
            .unwrap();
            assert!(fx.token_moves.is_empty());
            assert_eq!(fx.unknown_fund_moving.len(), 1, "args={args}");
        }
    }

    #[test]
    fn ft_transfer_call_and_strangers_are_unstatable() {
        let fx = decode_effects(&format!(
            r#"{{"request":{{"external":[
                {{"receiver_id":"t.near","actions":[{{"action":"function_call","payload":{{
                    "function_name":"ft_transfer_call","args":"{}","deposit":"1"}}}}]}},
                {{"receiver_id":"dex.near","actions":[{{"action":"function_call","payload":{{
                    "function_name":"swap","args":"{}","deposit":"1"}}}}]}}
            ]}}}}"#,
            b64(r#"{"receiver_id":"bob.near","amount":"1","msg":"x"}"#),
            b64(r#"{"pool":1}"#),
        ))
        .unwrap();
        assert_eq!(fx.unknown_fund_moving.len(), 2);
        assert_eq!(fx.unknown_fund_moving[0].method, "ft_transfer_call");
        assert_eq!(fx.unknown_fund_moving[1].method, "swap");
    }

    #[test]
    fn nft_semantics_carry_the_item_and_flag_an_approval() {
        let fx = decode_effects(&format!(
            r#"{{"request":{{"external":[{{
                "receiver_id":"col.near",
                "actions":[{{"action":"function_call","payload":{{
                    "function_name":"nft_transfer","args":"{}","deposit":"1"}}}}]}}]}}}}"#,
            b64(r#"{"receiver_id":"bob.near","token_id":"1041","approval_id":7}"#),
        ))
        .unwrap();
        assert_eq!(fx.token_moves.len(), 1);
        assert_eq!(fx.token_moves[0].amount, TokenAmount::Item("1041".to_string()));
        assert!(fx
            .shape_facts
            .contains(&ShapeFact::NftApprovalIdSet { promise_index: 0 }));
    }

    #[test]
    fn storage_deposit_names_its_beneficiary_and_meters_native() {
        let fx = decode_effects(&format!(
            r#"{{"request":{{"external":[{{
                "receiver_id":"usdc.near",
                "actions":[{{"action":"function_call","payload":{{
                    "function_name":"storage_deposit","args":"{}",
                    "deposit":"1250000000000000000000"}}}}]}}]}}}}"#,
            b64(r#"{"account_id":"bob.near"}"#),
        ))
        .unwrap();
        assert_eq!(fx.storage_registrations.len(), 1);
        assert_eq!(fx.storage_registrations[0].account.as_deref(), Some("bob.near"));
        assert_eq!(fx.storage_registrations[0].deposit, 1_250_000_000_000_000_000_000);
        // The deposit is NATIVE money and counted exactly once, in the total.
        assert_eq!(fx.native_total, 1_250_000_000_000_000_000_000);
    }

    #[test]
    fn garbage_is_a_decode_error_not_a_panic() {
        for bad in [
            "",
            "not json",
            "{}",                          // no `request`
            r#"{"request": 5}"#,           // wrong type
            r#"{"request":{"external":[{"actions":[]}]}}"#, // missing receiver_id
        ] {
            assert!(decode(bad.as_bytes()).is_err(), "{bad:?} must refuse");
        }
        // A non-numeric TRANSFER amount is discovered in effects() — refusal,
        // not a skipped action.
        assert!(decode_effects(
            r#"{"request":{"external":[{
                "receiver_id":"a.near",
                "actions":[{"action":"transfer","payload":{"amount":"lots"}}]}]}}"#
        )
        .is_err());
    }
}

#[cfg(test)]
mod fuzz_tests {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};

    /// The decoder must REFUSE, never panic.
    ///
    /// It runs inside the enclave, on a body the caller chose, before anything
    /// is signed. A panic there is not a wrong answer — it is the enclave
    /// falling over on request, which is a denial of service anyone can
    /// trigger. `decode` returning `Err` is the whole contract; this asserts
    /// there is no third outcome.
    ///
    /// Deterministic rather than random: a fuzz case that only fails on some
    /// runs is a fuzz case nobody can act on. The seeds walk a wide spread of
    /// byte patterns, and any real finding should be pasted in as its own
    /// named test rather than left to a seed to rediscover.
    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        for seed in 0u64..2_000 {
            let bytes = pseudo_random_bytes(seed, (seed % 512) as usize);
            // The ONLY thing asserted: it returns. Err is fine, Ok is fine.
            if let Ok(envelope) = decode(&bytes) {
                // Reaching `effects` on random bytes is unlikely but not
                // impossible, and it is the half that does arithmetic.
                let _ = effects(&envelope, bytes.len());
            }
        }
    }

    /// The same for input that LOOKS like a request.
    ///
    /// Random bytes almost never survive `serde_json`, so on their own they
    /// exercise the JSON parser and little else. These are well-formed
    /// envelopes with hostile VALUES — the amounts, gas figures and base64 that
    /// `effects` actually does arithmetic on — which is where an overflow or an
    /// unwrap would live.
    #[test]
    fn effects_never_panics_on_hostile_values() {
        let hostile = [
            // u128::MAX and one past it, in every field that is parsed.
            "340282366920938463463374607431768211455",
            "340282366920938463463374607431768211456",
            "99999999999999999999999999999999999999999999999999",
            "-1",
            "",
            " 1",
            "0x10",
            "1e30",
            "١٢٣", // non-ASCII digits
        ];
        for amount in hostile {
            for gas in hostile {
                let json = format!(
                    r#"{{"request":{{"external":[
                        {{"receiver_id":"a.near","actions":[
                            {{"action":"transfer","payload":{{"amount":"{amount}"}}}},
                            {{"action":"function_call","payload":{{
                                "function_name":"ft_transfer","args":"","deposit":"{amount}",
                                "gas":"{gas}"}}}}
                        ]}}]}}}}"#
                );
                if let Ok(envelope) = decode(json.as_bytes()) {
                    let _ = effects(&envelope, json.len());
                }
            }
        }
    }

    /// Saturating arithmetic, proved rather than assumed.
    ///
    /// `native_total` sums promise totals and each promise sums its actions. A
    /// plain `+` here would panic in debug and wrap in release — the second
    /// being worse, because a wrapped total reads as a tiny spend and passes
    /// every limit.
    #[test]
    fn totals_saturate_instead_of_overflowing() {
        let max = u128::MAX.to_string();
        let json = format!(
            r#"{{"request":{{"external":[
                {{"receiver_id":"a.near","actions":[
                    {{"action":"transfer","payload":{{"amount":"{max}"}}}},
                    {{"action":"transfer","payload":{{"amount":"{max}"}}}}]}},
                {{"receiver_id":"b.near","actions":[
                    {{"action":"transfer","payload":{{"amount":"{max}"}}}}]}}]}}}}"#
        );
        let fx = effects(&decode(json.as_bytes()).unwrap(), json.len()).unwrap();
        assert_eq!(fx.native_total, u128::MAX, "the total must saturate, never wrap");
        assert_eq!(fx.native_per_promise[0], u128::MAX);
    }

    /// Deep nesting must be refused by the parser rather than eat the stack.
    #[test]
    fn deeply_nested_input_is_refused_not_recursed() {
        let deep = format!("{}{}", "[".repeat(20_000), "]".repeat(20_000));
        let json = format!(r#"{{"request":{{"external":{deep}}}}}"#);
        assert!(decode(json.as_bytes()).is_err(), "serde_json bounds its own recursion");
    }

    /// `arbitrary` drives the shape as well as the bytes, so the generator is
    /// not just this file's imagination.
    #[test]
    fn arbitrary_driven_envelopes_never_panic() {
        for seed in 0u64..500 {
            let raw = pseudo_random_bytes(seed, 96);
            let mut u = Unstructured::new(&raw);
            let Ok(shape) = <(u8, u64, u64, bool)>::arbitrary(&mut u) else { continue };
            let (promises, amount, gas, with_call) = shape;
            let mut external = Vec::new();
            for i in 0..(promises % 6) {
                let action = if with_call {
                    format!(
                        r#"{{"action":"function_call","payload":{{"function_name":"ft_transfer",
                            "args":"{}","deposit":"{amount}","gas":{gas}}}}}"#,
                        "!".repeat((i % 3) as usize)
                    )
                } else {
                    format!(r#"{{"action":"transfer","payload":{{"amount":"{amount}"}}}}"#)
                };
                external.push(format!(
                    r#"{{"receiver_id":"a{i}.near","actions":[{action}]}}"#
                ));
            }
            let json = format!(
                r#"{{"request":{{"external":[{}]}}}}"#,
                external.join(",")
            );
            if let Ok(envelope) = decode(json.as_bytes()) {
                let _ = effects(&envelope, json.len());
            }
        }
    }

    /// A cheap deterministic spread. Not cryptography — the point is coverage
    /// that reproduces exactly, on every machine, forever.
    fn pseudo_random_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state >> 33) as u8
            })
            .collect()
    }
}

#[cfg(test)]
mod upstream_roundtrip_tests {
    //! The frozen structs, held against the source they were frozen from.
    //!
    //! [`crate::wallet_request_decode::decoder_v1`] mirrors the upstream wire
    //! format by hand, on purpose (D2): two decoder revisions must be able to
    //! live in one binary, and a fast-moving git crate inside a measured image
    //! is supply-chain surface we do not want. The cost of that choice is that
    //! the mirror can drift in silence — upstream renames a field, adds a
    //! variant, changes how a number is written, and our decode keeps
    //! succeeding while meaning something else.
    //!
    //! The golden vectors do not catch this. They prove our RULES agree with
    //! the contract's rules; these prove our STRUCTS agree with its FORMAT.
    //! Both, or the pair is incomplete.
    //!
    //! Upstream is a DEV-dependency pinned to the same rev the structs were
    //! transcribed from, so nothing here reaches the enclave image.

    use crate::wallet_request_decode::{decode, effects};
    use defuse_near_promise::{
        actions::{FunctionCall, NearAction, Transfer},
        NearPromise,
    };
    use defuse_wallet::{Request, WalletOp};
    // Upstream's OWN re-exports, not our own copies of the same crates: the
    // point is to build values with exactly the types the contract's callers
    // build them with, and a second version of `near-account-id` in the graph
    // would be a different type wearing the same name.
    use defuse_near_promise::{AccountId, Gas, NearToken};

    fn acc(s: &str) -> AccountId {
        s.parse().expect("valid account id")
    }

    /// Serialize with THEIR types, read with OURS, and check every field we
    /// claim to understand.
    #[test]
    fn upstream_serialization_decodes_to_the_same_facts() {
        let ft_args = serde_json::json!({ "receiver_id": "bob.near", "amount": "1000000" })
            .to_string()
            .into_bytes();

        let request = Request {
            internal: vec![],
            external: vec![
                NearPromise {
                    receiver_id: acc("token.near"),
                    refund_to: Some(acc("refunds.near")),
                    actions: vec![NearAction::FunctionCall(FunctionCall {
                        function_name: "ft_transfer".to_string(),
                        args: ft_args,
                        deposit: NearToken::from_yoctonear(1),
                        gas: Gas::from_tgas(30),
                        gas_weight: Default::default(),
                    })],
                },
                NearPromise {
                    receiver_id: acc("carol.near"),
                    refund_to: None,
                    actions: vec![NearAction::Transfer(Transfer {
                        amount: NearToken::from_near(2),
                    })],
                },
            ],
        };

        // The envelope near-sdk builds for `w_execute_extension(request)`.
        let wire = serde_json::json!({ "request": request }).to_string();

        let envelope = decode(wire.as_bytes())
            .unwrap_or_else(|e| panic!("our decoder rejected UPSTREAM's own output: {e}\n{wire}"));
        let fx = effects(&envelope, wire.len()).expect("effects");

        assert_eq!(fx.receivers, vec!["token.near", "carol.near"]);
        assert_eq!(fx.refund_tos, vec![(0, "refunds.near".to_string())]);
        assert_eq!(fx.native_total, NearToken::from_near(2).as_yoctonear() + 1);
        assert_eq!(fx.token_moves.len(), 1);
        assert_eq!(fx.token_moves[0].recipient, "bob.near");
        assert_eq!(fx.token_moves[0].token, "token.near");
        assert!(fx.unknown_fund_moving.is_empty(), "{:?}", fx.unknown_fund_moving);
        assert!(!fx.has_internal);
    }

    /// The three internal ops, by their upstream names.
    ///
    /// R4 denies all of them, and the deny is keyed off the NAME. A rename
    /// upstream would leave us reading an unknown variant — which fails closed
    /// — but a variant ADDED upstream would too, and this is where that shows.
    #[test]
    fn every_upstream_internal_op_is_seen_as_internal() {
        for (op, expected) in [
            (WalletOp::AddExtension { account_id: acc("evil.near") }, "add_extension"),
            (WalletOp::RemoveExtension { account_id: acc("evil.near") }, "remove_extension"),
            (WalletOp::SetSignatureMode { enable: true }, "set_signature_mode"),
        ] {
            let request = Request { internal: vec![op], external: vec![] };
            let wire = serde_json::json!({ "request": request }).to_string();
            let fx = effects(&decode(wire.as_bytes()).expect("decode"), wire.len())
                .expect("effects");
            assert!(fx.has_internal, "{expected}: not seen as internal — R4 would not fire");
            assert_eq!(fx.internal_ops, vec![expected.to_string()]);
        }
    }

    /// Upstream's omissions are ours: `refund_to` absent, `args` empty, a
    /// zero deposit. Their serializer SKIPS these fields, and a decoder that
    /// required them would refuse requests the chain executes happily.
    #[test]
    fn upstream_omits_defaults_and_we_accept_the_omission() {
        let request = Request {
            internal: vec![],
            external: vec![NearPromise {
                receiver_id: acc("a.near"),
                refund_to: None,
                actions: vec![NearAction::FunctionCall(FunctionCall {
                    function_name: "unknown_method".to_string(),
                    args: Vec::new(),
                    deposit: NearToken::from_yoctonear(0),
                    gas: Gas::from_gas(0),
                    gas_weight: Default::default(),
                })],
            }],
        };
        let wire = serde_json::json!({ "request": request }).to_string();
        assert!(!wire.contains("refund_to"), "upstream still omits refund_to: {wire}");

        let fx = effects(&decode(wire.as_bytes()).expect("decode"), wire.len()).expect("effects");
        assert!(fx.refund_tos.is_empty());
        // An unlisted method is unstatable, deposit or not — fail-closed.
        assert_eq!(fx.unknown_fund_moving.len(), 1);
    }

    /// The one place upstream is looser than we were: `NearGas` writes as a
    /// number, `NearToken` as a string. We refused the number form once, which
    /// would have denied requests built with their own types.
    #[test]
    fn gas_and_token_are_written_the_way_upstream_writes_them() {
        let request = Request {
            internal: vec![],
            external: vec![NearPromise {
                receiver_id: acc("a.near"),
                refund_to: None,
                actions: vec![NearAction::FunctionCall(FunctionCall {
                    function_name: "ft_transfer".to_string(),
                    args: br#"{"receiver_id":"b.near","amount":"5"}"#.to_vec(),
                    deposit: NearToken::from_yoctonear(1),
                    gas: Gas::from_tgas(30),
                    gas_weight: Default::default(),
                })],
            }],
        };
        let wire = serde_json::json!({ "request": request }).to_string();
        let fx = effects(&decode(wire.as_bytes()).expect("decode"), wire.len()).expect("effects");
        assert_eq!(fx.total_gas, Gas::from_tgas(30).as_gas());
        assert_eq!(fx.native_total, 1);
    }
}
