//! Golden vectors taken from the HoS wallet's OWN test suite.
//!
//! Source: `houseofstake/tla-contracts`, tag `valhalla-2026-08` (`5d22acf`),
//! `contracts/hos-wallet/src/tests.rs`. Each case below is one of their tests,
//! transcribed to the wire form the request would actually take, and asserted
//! against OUR verdict.
//!
//! Why this file exists. [`crate::hos`] mirrors the contract's spend rules so a
//! doomed request is refused before it costs gas, with the rule named instead
//! of a panic string. A mirror is only worth having while it still reflects:
//! the value of every rule in it is that it agrees with the chain, and reading
//! the source once is not a way to keep agreeing. These are the authority's own
//! cases, so when they bump the contract, running this file says whether our
//! mirror moved with it.
//!
//! What "agree" means here, precisely:
//!
//! * where they `should_panic`, the class we REPORT — the first violation, the
//!   only one the caller sees — must be the one the panic maps to (the table in
//!   `.idea/vlock-0819-report.md` §4, itself the literal constants of their
//!   `error.rs`). Merely producing it somewhere in the list is not agreement:
//!   the owner acts on the sentence they are given, and the wrong one sends
//!   them to fix something that cannot be fixed;
//! * where their test passes, we must produce NO violation. A false refusal is
//!   the failure mode a mirror is most prone to and the one an owner feels: a
//!   request the chain would have executed, stopped by us.
//!
//! Deliberately NOT mirrored: their tests about who may WRITE a grant
//! (`assert_grantable`, `TOKEN_LISTED_TWICE`, `EMPTY_ITEM_GRANT`) and about
//! rotation. We never write a grant, and rotation is handled by the binding
//! lifecycle, not by admission.

use crate::binding::{BindingProfile, HosLease, VerifiedState, Violation};
use crate::hos::AgentStatusView;
use crate::wallet_request_decode::{decode, effects, EffectsSet};

/// THEIR fixture's collection id, copied from `tests.rs` line for line.
///
/// Not an account of ours, on any network — nothing needs to exist under this
/// name and nothing here should ever be renamed to something we own. It is a
/// string in their unit tests, and these vectors only mean anything while they
/// are their cases rather than ours.
///
/// What this stands in for in production is read from the CHAIN, never from a
/// constant: `nft_item_info().collection_id` on the leased account itself. The
/// rule under test — a spend grant may not move the account's own name — is
/// plain string equality against that value, so it is network-agnostic and
/// the spelling below is irrelevant to it.
const THEIR_FIXTURE_COLLECTION_ID: &str = "registry.testnet";

const NOW_NS: u64 = 1_000_000;
const HOUR_NS: u64 = 3_600_000_000_000;

/// base64 of a JSON literal — how `FunctionCall.args` travels.
fn args(json: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(json)
}

/// Their `ft_transfer(token, to, amount)` fixture. Note `U128` serializes as a
/// STRING, which is what makes our decoder's strictness correct.
fn ft_transfer(token: &str, to: &str, amount: u128) -> String {
    format!(
        r#"{{"receiver_id":"{token}","actions":[{{"action":"function_call","payload":{{
            "function_name":"ft_transfer","args":"{}","deposit":"1"}}}}]}}"#,
        args(&format!(
            r#"{{"receiver_id":"{to}","amount":"{amount}"}}"#
        ))
    )
}

/// Their `nft_transfer(collection, to, token_id)` fixture.
fn nft_transfer(collection: &str, to: &str, token_id: &str) -> String {
    format!(
        r#"{{"receiver_id":"{collection}","actions":[{{"action":"function_call","payload":{{
            "function_name":"nft_transfer","args":"{}","deposit":"1"}}}}]}}"#,
        args(&format!(
            r#"{{"receiver_id":"{to}","token_id":"{token_id}"}}"#
        ))
    )
}

/// Their `send(to, amount)` fixture: a plain native transfer.
fn send(to: &str, yocto: u128) -> String {
    format!(
        r#"{{"receiver_id":"{to}","actions":[{{"action":"transfer","payload":{{"amount":"{yocto}"}}}}]}}"#
    )
}

fn fx_of(promises: &[String]) -> EffectsSet {
    let json = format!(r#"{{"request":{{"external":[{}]}}}}"#, promises.join(","));
    let envelope = decode(json.as_bytes()).unwrap_or_else(|e| panic!("decode failed: {e}\n{json}"));
    effects(&envelope, json.len()).unwrap_or_else(|e| panic!("effects failed: {e}\n{json}"))
}

/// A grant as `hos_agent_status` reports it.
struct Grant {
    receivers: Vec<&'static str>,
    budget_yocto: u128,
    spent_yocto: u128,
    tokens: Vec<(&'static str, u128, u128)>,
    items: Vec<(&'static str, Vec<&'static str>)>,
    expires_at: u64,
    /// `env::account_balance()` in their fixture — 10 NEAR, from `ctx`.
    balance_yocto: u128,
    /// Whether the account has a grant at all. `false` is their
    /// "installed but never granted" fixture, and it is the DOOR refusing —
    /// see [`verdict`], which then reports nothing else.
    grant_present: bool,
    /// `self.reserve()` in their fixture: storage byte cost × storage usage,
    /// plus `RENTER_BUFFER` (5 millinear). Zero by default so that the
    /// reserve rule stays out of the way of every vector that is not about it
    /// — with a zero floor, `balance - total >= 0` holds for any amounts,
    /// including ones larger than the balance.
    reserve_yocto: u128,
}

impl Default for Grant {
    fn default() -> Self {
        Grant {
            receivers: vec!["carol.testnet"],
            budget_yocto: 0,
            spent_yocto: 0,
            tokens: Vec::new(),
            items: Vec::new(),
            expires_at: NOW_NS + HOUR_NS,
            balance_yocto: NEAR * 10,
            grant_present: true,
            reserve_yocto: 0,
        }
    }
}

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;

impl Grant {
    fn state(&self) -> VerifiedState {
        let tokens: serde_json::Map<String, serde_json::Value> = self
            .tokens
            .iter()
            .map(|(t, budget, spent)| {
                (
                    (*t).to_string(),
                    serde_json::json!({ "budget": budget.to_string(), "spent": spent.to_string() }),
                )
            })
            .collect();
        let items: serde_json::Map<String, serde_json::Value> = self
            .items
            .iter()
            .map(|(c, ids)| ((*c).to_string(), serde_json::json!(ids)))
            .collect();
        VerifiedState::HosLease {
            status: AgentStatusView {
                extension_enabled: true,
                grant: self.grant_present.then(|| serde_json::json!({
                    "receivers": self.receivers,
                    "budget_yocto": self.budget_yocto.to_string(),
                    "spent_yocto": self.spent_yocto.to_string(),
                    "tokens": tokens,
                    "items": items,
                    "expires_at": self.expires_at.to_string(),
                })),
                state: "Active".into(),
                frozen: "Unfrozen".into(),
                lease_until_ns: (NOW_NS + HOUR_NS).to_string(),
                reserve_yocto: self.reserve_yocto.to_string(),
                impl_version: 6,
            },
        }
    }
}

/// Our full verdict for one request, assembled exactly as the coordinator's
/// pre-flight assembles it — which is the contract's own order. Kept in step
/// with `preflight_extension_call` deliberately: a harness that ordered them
/// differently would pass while the API answered something else.
///
/// Three stages, because the contract has three:
///
/// * the DOOR — `charge_spend` reads the grant and its expiry once, before any
///   promise. When that refuses, nothing downstream ran, so nothing downstream
///   is reported ([`crate::binding::Violation::answers_alone`]);
/// * PER PROMISE — `check_own_collection` mirrors the guard at the very top of
///   `charge_token_call`, ahead of its method allowlist and any item or budget
///   rule; `admission` mirrors the rest of `charge_spend`;
/// * the RESERVE — `assert_within_reserve`, which `execute_request` reaches
///   only after `charge_spend` has returned.
///
/// The order matters to these vectors because only the FIRST violation reaches
/// the caller, so it is the one [`refused_as`] pins.
fn verdict(fx: &EffectsSet, grant: &Grant, now_ns: u64) -> Vec<Violation> {
    let admitted = HosLease::admission(fx, &grant.state(), now_ns);
    if admitted.first().is_some_and(|v| v.answers_alone()) {
        return admitted;
    }

    let mut v = HosLease::check_own_collection(fx, THEIR_FIXTURE_COLLECTION_ID);
    v.extend(admitted);
    if let VerifiedState::HosLease { status } = &grant.state() {
        v.extend(HosLease::check_reserve(fx, status, grant.balance_yocto));
    }
    v
}

/// The class the CALLER is told, which is the first violation in list order.
///
/// Separate from [`classes`] because that one sorts, and a sorted list cannot
/// answer this question — it was hiding the ordering entirely.
fn reported_class(v: &[Violation]) -> Option<String> {
    v.first().map(Violation::class)
}

/// The distinct classes a verdict carries, sorted — for messages and for
/// "exactly this set", never for "which one is reported".
fn classes(v: &[Violation]) -> Vec<String> {
    let mut out: Vec<String> = v
        .iter()
        .map(|x| match x.subcode {
            Some(sub) => format!("{}:{}", x.rule, sub),
            None => x.rule.to_string(),
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Their test panicked; ours must refuse with the class the panic maps to.
#[track_caller]
fn refused_as(their_test: &str, fx: &EffectsSet, grant: &Grant, expected: &str) {
    let v = verdict(fx, grant, NOW_NS);
    assert!(
        !v.is_empty(),
        "{their_test}: the contract panics on this request and we let it through"
    );
    // FIRST, not merely present. Only the first violation reaches the caller
    // (`preflight_extension_call` answers with `violations.first()`), so
    // "somewhere in the list" would let a vector pass while the owner is told
    // a different rule — and the wrong rule sends them to fix the wrong thing.
    // This caught exactly one case: a name transfer to the account's own
    // collection reported `item_not_granted`, which reads as "add the item to
    // the grant" for an item that is ungrantable by construction.
    let reported = reported_class(&v);
    assert_eq!(
        reported.as_deref(),
        Some(expected),
        "{their_test}: the caller would be told {reported:?}, not '{expected}' (all: {:?})",
        classes(&v)
    );
}

/// Their test passed; ours must not refuse. This direction is the one worth
/// guarding: a mirror that refuses too much stops requests the chain accepts.
#[track_caller]
fn accepted(their_test: &str, fx: &EffectsSet, grant: &Grant) {
    let v = verdict(fx, grant, NOW_NS);
    assert!(
        v.is_empty(),
        "{their_test}: the contract executes this request and we refuse it: {:?}",
        classes(&v)
    );
}

// ---------------------------------------------------------------------------
// The grant itself
// ---------------------------------------------------------------------------

#[test]
fn an_installed_extension_cannot_spend_without_a_grant() {
    let fx = fx_of(&[send("carol.testnet", 1_000_000_000_000_000_000_000)]);
    // Through `verdict`, not `admission` directly. Calling the inner function
    // is what let this vector pass while the assembled answer was wrong: the
    // door refusal was there, and something else was being reported ahead of
    // it. Every vector goes through the same assembly the API uses.
    refused_as(
        "an_installed_extension_cannot_spend_without_a_grant",
        &fx,
        &Grant { grant_present: false, ..Default::default() },
        "grant_missing",
    );
}

/// No grant AND a request that would break a promise-level rule.
///
/// The chain never gets to the promise: `charge_spend` reads the grant, finds
/// none, and panics. So `grant_missing` is the whole answer, and the
/// own-collection refusal — true as it is — must not be the sentence the owner
/// reads, because it would send them to rewrite a request whose only problem is
/// that nobody granted them anything.
///
/// Written after the ordering fix that introduced exactly this fault: the
/// own-collection rule was moved ahead of `admission` to fix a different
/// misreport, and it jumped the door as well.
#[test]
fn the_door_answers_alone_even_when_a_promise_rule_also_applies() {
    let fx = fx_of(&[nft_transfer(
        THEIR_FIXTURE_COLLECTION_ID,
        "carol.testnet",
        "bob.tla.testnet",
    )]);
    let v = verdict(&fx, &Grant { grant_present: false, ..Default::default() }, NOW_NS);
    assert_eq!(
        classes(&v),
        vec!["grant_missing"],
        "with no grant the door answers ALONE — nothing downstream ran, so nothing downstream \
         may be reported"
    );
}

#[test]
fn a_granted_extension_may_spend_within_its_scope() {
    let fx = fx_of(&[send("carol.testnet", 1_000_000_000_000_000_000_000)]);
    accepted(
        "a_granted_extension_may_spend_within_its_scope",
        &fx,
        &Grant { budget_yocto: 10_000_000_000_000_000_000_000, ..Default::default() },
    );
}

#[test]
fn a_granted_extension_cannot_pay_an_ungranted_receiver() {
    let fx = fx_of(&[send("attacker.testnet", 1_000_000_000_000_000_000_000)]);
    refused_as(
        "a_granted_extension_cannot_pay_an_ungranted_receiver",
        &fx,
        &Grant { budget_yocto: 10_000_000_000_000_000_000_000, ..Default::default() },
        "receiver_not_granted",
    );
}

#[test]
fn a_granted_extension_cannot_redirect_refunds_past_the_allowlist() {
    // Their case: a PLAIN transfer to a granted receiver, with refund_to set.
    // The refusal is the refund target, and it applies to any promise —
    // reading it as a token-call rule only would let this through.
    let promise = format!(
        r#"{{"receiver_id":"carol.testnet","refund_to":"attacker.testnet",
            "actions":[{{"action":"transfer","payload":{{"amount":"1000000000000000000000"}}}}]}}"#
    );
    refused_as(
        "a_granted_extension_cannot_redirect_refunds_past_the_allowlist",
        &fx_of(&[promise]),
        &Grant { budget_yocto: 10_000_000_000_000_000_000_000, ..Default::default() },
        "grant_shape_violation:refund_target_not_allowed",
    );
}

#[test]
fn a_granted_extension_cannot_exceed_the_cap() {
    let fx = fx_of(&[send("carol.testnet", 2_000_000_000_000_000_000_000)]);
    refused_as(
        "a_granted_extension_cannot_exceed_the_cap",
        &fx,
        &Grant { budget_yocto: 1_000_000_000_000_000_000_000, ..Default::default() },
        "grant_exhausted",
    );
}

#[test]
fn a_grant_stops_working_once_it_expires() {
    let fx = fx_of(&[send("carol.testnet", 1_000_000_000_000_000_000_000)]);
    let grant = Grant { budget_yocto: 10_000_000_000_000_000_000_000, ..Default::default() };
    // Their clock: two hours on, against a one-hour grant.
    let v = verdict(&fx, &grant, NOW_NS + 2 * HOUR_NS);
    assert_eq!(classes(&v), vec!["grant_expired"]);
}

// ---------------------------------------------------------------------------
// Fungible tokens
// ---------------------------------------------------------------------------

#[test]
fn a_grantee_cannot_reach_a_token_the_grant_never_named() {
    let fx = fx_of(&[ft_transfer("usdt.testnet", "carol.testnet", 1)]);
    refused_as(
        "a_grantee_cannot_reach_a_token_the_grant_never_named",
        &fx,
        &Grant {
            budget_yocto: 1_000_000_000_000_000_000_000,
            tokens: vec![("usdc.testnet", 100, 0)],
            ..Default::default()
        },
        "token_not_granted",
    );
}

#[test]
fn a_grantee_can_move_a_granted_token_within_its_budget() {
    // Their assertion alongside the pass: the yocto a token demands as proof
    // of signature is NOT spend. Hence a ZERO native budget here — if we
    // charged that yocto, this legal request would be refused.
    let fx = fx_of(&[ft_transfer("usdc.testnet", "carol.testnet", 40)]);
    accepted(
        "a_grantee_can_move_a_granted_token_within_its_budget",
        &fx,
        &Grant { tokens: vec![("usdc.testnet", 100, 0)], ..Default::default() },
    );
}

#[test]
fn a_token_budget_bounds_the_amount_inside_the_arguments() {
    let fx = fx_of(&[ft_transfer("usdc.testnet", "carol.testnet", 101)]);
    refused_as(
        "a_token_budget_bounds_the_amount_inside_the_arguments",
        &fx,
        &Grant { tokens: vec![("usdc.testnet", 100, 0)], ..Default::default() },
        "token_budget_exceeded",
    );
}

#[test]
fn token_spending_accumulates_across_calls() {
    // Their test spends 60 twice against a cap of 100. We read the meter from
    // the view rather than keeping one, so the second call is the state their
    // first call left: spent = 60.
    let fx = fx_of(&[ft_transfer("usdc.testnet", "carol.testnet", 60)]);
    accepted(
        "token_spending_accumulates_across_calls (first)",
        &fx,
        &Grant { tokens: vec![("usdc.testnet", 100, 0)], ..Default::default() },
    );
    refused_as(
        "token_spending_accumulates_across_calls (second)",
        &fx,
        &Grant { tokens: vec![("usdc.testnet", 100, 60)], ..Default::default() },
        "token_budget_exceeded",
    );
}

#[test]
fn topping_up_a_grant_does_not_un_spend_the_meter() {
    // After 60 spent, the ceiling is raised to 200 and `spent` CARRIES. The
    // remaining room is 140, not 200: a request for 150 must still refuse.
    let raised = Grant { tokens: vec![("usdc.testnet", 200, 60)], ..Default::default() };
    accepted(
        "topping_up_a_grant_does_not_un_spend_the_meter (within the carried room)",
        &fx_of(&[ft_transfer("usdc.testnet", "carol.testnet", 140)]),
        &raised,
    );
    refused_as(
        "topping_up_a_grant_does_not_un_spend_the_meter (past it)",
        &fx_of(&[ft_transfer("usdc.testnet", "carol.testnet", 150)]),
        &raised,
        "token_budget_exceeded",
    );
}

#[test]
fn revoking_a_grant_resets_the_meter() {
    // Revoke then re-grant: `spent` is zero again, and the full 100 is
    // available. Reading the meter from the view is what makes this free.
    accepted(
        "revoking_a_grant_resets_the_meter",
        &fx_of(&[ft_transfer("usdc.testnet", "carol.testnet", 100)]),
        &Grant { tokens: vec![("usdc.testnet", 100, 0)], ..Default::default() },
    );
}

#[test]
fn a_token_call_cannot_pay_an_account_outside_the_grant() {
    // The receiver checked is the one DECODED FROM THE ARGUMENTS, not the
    // token contract. Checking the promise receiver instead would demand the
    // token contract be granted, which it never is.
    let fx = fx_of(&[ft_transfer("usdc.testnet", "attacker.testnet", 1)]);
    refused_as(
        "a_token_call_cannot_pay_an_account_outside_the_grant",
        &fx,
        &Grant { tokens: vec![("usdc.testnet", 100, 0)], ..Default::default() },
        "receiver_not_granted",
    );
}

// ---------------------------------------------------------------------------
// The form a granted call must take
// ---------------------------------------------------------------------------

#[test]
fn a_grantee_cannot_call_ft_transfer_call() {
    let promise = format!(
        r#"{{"receiver_id":"usdc.testnet","actions":[{{"action":"function_call","payload":{{
            "function_name":"ft_transfer_call","args":"{}","deposit":"1"}}}}]}}"#,
        args(r#"{"receiver_id":"carol.testnet","amount":"1","msg":""}"#)
    );
    refused_as(
        "a_grantee_cannot_call_ft_transfer_call",
        &fx_of(&[promise]),
        &Grant { tokens: vec![("usdc.testnet", 100, 0)], ..Default::default() },
        "grant_shape_violation:grant_method_not_allowed",
    );
}

#[test]
fn a_grantee_cannot_call_nft_transfer_call() {
    let promise = format!(
        r#"{{"receiver_id":"art.testnet","actions":[{{"action":"function_call","payload":{{
            "function_name":"nft_transfer_call","args":"{}","deposit":"1"}}}}]}}"#,
        args(r#"{"receiver_id":"carol.testnet","token_id":"1041","msg":""}"#)
    );
    refused_as(
        "a_grantee_cannot_call_nft_transfer_call",
        &fx_of(&[promise]),
        &Grant { items: vec![("art.testnet", vec!["1041"])], ..Default::default() },
        "grant_shape_violation:grant_method_not_allowed",
    );
}

#[test]
fn a_grantee_cannot_hand_out_an_approval() {
    let promise = format!(
        r#"{{"receiver_id":"art.testnet","actions":[{{"action":"function_call","payload":{{
            "function_name":"nft_approve","args":"{}","deposit":"1"}}}}]}}"#,
        args(r#"{"token_id":"1041","account_id":"attacker.testnet"}"#)
    );
    refused_as(
        "a_grantee_cannot_hand_out_an_approval",
        &fx_of(&[promise]),
        &Grant { items: vec![("art.testnet", vec!["1041"])], ..Default::default() },
        "grant_shape_violation:grant_method_not_allowed",
    );
}

#[test]
fn a_token_call_carrying_an_unreadable_argument_is_refused() {
    // Their `surprise` field, verbatim. The contract parses these arguments
    // with deny_unknown_fields, so it cannot read them at all.
    let promise = format!(
        r#"{{"receiver_id":"usdc.testnet","actions":[{{"action":"function_call","payload":{{
            "function_name":"ft_transfer","args":"{}","deposit":"1"}}}}]}}"#,
        args(r#"{"receiver_id":"carol.testnet","amount":"1","surprise":"unread by this contract"}"#)
    );
    refused_as(
        "a_token_call_carrying_an_unreadable_argument_is_refused",
        &fx_of(&[promise]),
        &Grant { tokens: vec![("usdc.testnet", 100, 0)], ..Default::default() },
        "grant_shape_violation:grant_args_unreadable",
    );
}

#[test]
fn a_token_call_cannot_carry_a_deposit_of_its_own() {
    let promise = format!(
        r#"{{"receiver_id":"usdc.testnet","actions":[{{"action":"function_call","payload":{{
            "function_name":"ft_transfer","args":"{}","deposit":"1000000000000000000000000"}}}}]}}"#,
        args(r#"{"receiver_id":"carol.testnet","amount":"1"}"#)
    );
    refused_as(
        "a_token_call_cannot_carry_a_deposit_of_its_own",
        &fx_of(&[promise]),
        &Grant { tokens: vec![("usdc.testnet", 100, 0)], ..Default::default() },
        "grant_shape_violation:grant_call_deposit",
    );
}

#[test]
fn a_token_call_cannot_smuggle_a_transfer_alongside_it() {
    let promise = format!(
        r#"{{"receiver_id":"usdc.testnet","actions":[
            {{"action":"function_call","payload":{{
                "function_name":"ft_transfer","args":"{}","deposit":"1"}}}},
            {{"action":"transfer","payload":{{"amount":"1000000000000000000000000"}}}}]}}"#,
        args(r#"{"receiver_id":"carol.testnet","amount":"1"}"#)
    );
    refused_as(
        "a_token_call_cannot_smuggle_a_transfer_alongside_it",
        &fx_of(&[promise]),
        &Grant { tokens: vec![("usdc.testnet", 100, 0)], ..Default::default() },
        "grant_shape_violation:grant_call_must_stand_alone",
    );
}

#[test]
fn a_grantee_cannot_deploy_code_through_a_state_init() {
    let promise = r#"{"receiver_id":"carol.testnet","actions":[
        {"action":"deterministic_state_init","payload":{
            "state_init":{"v1":{"code":"global.testnet"}},
            "deposit":"1000000000000000000000"}}]}"#
        .to_string();
    refused_as(
        "a_grantee_cannot_deploy_code_through_a_state_init",
        &fx_of(&[promise]),
        &Grant { budget_yocto: 1_000_000_000_000_000_000_000_000, ..Default::default() },
        "grant_shape_violation:grant_action_not_allowed",
    );
}

// ---------------------------------------------------------------------------
// Non-fungible items: fenced by identity, never metered
// ---------------------------------------------------------------------------

#[test]
fn a_grantee_can_move_an_item_the_grant_fenced() {
    // Note the grant: no `tokens` entry for the collection and a zero native
    // budget. An item costs no budget at all — demanding one would refuse
    // every legal NFT transfer.
    let fx = fx_of(&[nft_transfer("art.testnet", "carol.testnet", "1041")]);
    accepted(
        "a_grantee_can_move_an_item_the_grant_fenced",
        &fx,
        &Grant {
            items: vec![("art.testnet", vec!["1041", "1055"])],
            ..Default::default()
        },
    );
}

#[test]
fn an_item_fence_is_identity_not_a_count() {
    // Their test moves the same item three times and expects all three to
    // pass: the fence is identity, so nothing is consumed. For us that means
    // the same grant state admits it every time.
    let fx = fx_of(&[nft_transfer("art.testnet", "carol.testnet", "1041")]);
    let grant = Grant { items: vec![("art.testnet", vec!["1041"])], ..Default::default() };
    for _ in 0..3 {
        accepted("an_item_fence_is_identity_not_a_count", &fx, &grant);
    }
}

#[test]
fn a_grantee_cannot_move_an_item_outside_the_fence() {
    let fx = fx_of(&[nft_transfer("art.testnet", "carol.testnet", "9000")]);
    refused_as(
        "a_grantee_cannot_move_an_item_outside_the_fence",
        &fx,
        &Grant { items: vec![("art.testnet", vec!["1041"])], ..Default::default() },
        "item_not_granted",
    );
}

#[test]
fn a_grantee_cannot_reach_a_collection_the_grant_never_named() {
    let fx = fx_of(&[nft_transfer("other.testnet", "carol.testnet", "1041")]);
    refused_as(
        "a_grantee_cannot_reach_a_collection_the_grant_never_named",
        &fx,
        &Grant { items: vec![("art.testnet", vec!["1041"])], ..Default::default() },
        "item_not_granted",
    );
}

#[test]
fn a_granted_item_transfer_cannot_spend_an_approval() {
    let promise = format!(
        r#"{{"receiver_id":"art.testnet","actions":[{{"action":"function_call","payload":{{
            "function_name":"nft_transfer","args":"{}","deposit":"1"}}}}]}}"#,
        args(r#"{"receiver_id":"carol.testnet","token_id":"1041","approval_id":7}"#)
    );
    refused_as(
        "a_granted_item_transfer_cannot_spend_an_approval",
        &fx_of(&[promise]),
        &Grant { items: vec![("art.testnet", vec!["1041"])], ..Default::default() },
        "grant_shape_violation:grant_approval_not_allowed",
    );
}

#[test]
fn an_item_transfer_cannot_pay_an_account_outside_the_grant() {
    let fx = fx_of(&[nft_transfer("art.testnet", "attacker.testnet", "1041")]);
    refused_as(
        "an_item_transfer_cannot_pay_an_account_outside_the_grant",
        &fx,
        &Grant { items: vec![("art.testnet", vec!["1041"])], ..Default::default() },
        "receiver_not_granted",
    );
}

// ---------------------------------------------------------------------------
// The account's own names are never spendable
// ---------------------------------------------------------------------------

#[test]
fn the_registry_is_refused_at_spend_time_on_the_token_path_too() {
    // A grant cannot legally NAME the registry, but one written before a
    // migration still can, which is why the contract checks again at spend
    // time. Their fixture grants usdc and then calls the registry.
    let fx = fx_of(&[ft_transfer(THEIR_FIXTURE_COLLECTION_ID, "carol.testnet", 1)]);
    refused_as(
        "the_registry_is_refused_at_spend_time_on_the_token_path_too",
        &fx,
        &Grant { tokens: vec![("usdc.testnet", 1_000, 0)], ..Default::default() },
        "own_collection_refused",
    );
}

#[test]
fn a_grantee_cannot_move_a_name_even_if_the_registry_slipped_into_a_grant() {
    let fx = fx_of(&[nft_transfer(THEIR_FIXTURE_COLLECTION_ID, "carol.testnet", "bob.tla.testnet")]);
    refused_as(
        "a_grantee_cannot_move_a_name_even_if_the_registry_slipped_into_a_grant",
        &fx,
        &Grant { items: vec![("art.testnet", vec!["1041"])], ..Default::default() },
        "own_collection_refused",
    );
}

// ---------------------------------------------------------------------------
// The one case the mirror must NOT copy
// ---------------------------------------------------------------------------

#[test]
fn the_owner_may_still_direct_refunds_but_that_is_not_our_lane() {
    // Their `the_owner_may_still_direct_refunds` passes because `charge_spend`
    // returns early for the OWNER — no grant applies to them at all. Our
    // executor is never the owner: it is an extension with a grant, so the
    // same request is refused for us, and correctly.
    //
    // Recorded here so nobody reads their passing test as evidence that a
    // granted extension may set refund_to. That misreading is exactly what
    // the VLOCK-0819 review corrected.
    let promise = r#"{"receiver_id":"carol.testnet","refund_to":"carol.testnet",
        "actions":[{"action":"transfer","payload":{"amount":"1000000000000000000000"}}]}"#
        .to_string();
    refused_as(
        "the_owner_may_still_direct_refunds (as an EXTENSION, not the owner)",
        &fx_of(&[promise]),
        &Grant { budget_yocto: 10_000_000_000_000_000_000_000, ..Default::default() },
        "grant_shape_violation:refund_target_not_allowed",
    );
}

// ---------------------------------------------------------------------------
// The balance reserve (`assert_within_reserve`)
// ---------------------------------------------------------------------------
//
// Their two cases run as the OWNER, who never reaches `charge_spend` — the
// reserve is the only rule that applies to them. Our executor is an extension,
// so the grant has to cover the same spend for the request to reach the
// reserve at all; the grants below do exactly that and nothing more, leaving
// the reserve as the only thing under test.
//
// Their fixture's floor is `self.reserve()` = storage byte cost × storage
// usage + `RENTER_BUFFER` (5 millinear), which is not computable off chain and
// is why `reserve_yocto` is a reported field rather than a derived one. The
// exact number does not change either verdict: with a 10 NEAR balance, 1 NEAR
// out clears any floor below 9 NEAR and 10 NEAR out clears none above zero.
// The buffer alone is used, as the smallest floor the contract can ever have.

const RENTER_BUFFER: u128 = 5 * (NEAR / 1_000);

#[test]
fn outbound_spending_is_allowed_within_the_reserve() {
    let fx = fx_of(&[send("carol.testnet", NEAR)]);
    accepted(
        "outbound_spending_is_allowed_within_the_reserve",
        &fx,
        &Grant {
            budget_yocto: NEAR,
            balance_yocto: NEAR * 10,
            reserve_yocto: RENTER_BUFFER,
            ..Default::default()
        },
    );
}

#[test]
fn outbound_spending_cannot_breach_the_balance_reserve() {
    // The whole balance, leaving nothing for the floor the account needs to
    // keep its own storage paid. `RESERVE_BREACH` on chain.
    let fx = fx_of(&[send("carol.testnet", NEAR * 10)]);
    refused_as(
        "outbound_spending_cannot_breach_the_balance_reserve",
        &fx,
        &Grant {
            budget_yocto: NEAR * 10,
            balance_yocto: NEAR * 10,
            reserve_yocto: RENTER_BUFFER,
            ..Default::default()
        },
        "insufficient_vs_reserve",
    );
}
