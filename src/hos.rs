//! The `hos_lease` binding profile — House of Stake "Agent Connect".
//!
//! A custody wallet bound to a LEASED, keyless asset account (`agent.tla`).
//! The wallet's own NEAR implicit account acts as the EXECUTOR: it is
//! registered in the asset account's control set and is the only identity
//! that signs the outer transaction.
//!
//! This module holds the mode's chain types and its verification rules; the
//! trait it implements, the dispatch and everything shared between modes live
//! in [`crate::binding`]. Both registries compile into the measured keystore
//! image, so nothing outside the enclave can claim "version N parses with
//! decoder M" and steer an unknown schema into a known parser.

use serde::{Deserialize, Serialize};

use crate::binding::{
    BindingFault, BindingKind, BindingProfile, ChainVersion, HosLease, Stage, VerifiedState,
    Violation,
};
use crate::wallet_request_decode::{EffectsSet, ShapeFact, TokenAmount};

/// `(impl_version, decoder_version)` pairs this build can evaluate.
///
/// Versions below 6 are absent on purpose: their grants did not bound token
/// movement on chain, so no lane we would open against them is acceptable.
pub const DECODER_FOR_IMPL: &[(u32, u32)] = &[(6, 1)];

/// The decoder that evaluates `impl_version`, or `None` when the version is
/// unsupported (fail closed — the caller must refuse, not guess).
pub fn decoder_for(impl_version: u32) -> Option<u32> {
    DECODER_FOR_IMPL
        .iter()
        .find(|(impl_v, _)| *impl_v == impl_version)
        .map(|(_, decoder)| *decoder)
}

/// `hos_agent_status(extension)` on the asset account — everything needed
/// before signing, in one view call.
///
/// Every default is the value that FAILS verification: an absent
/// `extension_enabled` reads as disabled, an absent `state` is not `"Active"`,
/// an absent `frozen` is not `"Unfrozen"`, an absent lease is expired, an
/// absent `impl_version` (0) is unsupported. A truncated or reshaped response
/// therefore denies rather than permits.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentStatusView {
    #[serde(default)]
    pub extension_enabled: bool,
    /// The spend grant, opaque here: identity checks do not read it, and the
    /// decoder release will type it when something starts to.
    #[serde(default)]
    pub grant: Option<serde_json::Value>,
    /// The contract's `OperatingState`: `Active` | `Listed` | `Settling` |
    /// `Suspended` | `Parked`. Anything but `Active` blocks execution there
    /// (`blocking_condition`), so anything but `Active` refuses here.
    /// Note there is no `Expired` state — an ended lease shows up in
    /// `lease_until_ns`, and `Frozen` is the separate field below.
    #[serde(default)]
    pub state: String,
    /// The contract's `FreezeState`: `Unfrozen` | `SelfFrozen` |
    /// `AuthorityFrozen`. Anything but `Unfrozen` means frozen.
    #[serde(default)]
    pub frozen: String,
    /// Nanoseconds since epoch, as a decimal string (near-sdk `U64`).
    #[serde(default = "zero_string")]
    pub lease_until_ns: String,
    /// Balance floor in yoctoNEAR, as a decimal string. Not an identity check —
    /// carried for the spend pre-flight that reads the same view.
    #[serde(default = "zero_string")]
    pub reserve_yocto: String,
    #[serde(default)]
    pub impl_version: u32,
}

fn zero_string() -> String {
    "0".to_string()
}

impl BindingProfile for HosLease {
    const KIND: BindingKind = BindingKind::HosLease;
    type ChainStatus = AgentStatusView;

    /// Read `hos_agent_status` fail-closed. `Ok` means the executor's lane is
    /// live RIGHT NOW: enabled, active, unfrozen, leased, on a supported
    /// version. `now_ns` comes from the caller so the check stays pure
    /// (reproducible vectors, no clock in this crate).
    fn verify(status: &AgentStatusView, now_ns: u64) -> Result<VerifiedState, BindingFault> {
        if !status.extension_enabled {
            return Err(BindingFault::ExtensionDisabled);
        }
        if status.frozen != "Unfrozen" {
            return Err(BindingFault::Frozen(status.frozen.clone()));
        }
        match status.state.as_str() {
            "Active" => {}
            "Expired" => return Err(BindingFault::StateExpired),
            other => return Err(BindingFault::StateNotActive(other.to_string())),
        }
        let lease_until: u64 = status.lease_until_ns.parse().map_err(|_| {
            BindingFault::Malformed(format!("lease_until_ns='{}'", status.lease_until_ns))
        })?;
        if lease_until <= now_ns {
            return Err(BindingFault::LeaseExpired);
        }
        if decoder_for(status.impl_version).is_none() {
            return Err(BindingFault::ImplVersionUnsupported(status.impl_version));
        }
        Ok(VerifiedState::HosLease {
            status: status.clone(),
        })
    }

    fn version_gate(version: &ChainVersion) -> Result<u32, BindingFault> {
        match version {
            ChainVersion::ImplVersion(v) => {
                decoder_for(*v).ok_or(BindingFault::ImplVersionUnsupported(*v))
            }
            ChainVersion::CodeHash(_) => Err(BindingFault::EvidenceMismatch),
        }
    }

    /// The leased mode's own layer over the decoded effects: the grant, the
    /// call FORM and the balance reserve. Every rule here mirrors one the
    /// wallet contract enforces on chain (`charge_spend` → `charge_promise`
    /// → `charge_transfer` / `charge_token_call`, plus
    /// `assert_within_reserve`) at `houseofstake/tla-contracts` tag
    /// `valhalla-2026-08` (`5d22acf`) — verified against that source, not
    /// against prose. Refusing here costs no gas and names the exact rule
    /// instead of a panic string. Only ever ADDS refusals; the core's
    /// mode-blind evaluation already ran.
    ///
    /// The reserve rule needs the account's balance, which is a separate
    /// view, so it lives in [`HosLease::check_reserve`] and the caller that
    /// has the balance runs it.
    fn admission(fx: &EffectsSet, st: &VerifiedState, now_ns: u64) -> Vec<Violation> {
        let status = match st {
            VerifiedState::HosLease { status } => status,
            VerifiedState::PersonalAccount { .. } => {
                return vec![Violation {
                    promise_index: None,
                    stage: Stage::Door,
                    rule: "evidence_mismatch",
                    subcode: None,
                    message: "the verified state belongs to personal_account, not the leased mode"
                        .to_string(),
                }]
            }
        };
        let mut violations = Vec::new();

        // The grant comes FIRST, and its absence or expiry answers alone —
        // exactly the contract's order (`charge_spend` reads the grant and
        // checks expiry once, before it looks at a single promise). Reporting
        // a form rule while the real blocker is an expired grant would send
        // the owner to fix the wrong thing.
        let Some(grant_value) = &status.grant else {
            return vec![Violation {
                promise_index: None,
                stage: Stage::Door,
                rule: "grant_missing",
                subcode: None,
                message: "the executor has no spend grant on this account".to_string(),
            }];
        };
        let grant: SpendGrant = match serde_json::from_value(grant_value.clone()) {
            Ok(g) => g,
            Err(e) => {
                return vec![Violation {
                    promise_index: None,
                    stage: Stage::Door,
                    rule: "grant_unreadable",
                    subcode: None,
                    message: format!("the spend grant does not parse: {e}"),
                }]
            }
        };
        match grant.expires_at.parse::<u64>() {
            Ok(expires_at) if expires_at > now_ns => {}
            _ => {
                return vec![Violation {
                    promise_index: None,
                    stage: Stage::Door,
                    rule: "grant_expired",
                    subcode: None,
                    message: "the spend grant has expired (or its expiry is unreadable) — \
                              the owner must issue a new grant"
                        .to_string(),
                }]
            }
        }

        // The FORM a granted request must take. Each fact maps to the panic
        // the contract would raise; they share one error class because a
        // client reacts to all of them the same way (fix the request), and
        // differ by subcode because the owner needs to know which rule.
        //
        // Note what is absent: several `transfer` actions in one promise.
        // `charge_transfer` accepts any number of them — only a promise
        // carrying a CALL must stand alone — so flagging a multi-transfer
        // promise would refuse a request the chain would have executed.
        // The rung each fact carries is the one the CONTRACT checks it at, and
        // they are far apart: `refund_to` is the first thing `charge_promise`
        // looks at, while an unreadable argument is only reached inside
        // `charge_ft_transfer`, five rules later. Collecting them under one
        // loop is fine; reporting them in loop order would not be.
        for fact in &fx.shape_facts {
            let (promise_index, rung, subcode, message) = match fact {
                ShapeFact::RefundToSet { promise_index } => (
                    *promise_index,
                    1,
                    "refund_target_not_allowed",
                    "a granted spend cannot redirect refunds".to_string(),
                ),
                ShapeFact::CallNotStandalone { promise_index } => (
                    *promise_index,
                    2,
                    "grant_call_must_stand_alone",
                    "a granted token call may carry no other action".to_string(),
                ),
                ShapeFact::CallDepositNotOneYocto { promise_index, deposit } => (
                    *promise_index,
                    3,
                    "grant_call_deposit",
                    format!("a granted token call attaches exactly one yocto, not {deposit}"),
                ),
                ShapeFact::NftApprovalIdSet { promise_index } => (
                    *promise_index,
                    7,
                    "grant_approval_not_allowed",
                    "a granted transfer cannot spend an approval".to_string(),
                ),
                ShapeFact::TokenArgsUnknownField { promise_index, field } => (
                    *promise_index,
                    6,
                    "grant_args_unreadable",
                    format!(
                        "granted token call arguments are not readable: the contract refuses \
                         the unknown field '{field}' (only `memo` may accompany the standard \
                         arguments)"
                    ),
                ),
            };
            violations.push(Violation {
                promise_index: Some(promise_index),
                stage: Stage::Promise(rung),
                rule: "grant_shape_violation",
                subcode: Some(subcode),
                message,
            });
        }

        // Methods a grant never covers, whatever the budget says.
        //
        // `charge_token_call` dispatches on the function name and panics on
        // anything but `ft_transfer`/`nft_transfer` — `ft_transfer_call`,
        // `nft_transfer_call`, `nft_approve`, a swap, anything. The core
        // already refuses a call whose effects it cannot state, so today this
        // would be unreachable; it is here so that it STAYS refused when an
        // owner opt-in (`immediate_receiver_only`, plan item K6) starts
        // letting named methods past the core. A profile may only add
        // refusals, and this is the grant's own list, not a borrowed one.
        for u in &fx.unknown_fund_moving {
            let readable_method = u.method == "ft_transfer" || u.method == "nft_transfer";
            violations.push(Violation {
                promise_index: Some(u.promise_index),
                // The method dispatch is rung 5; unreadable arguments are only
                // reached once the method matched, which is rung 6.
                stage: Stage::Promise(if readable_method { 6 } else { 5 }),
                rule: "grant_shape_violation",
                subcode: Some(if readable_method {
                    // The right method, arguments the contract cannot parse.
                    "grant_args_unreadable"
                } else {
                    "grant_method_not_allowed"
                }),
                message: if readable_method {
                    format!(
                        "granted token call arguments are not readable: {} ({})",
                        u.method, u.reason
                    )
                } else {
                    format!(
                        "a spend grant covers ft_transfer and nft_transfer only, never \
                         '{}' on '{}'",
                        u.method, u.contract
                    )
                },
            });
        }

        // Actions a grant never covers.
        for s in &fx.storage_registrations {
            violations.push(Violation {
                promise_index: Some(s.promise_index),
                // A storage registration is a CALL, so it reaches the same
                // method dispatch every other unrecognised method does.
                stage: Stage::Promise(5),
                rule: "grant_shape_violation",
                subcode: Some("grant_method_not_allowed"),
                message: "a spend grant covers ft_transfer and nft_transfer only, because \
                          nothing else states what it moves (storage_deposit is a \
                          personal_account-mode operation)"
                    .to_string(),
            });
        }
        for promise_index in &fx.state_inits {
            violations.push(Violation {
                promise_index: Some(*promise_index),
                // A state-init rides a promise with no call, so the contract
                // meets it in `charge_transfer` — where the receiver is
                // checked BEFORE the "every action is a Transfer" rule.
                stage: Stage::Promise(3),
                rule: "grant_shape_violation",
                subcode: Some("grant_action_not_allowed"),
                message: "a spend grant covers plain transfers and allowlisted token calls \
                          only, never deploying code"
                    .to_string(),
            });
        }

        // Native ceiling. Charged ONLY for promises without a function call:
        // the contract's `charge_transfer` handles those, while a token
        // call's mandated yocto is "protocol overhead rather than spend" and
        // is deliberately left out of the NEAR budget (its own words). Adding
        // it here would refuse a request a yocto short of the ceiling that
        // the chain would have accepted.
        //
        // Accumulated PROMISE BY PROMISE, because the contract does:
        // `charge_transfer` writes `grant.spent_yocto` back before the next
        // promise is charged, so the one that breaches the cap is the one it
        // panics on. A single total would give the same verdict and no
        // address — and with no promise index the refusal cannot be placed in
        // the order the chain would have hit it, which is the whole point of
        // reporting the first one.
        let budget = grant.budget_yocto.parse::<u128>().unwrap_or(0);
        let spent = grant.spent_yocto.parse::<u128>().unwrap_or(u128::MAX);
        let remaining = budget.saturating_sub(spent);
        let mut running = 0u128;
        for (promise_index, amount) in fx.native_per_promise.iter().enumerate() {
            if fx.call_promises.contains(&promise_index) {
                continue;
            }
            running = running.saturating_add(*amount);
            if running > remaining {
                violations.push(Violation {
                    promise_index: Some(promise_index),
                    // Rung 4 on the plain ladder: after the receiver and the
                    // action check, which `charge_transfer` runs first.
                    stage: Stage::Promise(4),
                    rule: "grant_exhausted",
                    subcode: None,
                    message: format!(
                        "spend exceeds the granted cap: {running} > {remaining} remaining \
                         (budget {budget}, spent {spent}); re-granting raises the ceiling, \
                         revoking resets the meter"
                    ),
                });
                // One refusal, at the promise that breached it. Reporting the
                // rest would name promises the chain never reached.
                break;
            }
        }

        // Destinations. The grant's `receivers` are read differently per
        // action, exactly as the contract reads them: a plain transfer is
        // checked against the PROMISE's receiver, a token call against the
        // recipient decoded from its arguments. Checking the promise receiver
        // for a token call would demand the token CONTRACT be granted, which
        // it never is.
        let permitted = |dest: &str| grant.receivers.iter().any(|r| r == dest);
        for (promise_index, receiver) in fx.receivers.iter().enumerate() {
            // A promise that also carries a call is checked by its arguments
            // below; the contract never reaches its transfer arm for one.
            // Every OTHER promise is checked, whatever it carries — including
            // one with no actions at all, which `charge_transfer` still
            // refuses when the receiver is not granted.
            if fx.call_promises.contains(&promise_index) {
                continue;
            }
            if !permitted(receiver) {
                violations.push(Violation {
                    promise_index: Some(promise_index),
                    // Rung 2 on the PLAIN ladder — the first thing
                    // `charge_transfer` checks, before the action rule and
                    // before the budget. The same class sits at rung 8 for a
                    // call promise below, which is why the rung cannot be
                    // recovered from the rule name later.
                    stage: Stage::Promise(2),
                    rule: "receiver_not_granted",
                    subcode: None,
                    message: format!("receiver '{receiver}' is not in the spend grant"),
                });
            }
        }
        for m in &fx.token_moves {
            if !permitted(&m.recipient) {
                violations.push(Violation {
                    promise_index: Some(m.promise_index),
                    // Rung 8 on the CALL ladder: the decoded recipient is only
                    // known once the arguments parsed.
                    stage: Stage::Promise(8),
                    rule: "receiver_not_granted",
                    subcode: None,
                    message: format!("receiver '{}' is not in the spend grant", m.recipient),
                });
            }
            match &m.amount {
                // Fungible tokens are METERED in their own units.
                TokenAmount::Fungible(amount) => match grant.tokens.get(&m.token) {
                    None => violations.push(Violation {
                        promise_index: Some(m.promise_index),
                        // Rung 9: the grant is looked up before the budget on
                        // it can be compared.
                        stage: Stage::Promise(9),
                        rule: "token_not_granted",
                        subcode: None,
                        message: format!("token '{}' is not in the spend grant", m.token),
                    }),
                    Some(budget) => {
                        let cap = budget.budget.parse::<u128>().unwrap_or(0);
                        let used = budget.spent.parse::<u128>().unwrap_or(u128::MAX);
                        if *amount > cap.saturating_sub(used) {
                            violations.push(Violation {
                                promise_index: Some(m.promise_index),
                                stage: Stage::Promise(10),
                                rule: "token_budget_exceeded",
                                subcode: None,
                                message: format!(
                                    "spend exceeds the granted cap for '{}': {amount} > {} remaining",
                                    m.token,
                                    cap.saturating_sub(used)
                                ),
                            });
                        }
                    }
                },
                // Non-fungible items are FENCED, never metered: there is no
                // quantity to count, so the grant names the exact token_ids
                // that may leave and no budget is debited. Charging one here
                // would invent a rule the chain does not have.
                //
                // The contract answers these two apart, and so must we: it
                // looks the collection up first (`COLLECTION_NOT_GRANTED` when
                // the grant never named it) and only then checks the fence
                // (`ITEM_NOT_GRANTED`). One class for both sent the owner to
                // add a token_id to a collection they had not granted at all —
                // the fix that cannot work, for the one problem they had.
                TokenAmount::Item(token_id) => match grant.items.get(&m.token) {
                    None => violations.push(Violation {
                        promise_index: Some(m.promise_index),
                        stage: Stage::Promise(9),
                        rule: "collection_not_granted",
                        subcode: None,
                        message: format!(
                            "collection '{}' is not in the spend grant — the grant must name \
                             the collection before any of its items can move",
                            m.token
                        ),
                    }),
                    Some(ids) => {
                        if !ids.iter().any(|id| id == token_id) {
                            violations.push(Violation {
                                promise_index: Some(m.promise_index),
                                stage: Stage::Promise(10),
                                rule: "item_not_granted",
                                subcode: None,
                                message: format!(
                                    "item '{token_id}' of '{}' is not in the spend grant",
                                    m.token
                                ),
                            });
                        }
                    }
                },
            }
        }

        violations
    }
}

impl HosLease {
    /// The account's own collection is off limits to a grant — checked
    /// separately because `collection_id` lives in `nft_item_info()`, not in
    /// `hos_agent_status`, so only a caller holding that second view can run
    /// it.
    ///
    /// Mirrors the guard at the top of `charge_token_call`: a granted CALL may
    /// not be addressed to the collection this account belongs to, whatever
    /// the grant says. The contract refuses at grant time too
    /// (`assert_grantable`), but this is the spend-time half — its own tests
    /// (`the_registry_is_refused_at_spend_time_on_the_token_path_too`) exist
    /// precisely because a grant written before a migration could still name
    /// it. Without this, the registry call passes our pre-flight and burns gas
    /// on a certain panic.
    pub fn check_own_collection(fx: &EffectsSet, collection_id: &str) -> Vec<Violation> {
        let mut violations = Vec::new();
        for promise_index in &fx.call_promises {
            let Some(receiver) = fx.receivers.get(*promise_index) else {
                continue;
            };
            if receiver == collection_id {
                violations.push(Violation {
                    promise_index: Some(*promise_index),
                    // Rung 4, NOT first. `charge_token_call` checks the
                    // deposit above this guard, and `charge_promise` has
                    // already demanded the call stand alone — so a
                    // non-standalone call at the own collection is refused by
                    // the chain for the shape, not for the target.
                    stage: Stage::Promise(4),
                    rule: "own_collection_refused",
                    subcode: None,
                    message: format!(
                        "'{receiver}' is the collection this account itself belongs to; a spend \
                         grant can never move this account's own names"
                    ),
                });
            }
        }
        violations
    }

    /// The balance floor, checked separately because it needs the asset
    /// account's balance (a second view) on top of the status.
    ///
    /// Mirrors `assert_within_reserve`: the sum of ALL promise deposits —
    /// token calls' mandated yocto included, unlike the grant's native
    /// budget — must leave the account at or above `reserve_yocto`, which
    /// tracks live storage usage and therefore cannot be derived off chain.
    pub fn check_reserve(
        fx: &EffectsSet,
        status: &AgentStatusView,
        account_balance_yocto: u128,
    ) -> Option<Violation> {
        let reserve = status.reserve_yocto.parse::<u128>().unwrap_or(u128::MAX);
        if account_balance_yocto.saturating_sub(fx.native_total) < reserve {
            return Some(Violation {
                promise_index: None,
                stage: Stage::Reserve,
                rule: "insufficient_vs_reserve",
                subcode: None,
                message: format!(
                    "spending {} would leave the account below its reserve floor of {reserve} \
                     (balance {account_balance_yocto}); the floor tracks live storage usage",
                    fx.native_total
                ),
            });
        }
        None
    }
}

/// The v6 on-chain grant, as `hos_agent_status` reports it. Missing fields
/// default to the EMPTY grant (no receivers, no tokens, zero budget) — a
/// shrunken answer can only refuse more, never less.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SpendGrant {
    #[serde(default)]
    pub receivers: Vec<String>,
    #[serde(default = "zero_string")]
    pub budget_yocto: String,
    #[serde(default = "zero_string")]
    pub spent_yocto: String,
    #[serde(default)]
    pub tokens: std::collections::BTreeMap<String, TokenBudget>,
    #[serde(default)]
    pub items: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(default = "zero_string")]
    pub expires_at: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TokenBudget {
    #[serde(default = "zero_string")]
    pub budget: String,
    #[serde(default = "zero_string")]
    pub spent: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verify(s: &AgentStatusView, now_ns: u64) -> Result<VerifiedState, BindingFault> {
        HosLease::verify(s, now_ns)
    }

    fn healthy() -> AgentStatusView {
        AgentStatusView {
            extension_enabled: true,
            grant: None,
            state: "Active".into(),
            frozen: "Unfrozen".into(),
            lease_until_ns: "2000".into(),
            reserve_yocto: "0".into(),
            impl_version: 6,
        }
    }

    #[test]
    fn a_healthy_status_passes_and_each_fault_is_named() {
        assert!(matches!(
            verify(&healthy(), 1000),
            Ok(VerifiedState::HosLease { .. })
        ));

        let mut s = healthy();
        s.extension_enabled = false;
        assert_eq!(verify(&s, 1000), Err(BindingFault::ExtensionDisabled));

        let mut s = healthy();
        s.frozen = "Frozen".into();
        assert_eq!(verify(&s, 1000), Err(BindingFault::Frozen("Frozen".into())));

        let mut s = healthy();
        s.state = "Parked".into();
        assert_eq!(
            verify(&s, 1000),
            Err(BindingFault::StateNotActive("Parked".into()))
        );

        let mut s = healthy();
        s.state = "Expired".into();
        assert_eq!(verify(&s, 1000), Err(BindingFault::StateExpired));

        let mut s = healthy();
        s.lease_until_ns = "999".into();
        assert_eq!(verify(&s, 1000), Err(BindingFault::LeaseExpired));

        let mut s = healthy();
        s.impl_version = 5;
        assert_eq!(
            verify(&s, 1000),
            Err(BindingFault::ImplVersionUnsupported(5))
        );
    }

    /// The LIVE `hos_agent_status` from the partner's testnet account
    /// `alpha.tlademo.testnet`, executor
    /// `5356b2c0…e325806a`, captured 2026-08-22 by an RPC `call_function`.
    /// This is the first time the real wire form has been pinned — everything
    /// before it was built from their docs and their `tests.rs`. If they ever
    /// reshape the view, this fails instead of the coordinator failing in front
    /// of them.
    const LIVE_STATUS_ALPHA_TLADEMO: &str = r#"{
        "extension_enabled": true,
        "grant": {
            "receivers": ["hos-e2e-receiver.testnet"],
            "budget_yocto": "5000000000000000000000000",
            "spent_yocto": "0",
            "tokens": {
                "usdc.fakes.testnet": {"budget": "100000000", "spent": "0"},
                "wrap.testnet": {"budget": "5000000000000000000000000", "spent": "0"}
            },
            "items": {},
            "expires_at": "1790293105645958817"
        },
        "state": "Active",
        "frozen": "Unfrozen",
        "lease_until_ns": "1818746516312653999",
        "reserve_yocto": "12130000000000000000000",
        "impl_version": 6
    }"#;

    #[test]
    fn the_live_partner_status_parses_and_drives_our_preflight() {
        use base64::Engine;
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);

        // 1. It deserializes into our struct with no field left over and no
        //    field missing — the whole point of pinning the real bytes.
        let status: AgentStatusView =
            serde_json::from_str(LIVE_STATUS_ALPHA_TLADEMO).expect("live status must parse");
        assert_eq!(status.impl_version, 6);
        assert_eq!(status.state, "Active");
        assert_eq!(status.frozen, "Unfrozen");

        // 2. verify() accepts it (now is well before both expiries).
        let now = 1_700_000_000_000_000_000u64;
        let st = HosLease::verify(&status, now).expect("live status verifies");

        // 3. A granted ft_transfer of 100 USDC to the granted receiver, within
        //    budget → admitted. This is the exact path the partner ran with a
        //    throwaway extension before handing the account over.
        let ok = fx_from(&format!(
            r#"{{"request":{{"external":[{{"receiver_id":"usdc.fakes.testnet",
                "actions":[{{"action":"function_call","payload":{{
                    "function_name":"ft_transfer","args":"{}","deposit":"1"}}}}]}}]}}}}"#,
            b64(r#"{"receiver_id":"hos-e2e-receiver.testnet","amount":"100000000"}"#)
        ));
        assert!(HosLease::admission(&ok, &st, now).is_empty(), "in-budget grant call must pass");

        // 4. The receiver the partner said panics on chain
        //    ("receiver is not in the spend grant") — our preflight names it
        //    first, before any gas is spent.
        let stranger = fx_from(
            r#"{"request":{"external":[{"receiver_id":"attacker.testnet",
                "actions":[{"action":"transfer","payload":{"amount":"1000000000000000000000000"}}]}]}}"#,
        );
        assert_eq!(
            rules(&HosLease::admission(&stranger, &st, now)),
            vec!["receiver_not_granted"]
        );

        // 5. 101 USDC against the 100 USDC token budget → token_budget_exceeded.
        let over = fx_from(&format!(
            r#"{{"request":{{"external":[{{"receiver_id":"usdc.fakes.testnet",
                "actions":[{{"action":"function_call","payload":{{
                    "function_name":"ft_transfer","args":"{}","deposit":"1"}}}}]}}]}}}}"#,
            b64(r#"{"receiver_id":"hos-e2e-receiver.testnet","amount":"100000001"}"#)
        ));
        assert_eq!(rules(&HosLease::admission(&over, &st, now)), vec!["token_budget_exceeded"]);

        // 6. Native above the 5 NEAR budget → grant_exhausted. (The reserve
        //    floor of ~0.012 NEAR can never be reached live: the 5 NEAR grant
        //    cap trips first, so reserve breach is a stub-only case.)
        let big = fx_from(
            r#"{"request":{"external":[{"receiver_id":"hos-e2e-receiver.testnet",
                "actions":[{"action":"transfer","payload":{"amount":"6000000000000000000000000"}}]}]}}"#,
        );
        assert_eq!(rules(&HosLease::admission(&big, &st, now)), vec!["grant_exhausted"]);
    }

    /// A grant we cannot read says so, and refuses.
    ///
    /// `grant_unreadable` is the only rule in this file nothing ever reached.
    /// It is also the rule that fires if the partner's spelling and ours ever
    /// part company — the `rotation_seq` failure, one field over, except that
    /// here it would refuse EVERY spend on EVERY leased account at once. The
    /// live grant is pinned above and proves the shapes agree TODAY; this
    /// proves what happens on the day they stop.
    #[test]
    fn a_grant_we_cannot_read_refuses_and_names_itself() {
        let now = 1_700_000_000_000_000_000u64;
        let with_grant = |g: serde_json::Value| {
            let mut s: AgentStatusView =
                serde_json::from_str(LIVE_STATUS_ALPHA_TLADEMO).expect("live status must parse");
            s.grant = Some(g);
            let st = HosLease::verify(&s, now).expect("the identity fields are untouched");
            let fx = fx_from(
                r#"{"request":{"external":[{"receiver_id":"hos-e2e-receiver.testnet",
                    "actions":[{"action":"transfer","payload":{"amount":"1"}}]}]}}"#,
            );
            rules(&HosLease::admission(&fx, &st, now))
        };

        // A list where the contract sends a list, a string where it sends a
        // string — get either backwards and the grant does not parse.
        assert_eq!(with_grant(serde_json::json!({ "receivers": "bob.near" })), vec!["grant_unreadable"]);
        assert_eq!(with_grant(serde_json::json!({ "budget_yocto": 5 })), vec!["grant_unreadable"]);
        assert_eq!(
            with_grant(serde_json::json!({ "tokens": { "usdc.fakes.testnet": "100" } })),
            vec!["grant_unreadable"]
        );
        // And it is reported ALONE: an owner told about a form rule while the
        // grant itself is unreadable would go and fix the request.
        assert_eq!(with_grant(serde_json::json!("a grant, allegedly")), vec!["grant_unreadable"]);

        // A grant that answers with LESS than we expect is a different case and
        // must NOT be one of these: every field defaults, the empty grant
        // refuses more rather than less, and the caller hears which rule.
        let shrunken = with_grant(serde_json::json!({}));
        assert_eq!(
            shrunken,
            vec!["grant_expired"],
            "a shrunken grant must refuse on its own terms, not as unreadable: {shrunken:?}"
        );

        // No grant at all is its own rule, and stays distinguishable from both.
        let mut none: AgentStatusView =
            serde_json::from_str(LIVE_STATUS_ALPHA_TLADEMO).expect("live status must parse");
        none.grant = None;
        let st = HosLease::verify(&none, now).expect("verify");
        let fx = fx_from(
            r#"{"request":{"external":[{"receiver_id":"hos-e2e-receiver.testnet",
                "actions":[{"action":"transfer","payload":{"amount":"1"}}]}]}}"#,
        );
        assert_eq!(rules(&HosLease::admission(&fx, &st, now)), vec!["grant_missing"]);
    }

    #[test]
    fn a_lease_ending_now_is_already_over() {
        // `<=` not `<`: at the boundary nanosecond the lease is NOT live. An
        // off-by-one here signs against a reclaimable account.
        let mut s = healthy();
        s.lease_until_ns = "1000".into();
        assert_eq!(verify(&s, 1000), Err(BindingFault::LeaseExpired));
    }

    #[test]
    fn an_empty_response_fails_on_its_first_missing_field() {
        // serde defaults are the unhealthy values, so `{}` must deny.
        let s: AgentStatusView = serde_json::from_str("{}").unwrap();
        assert_eq!(verify(&s, 1000), Err(BindingFault::ExtensionDisabled));
    }

    #[test]
    fn an_unreadable_lease_is_malformed_not_expired() {
        let mut s = healthy();
        s.lease_until_ns = "soon".into();
        assert!(matches!(verify(&s, 1000), Err(BindingFault::Malformed(_))));
    }

    #[test]
    fn the_method_list_example_parses_and_passes() {
        // The exact shape the partner's method list shows for hos_agent_status.
        let json = r#"{
          "extension_enabled": true,
          "grant": {
            "receivers": ["bob.near"],
            "budget_yocto": "5000000000000000000000000",
            "spent_yocto": "0",
            "tokens": { "token.near": { "budget": "1000000000", "spent": "0" } },
            "items": { "collection.near": ["1041", "1055"] },
            "expires_at": "1786000000000000000"
          },
          "state": "Active",
          "frozen": "Unfrozen",
          "lease_until_ns": "1790000000000000000",
          "reserve_yocto": "3140000000000000000000000",
          "impl_version": 6
        }"#;
        let s: AgentStatusView = serde_json::from_str(json).unwrap();
        assert!(matches!(
            verify(&s, 1_789_999_999_999_999_999),
            Ok(VerifiedState::HosLease { .. })
        ));
        assert_eq!(
            verify(&s, 1_790_000_000_000_000_000),
            Err(BindingFault::LeaseExpired)
        );
    }

    fn fx_from(request_json: &str) -> EffectsSet {
        let envelope = crate::wallet_request_decode::decode(request_json.as_bytes()).unwrap();
        crate::wallet_request_decode::effects(&envelope, request_json.len()).unwrap()
    }

    fn granted_state(grant: serde_json::Value) -> VerifiedState {
        let mut status = healthy();
        status.grant = Some(grant);
        VerifiedState::HosLease { status }
    }

    /// The error CLASSES a set of violations carries, in order.
    fn rules(v: &[Violation]) -> Vec<&'static str> {
        v.iter().map(|x| x.rule).collect()
    }

    /// The subcodes, for the class that has them.
    fn subcodes(v: &[Violation]) -> Vec<&'static str> {
        v.iter().filter_map(|x| x.subcode).collect()
    }

    /// The personal mode adds NOTHING, and that is a decision, not a gap.
    ///
    /// Every rule in `HosLease::admission` exists because the HoS contract
    /// enforces it: the granted-call form, the method allowlist, the grant's
    /// budgets and receivers, the reserve. The owner's own no-sign contract
    /// enforces none of them — it accepts bundles, refunds and any deposit —
    /// so there is no shared subset to inherit and the correct answer is an
    /// empty one.
    ///
    /// That is what makes the personal mode the leased mode with its grant
    /// rules switched off, and this test is where it stops being a comment.
    /// A rule added to the personal profile fails here, and whoever added it
    /// has to say why the two lanes now differ — which is a product decision,
    /// not an implementation detail.
    #[test]
    fn the_personal_mode_adds_no_rules_of_its_own() {
        use crate::binding::{BindingProfile, PersonalAccount};

        // One request that trips as much of the leased ladder as a single
        // request can: refund_to, a call that is not standalone, a method the
        // grant never covers, and a recipient nobody granted.
        let args = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .encode(r#"{"receiver_id":"stranger.near","amount":"10"}"#)
        };
        let fx = fx_from(&format!(
            r#"{{"request":{{"external":[{{
                "receiver_id":"token.near",
                "refund_to":"attacker.near",
                "actions":[
                  {{"action":"function_call","payload":{{
                     "function_name":"ft_transfer_call","args":"{args}","deposit":"5"}}}},
                  {{"action":"transfer","payload":{{"amount":"250"}}}}
                ]}}]}}}}"#
        ));

        let leased = granted_state(serde_json::json!({
            "receivers": ["bob.near"],
            "budget_yocto": "1", "spent_yocto": "0",
            "tokens": {}, "items": {}, "expires_at": "2000"
        }));
        let leased_violations = HosLease::admission(&fx, &leased, 1000);
        assert!(
            leased_violations.len() >= 3,
            "the fixture must actually trip the leased ladder, or this test proves nothing \
             about the personal one: {leased_violations:#?}"
        );

        let personal = VerifiedState::PersonalAccount { code_hash: [0; 32] };
        let personal_violations = PersonalAccount::admission(&fx, &personal, 1000);
        assert!(
            personal_violations.is_empty(),
            "the personal profile added rules of its own: {personal_violations:#?}\n\
             Every leased rule comes from the HoS contract, and the owner's contract enforces \
             none of them — so anything refused here is a rule this codebase invented for one \
             mode. The wall for a personal binding is the owner's custody policy, in the core."
        );
    }

    /// A profile may only ADD refusals — the trait says so, and here it is
    /// asserted.
    ///
    /// The direction matters more than it looks. Core denials are the ones
    /// that hold for every wallet, bound or not; a profile that could lift one
    /// would turn a binding into a way to widen what an agent may do, when a
    /// binding is only ever a way to narrow it. The worst a profile bug can
    /// then produce is a spurious refusal — never a spurious signature.
    #[test]
    fn a_profile_cannot_take_a_refusal_away() {
        use crate::binding::{verdict, BindingKind, BindingProfile, PersonalAccount, Violation};

        // A refusal that did not come from any profile — the shape a core
        // denial has when it reaches the assembly.
        let core_said_no = Violation {
            promise_index: Some(0),
            stage: crate::binding::Stage::Promise(2),
            rule: "receiver_not_granted",
            subcode: None,
            message: "core".into(),
        };
        let fx = fx_from(
            r#"{"request":{"external":[{"receiver_id":"bob.near",
                "actions":[{"action":"transfer","payload":{"amount":"1"}}]}]}}"#,
        );

        for kind in [BindingKind::HosLease, BindingKind::PersonalAccount] {
            let out = verdict(kind, &fx, vec![core_said_no.clone()], None, None);
            assert!(
                out.iter().any(|v| v.message == "core"),
                "{kind:?} dropped a refusal it was handed — a profile may add, never subtract"
            );
        }

        // And the personal profile, asked about the wrong evidence, refuses
        // rather than reinterpreting it.
        let wrong = VerifiedState::HosLease { status: healthy() };
        let v = PersonalAccount::admission(&fx, &wrong, 1000);
        assert_eq!(
            v.first().map(|x| x.rule),
            Some("evidence_mismatch"),
            "a profile handed the other mode's evidence must refuse, not reinterpret"
        );
    }

    #[test]
    fn admission_enforces_the_granted_call_form() {
        // The spec's own illustration: refund_to set, ft_transfer bundled
        // with a plain transfer. The contract rejects it two ways; admission
        // names both before any gas is burned, under ONE class with distinct
        // subcodes.
        let ft = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .encode(r#"{"receiver_id":"bob.near","amount":"10"}"#)
        };
        let fx = fx_from(&format!(
            r#"{{"request":{{"external":[{{
                "receiver_id":"token.near",
                "refund_to":"attacker.near",
                "actions":[
                  {{"action":"function_call","payload":{{
                     "function_name":"ft_transfer","args":"{ft}","deposit":"1"}}}},
                  {{"action":"transfer","payload":{{"amount":"250"}}}}
                ]}}]}}}}"#
        ));
        let st = granted_state(serde_json::json!({
            "receivers": ["bob.near", "token.near"],
            "budget_yocto": "1000000", "spent_yocto": "0",
            "tokens": { "token.near": { "budget": "100", "spent": "0" } },
            "items": {}, "expires_at": "2000"
        }));

        let violations = HosLease::admission(&fx, &st, 1000);
        let subs = subcodes(&violations);
        assert!(subs.contains(&"refund_target_not_allowed"), "{violations:?}");
        assert!(subs.contains(&"grant_call_must_stand_alone"), "{violations:?}");
        assert!(
            rules(&violations).iter().all(|r| *r == "grant_shape_violation"),
            "form refusals share one class: {violations:?}"
        );

        // The SAME effects under the personal profile: zero violations — the
        // form is legal there, and this asymmetry is the differential subject.
        let personal = crate::binding::PersonalAccount::admission(
            &fx,
            &VerifiedState::PersonalAccount { code_hash: crate::binding::WALLET_CODE_HASHES[0] },
            1000,
        );
        assert!(personal.is_empty(), "{personal:?}");
    }

    #[test]
    fn several_transfers_in_one_promise_are_legal_under_a_grant() {
        // `charge_transfer` accepts any number of Transfer actions — only a
        // promise carrying a CALL must stand alone. Treating a multi-transfer
        // promise as malformed would refuse a request the chain executes.
        let fx = fx_from(
            r#"{"request":{"external":[{
                "receiver_id":"bob.near",
                "actions":[
                    {"action":"transfer","payload":{"amount":"10"}},
                    {"action":"transfer","payload":{"amount":"20"}},
                    {"action":"transfer","payload":{"amount":"30"}}]}]}}"#,
        );
        let st = granted_state(serde_json::json!({
            "receivers": ["bob.near"], "budget_yocto": "1000", "spent_yocto": "0",
            "expires_at": "2000"
        }));
        assert!(HosLease::admission(&fx, &st, 1000).is_empty());
        // ...and the whole promise is metered, all three actions together.
        let tight = granted_state(serde_json::json!({
            "receivers": ["bob.near"], "budget_yocto": "59", "spent_yocto": "0",
            "expires_at": "2000"
        }));
        assert_eq!(rules(&HosLease::admission(&fx, &tight, 1000)), vec!["grant_exhausted"]);
    }

    #[test]
    fn a_token_calls_mandated_yocto_is_not_charged_to_the_native_budget() {
        // The contract calls it "protocol overhead rather than spend" and
        // leaves it out of the NEAR budget. Counting it would refuse a
        // request one yocto short of the ceiling that the chain accepts.
        use base64::Engine;
        let ft = base64::engine::general_purpose::STANDARD
            .encode(r#"{"receiver_id":"bob.near","amount":"5"}"#);
        let fx = fx_from(&format!(
            r#"{{"request":{{"external":[{{
                "receiver_id":"usdc.near",
                "actions":[{{"action":"function_call","payload":{{
                    "function_name":"ft_transfer","args":"{ft}","deposit":"1"}}}}]}}]}}}}"#
        ));
        // Native budget fully spent: a token call must still pass, because it
        // charges the TOKEN budget only.
        let st = granted_state(serde_json::json!({
            "receivers": ["bob.near"],
            "budget_yocto": "100", "spent_yocto": "100",
            "tokens": { "usdc.near": { "budget": "10", "spent": "0" } },
            "expires_at": "2000"
        }));
        assert!(HosLease::admission(&fx, &st, 1000).is_empty());
    }

    #[test]
    fn admission_meters_the_grant() {
        let transfer = r#"{"request":{"external":[{
            "receiver_id":"bob.near",
            "actions":[{"action":"transfer","payload":{"amount":"600"}}]}]}}"#;
        let fx = fx_from(transfer);

        // Missing grant: answers ALONE, like the contract, which reads the
        // grant before it looks at a promise.
        let no_grant = VerifiedState::HosLease { status: healthy() };
        assert_eq!(rules(&HosLease::admission(&fx, &no_grant, 1000)), vec!["grant_missing"]);

        // Expired grant.
        let expired = granted_state(serde_json::json!({
            "receivers": ["bob.near"], "budget_yocto": "1000", "spent_yocto": "0",
            "expires_at": "999"
        }));
        assert_eq!(rules(&HosLease::admission(&fx, &expired, 1000)), vec!["grant_expired"]);

        // Budget minus spent is the ceiling: 600 > 1000-500.
        let tight = granted_state(serde_json::json!({
            "receivers": ["bob.near"], "budget_yocto": "1000", "spent_yocto": "500",
            "expires_at": "2000"
        }));
        assert_eq!(rules(&HosLease::admission(&fx, &tight, 1000)), vec!["grant_exhausted"]);

        // Receiver outside the grant: for a plain transfer that is the
        // PROMISE's receiver.
        let wrong_receiver = granted_state(serde_json::json!({
            "receivers": ["carol.near"], "budget_yocto": "1000000", "spent_yocto": "0",
            "expires_at": "2000"
        }));
        assert_eq!(
            rules(&HosLease::admission(&fx, &wrong_receiver, 1000)),
            vec!["receiver_not_granted"]
        );
    }

    #[test]
    fn an_expired_grant_is_reported_before_any_form_rule() {
        // A malformed request against an expired grant must say "expired":
        // the owner has to re-grant, not rewrite the call. The contract fails
        // in that order too.
        let fx = fx_from(
            r#"{"request":{"external":[{
                "receiver_id":"bob.near",
                "refund_to":"attacker.near",
                "actions":[{"action":"transfer","payload":{"amount":"1"}}]}]}}"#,
        );
        let expired = granted_state(serde_json::json!({
            "receivers": ["bob.near"], "budget_yocto": "1000", "spent_yocto": "0",
            "expires_at": "999"
        }));
        assert_eq!(rules(&HosLease::admission(&fx, &expired, 1000)), vec!["grant_expired"]);
    }

    #[test]
    fn admission_meters_tokens_in_their_own_units_and_fences_items() {
        use base64::Engine;
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);

        // 60 USDC against a 50-remaining token budget: refused by the TOKEN
        // cap; the huge native budget is irrelevant (different units).
        let ft = b64(r#"{"receiver_id":"bob.near","amount":"60"}"#);
        let fx = fx_from(&format!(
            r#"{{"request":{{"external":[{{
                "receiver_id":"usdc.near",
                "actions":[{{"action":"function_call","payload":{{
                    "function_name":"ft_transfer","args":"{ft}","deposit":"1"}}}}]}}]}}}}"#
        ));
        let st = granted_state(serde_json::json!({
            "receivers": ["bob.near"],
            "budget_yocto": "99999999999999999999", "spent_yocto": "0",
            "tokens": { "usdc.near": { "budget": "100", "spent": "50" } },
            "expires_at": "2000"
        }));
        assert_eq!(rules(&HosLease::admission(&fx, &st, 1000)), vec!["token_budget_exceeded"]);

        // A token with no entry at all.
        let st_none = granted_state(serde_json::json!({
            "receivers": ["bob.near"], "budget_yocto": "99999999999999999999",
            "spent_yocto": "0", "tokens": {}, "expires_at": "2000"
        }));
        assert_eq!(rules(&HosLease::admission(&fx, &st_none, 1000)), vec!["token_not_granted"]);

        // An NFT outside the fence: token_id 9999 when only 1041 may leave.
        let nft = b64(r#"{"receiver_id":"bob.near","token_id":"9999"}"#);
        let fx_nft = fx_from(&format!(
            r#"{{"request":{{"external":[{{
                "receiver_id":"col.near",
                "actions":[{{"action":"function_call","payload":{{
                    "function_name":"nft_transfer","args":"{nft}","deposit":"1"}}}}]}}]}}}}"#
        ));
        let st_items = granted_state(serde_json::json!({
            "receivers": ["bob.near"], "budget_yocto": "99999999999999999999",
            "spent_yocto": "0", "items": { "col.near": ["1041"] }, "expires_at": "2000"
        }));
        assert_eq!(rules(&HosLease::admission(&fx_nft, &st_items, 1000)), vec!["item_not_granted"]);

        // A FENCED item passes with NO token budget for that collection at
        // all: NFTs are fenced, never metered. Requiring a budget here would
        // refuse every legal NFT transfer.
        let ok_nft = b64(r#"{"receiver_id":"bob.near","token_id":"1041"}"#);
        let fx_ok = fx_from(&format!(
            r#"{{"request":{{"external":[{{
                "receiver_id":"col.near",
                "actions":[{{"action":"function_call","payload":{{
                    "function_name":"nft_transfer","args":"{ok_nft}","deposit":"1"}}}}]}}]}}}}"#
        ));
        assert!(HosLease::admission(&fx_ok, &st_items, 1000).is_empty());
    }

    #[test]
    fn memo_is_permitted_but_any_other_extra_argument_is_not() {
        use base64::Engine;
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let st = granted_state(serde_json::json!({
            "receivers": ["bob.near"],
            "budget_yocto": "1000", "spent_yocto": "0",
            "tokens": { "usdc.near": { "budget": "1000", "spent": "0" } },
            "expires_at": "2000"
        }));
        let call = |args: &str| {
            fx_from(&format!(
                r#"{{"request":{{"external":[{{
                    "receiver_id":"usdc.near",
                    "actions":[{{"action":"function_call","payload":{{
                        "function_name":"ft_transfer","args":"{}","deposit":"1"}}}}]}}]}}}}"#,
                b64(args)
            ))
        };

        // `memo` is declared by the standard and by the contract: legal.
        let with_memo = call(r#"{"receiver_id":"bob.near","amount":"5","memo":"rent"}"#);
        assert!(HosLease::admission(&with_memo, &st, 1000).is_empty());

        // `msg` is the ft_transfer_call field. The contract parses these
        // arguments with deny_unknown_fields, so it cannot read them at all —
        // refuse here rather than pay gas for a panic.
        let with_msg = call(r#"{"receiver_id":"bob.near","amount":"5","msg":"x"}"#);
        let v = HosLease::admission(&with_msg, &st, 1000);
        assert_eq!(rules(&v), vec!["grant_shape_violation"]);
        assert_eq!(subcodes(&v), vec!["grant_args_unreadable"]);

        // The personal mode reads the same call and refuses nothing: its
        // contract never parses these arguments.
        let personal = crate::binding::PersonalAccount::admission(
            &with_msg,
            &VerifiedState::PersonalAccount { code_hash: crate::binding::WALLET_CODE_HASHES[0] },
            1000,
        );
        assert!(personal.is_empty(), "{personal:?}");
    }

    #[test]
    fn admission_refuses_methods_the_grant_never_covers() {
        // storage_deposit is a personal_account operation; state_init deploys
        // code. Both are structurally outside a grant, whatever the budget.
        use base64::Engine;
        let sd = base64::engine::general_purpose::STANDARD.encode(r#"{"account_id":"bob.near"}"#);
        let fx = fx_from(&format!(
            r#"{{"request":{{"external":[
                {{"receiver_id":"usdc.near","actions":[{{"action":"function_call","payload":{{
                    "function_name":"storage_deposit","args":"{sd}","deposit":"1"}}}}]}},
                {{"receiver_id":"new.near","actions":[{{"action":"deterministic_state_init","payload":{{
                    "state_init":{{}},"deposit":"1"}}}}]}}
            ]}}}}"#
        ));
        let st = granted_state(serde_json::json!({
            "receivers": ["bob.near", "usdc.near", "new.near"],
            "budget_yocto": "99999999999999999999", "spent_yocto": "0",
            "expires_at": "2000"
        }));
        let v = HosLease::admission(&fx, &st, 1000);
        let subs = subcodes(&v);
        assert!(subs.contains(&"grant_method_not_allowed"), "{v:?}");
        assert!(subs.contains(&"grant_action_not_allowed"), "{v:?}");
    }

    #[test]
    fn a_promise_carrying_nothing_still_faces_the_receivers_list() {
        // `charge_transfer` checks the receiver BEFORE it looks at the
        // actions, so a promise with none at all is refused when the receiver
        // is not granted. Metering only the promises that move something would
        // pass it and pay gas for the panic.
        let fx = fx_from(
            r#"{"request":{"external":[{"receiver_id":"stranger.near","actions":[]}]}}"#,
        );
        let st = granted_state(serde_json::json!({
            "receivers": ["bob.near"], "budget_yocto": "1000", "spent_yocto": "0",
            "expires_at": "2000"
        }));
        assert_eq!(
            rules(&HosLease::admission(&fx, &st, 1000)),
            vec!["receiver_not_granted"]
        );
    }

    #[test]
    fn the_accounts_own_collection_is_refused_at_spend_time() {
        // `charge_token_call` refuses a call addressed to the collection this
        // account belongs to — the registry that holds its own name — before
        // it even looks at the method. The grant cannot legally name it, but a
        // grant written before a migration still can, which is why the
        // contract keeps a spend-time test of its own.
        use base64::Engine;
        let args = base64::engine::general_purpose::STANDARD
            .encode(r#"{"receiver_id":"bob.near","token_id":"agent.tla"}"#);
        let fx = fx_from(&format!(
            r#"{{"request":{{"external":[{{
                "receiver_id":"tla.near",
                "actions":[{{"action":"function_call","payload":{{
                    "function_name":"nft_transfer","args":"{args}","deposit":"1"}}}}]}}]}}}}"#
        ));

        let v = HosLease::check_own_collection(&fx, "tla.near");
        assert_eq!(rules(&v), vec!["own_collection_refused"]);
        assert_eq!(v[0].promise_index, Some(0));

        // Any OTHER collection is none of this rule's business.
        assert!(HosLease::check_own_collection(&fx, "other.near").is_empty());

        // And a plain transfer to the collection is not a token call — the
        // contract's guard sits inside `charge_token_call` only.
        let plain = fx_from(
            r#"{"request":{"external":[{
                "receiver_id":"tla.near",
                "actions":[{"action":"transfer","payload":{"amount":"1"}}]}]}}"#,
        );
        assert!(HosLease::check_own_collection(&plain, "tla.near").is_empty());
    }

    #[test]
    fn the_reserve_floor_is_checked_against_the_whole_request() {
        // `assert_within_reserve` sums EVERY promise's deposits — a token
        // call's yocto included, unlike the grant's native budget — and the
        // remainder must stay at or above the floor.
        let fx = fx_from(
            r#"{"request":{"external":[{
                "receiver_id":"bob.near",
                "actions":[{"action":"transfer","payload":{"amount":"60"}}]}]}}"#,
        );
        let mut status = healthy();
        status.reserve_yocto = "50".into();

        // 100 - 60 = 40 < 50 → refused.
        let v = HosLease::check_reserve(&fx, &status, 100).expect("must refuse");
        assert_eq!(v.rule, "insufficient_vs_reserve");
        // 120 - 60 = 60 ≥ 50 → allowed.
        assert!(HosLease::check_reserve(&fx, &status, 120).is_none());
        // Exactly at the floor is allowed (the contract uses `>=`).
        assert!(HosLease::check_reserve(&fx, &status, 110).is_none());
        // An unreadable floor refuses rather than assuming zero.
        status.reserve_yocto = "lots".into();
        assert!(HosLease::check_reserve(&fx, &status, u128::MAX).is_some());
    }

    #[test]
    fn the_registry_supports_exactly_version_six() {
        assert_eq!(decoder_for(6), Some(1));
        assert_eq!(decoder_for(5), None);
        assert_eq!(decoder_for(0), None);
        assert_eq!(decoder_for(7), None);
    }
}

#[cfg(test)]
mod answers_alone_tests {
    use super::*;
    use crate::binding::{BindingProfile, HosLease, PersonalAccount, VerifiedState};

    fn some_promise() -> EffectsSet {
        let json = r#"{"request":{"external":[{"receiver_id":"carol.testnet",
            "actions":[{"action":"transfer","payload":{"amount":"1"}}]}]}}"#;
        let envelope = crate::wallet_request_decode::decode(json.as_bytes()).unwrap();
        crate::wallet_request_decode::effects(&envelope, json.len()).unwrap()
    }

    fn status_with(grant: Option<serde_json::Value>) -> AgentStatusView {
        AgentStatusView {
            extension_enabled: true,
            grant,
            state: "Active".into(),
            frozen: "Unfrozen".into(),
            lease_until_ns: "9000000000000000000".into(),
            reserve_yocto: "0".into(),
            impl_version: 6,
        }
    }

    /// Every way `admission` can stop BEFORE looking at a promise must say so
    /// through `answers_alone`.
    ///
    /// The caller relies on this to decide whether to prepend the
    /// own-collection rule, which describes a stage the request never reached.
    /// A fifth early return added without a word here would silently start
    /// reporting a promise rule for a request the chain refused at the door.
    #[test]
    fn every_early_return_answers_alone() {
        let fx = some_promise();
        let cases: Vec<(&str, Vec<Violation>)> = vec![
            (
                "evidence of the wrong mode",
                HosLease::admission(
                    &fx,
                    &VerifiedState::PersonalAccount { code_hash: [0; 32] },
                    0,
                ),
            ),
            (
                "no grant at all",
                HosLease::admission(
                    &fx,
                    &VerifiedState::HosLease { status: status_with(None) },
                    0,
                ),
            ),
            (
                "a grant that does not parse",
                HosLease::admission(
                    &fx,
                    &VerifiedState::HosLease {
                        status: status_with(Some(serde_json::json!("not an object"))),
                    },
                    0,
                ),
            ),
            (
                "a grant past its expiry",
                HosLease::admission(
                    &fx,
                    &VerifiedState::HosLease {
                        status: status_with(Some(serde_json::json!({
                            "receivers": ["carol.testnet"],
                            "budget_yocto": "1000",
                            "spent_yocto": "0",
                            "expires_at": "1"
                        }))),
                    },
                    1_000_000,
                ),
            ),
            (
                "the personal profile handed leased evidence",
                PersonalAccount::admission(
                    &fx,
                    &VerifiedState::HosLease { status: status_with(None) },
                    0,
                ),
            ),
        ];

        for (what, violations) in cases {
            assert_eq!(violations.len(), 1, "{what}: an early return answers alone");
            assert!(
                violations[0].answers_alone(),
                "{what}: rule '{}' stops admission before any promise, but does not say so",
                violations[0].rule
            );
        }
    }

    /// The other direction, and the one that would fail QUIETLY: a
    /// promise-level rule must NOT claim to answer alone, or the caller would
    /// drop the own-collection refusal it was supposed to report first.
    #[test]
    fn promise_level_rules_do_not_answer_alone() {
        for rule in [
            "grant_exhausted",
            "grant_shape_violation",
            "receiver_not_granted",
            "token_not_granted",
            "token_budget_exceeded",
            "item_not_granted",
            "own_collection_refused",
            "insufficient_vs_reserve",
        ] {
            let v = Violation {
                promise_index: Some(0),
                stage: Stage::Promise(1),
                rule,
                subcode: None,
                message: String::new(),
            };
            assert!(
                !v.answers_alone(),
                "'{rule}' is decided while charging promises; treating it as a door rule would \
                 swallow the rules that belong beside it"
            );
        }
    }

    /// The wire form the partner's contract actually sends, byte for byte.
    ///
    /// Every other vector in this crate BUILDS an `AgentStatusView` in Rust and
    /// never deserializes one, so none of them can see a field whose JSON type
    /// is not what we declared. That is exactly how the `rotation_seq` bug
    /// survived: a `u64` where the chain sends a decimal string, fifty green
    /// checks over a form nothing produces, and every real leased binding stuck
    /// `pending`.
    ///
    /// Captured 2026-08-28 from `alpha.tlademo.testnet` on testnet
    /// (`hos_agent_status{"extension":"council.tlademo.testnet"}`). Three of
    /// these fields are near-sdk newtypes and arrive as STRINGS; `impl_version`
    /// is a plain number and arrives as one. Declaring any of them the other
    /// way is not a lenient parse — it is a refusal, and a refusal on this view
    /// is what suspends a lane.
    #[test]
    fn the_status_wire_form_the_partner_contract_sends_deserializes() {
        const CAPTURED: &str = r#"{
            "extension_enabled": true,
            "grant": null,
            "state": "Active",
            "frozen": "Unfrozen",
            "lease_until_ns": "1818746516312653999",
            "reserve_yocto": "12130000000000000000000",
            "impl_version": 6
        }"#;

        let view: AgentStatusView =
            serde_json::from_str(CAPTURED).expect("the chain's own answer must deserialize");
        assert!(view.extension_enabled);
        assert!(view.grant.is_none());
        assert_eq!(view.state, "Active");
        assert_eq!(view.frozen, "Unfrozen", "`frozen` is a FreezeState name, not a boolean");
        assert_eq!(view.lease_until_ns, "1818746516312653999");
        assert_eq!(view.reserve_yocto, "12130000000000000000000");
        assert_eq!(view.impl_version, 6);

        // The near-sdk fields as JSON numbers — the shape a naive fixture
        // produces — must NOT quietly succeed. If they ever do, the two forms
        // have diverged and a stub can go green over one the chain never sends.
        for wrong in [
            r#"{"lease_until_ns": 1818746516312653999}"#,
            r#"{"reserve_yocto": 12130000000000000000000}"#,
        ] {
            assert!(
                serde_json::from_str::<AgentStatusView>(wrong).is_err(),
                "a JSON number was accepted where the chain sends a string: {wrong}"
            );
        }

        // And `impl_version` the other way round: a string here is not the
        // wire form either, and reading it as one would let a version gate
        // pass on a value it never checked.
        assert!(
            serde_json::from_str::<AgentStatusView>(r#"{"impl_version": "6"}"#).is_err(),
            "`impl_version` is a plain number on the wire"
        );

        // A missing field is a DEFAULT, not an error — the fail-closed checks
        // below read those defaults, and they must be reachable.
        let bare: AgentStatusView = serde_json::from_str("{}").expect("an empty answer defaults");
        assert!(!bare.extension_enabled);
        assert_eq!(bare.lease_until_ns, "0");
        assert_eq!(bare.reserve_yocto, "0");
    }

}
