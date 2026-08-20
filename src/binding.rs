//! The binding profiles — the ONE module that knows both modes exist.
//!
//! A custody wallet can be bound to an on-chain account in two mutually
//! exclusive modes:
//!
//! * [`HosLease`] — the partner mode: a leased, keyless House-of-Stake wallet
//!   account (`agent.tla`). On-chain spend grants, lease, freeze, ownership
//!   rotation. Versioned by `impl_version` against [`hos::DECODER_FOR_IMPL`].
//! * [`PersonalAccount`] — the owner's own `user.near` with the upstream
//!   no-sign wallet contract installed by the owner personally. No grants, no
//!   lease, no rotation; the only lifecycle event is the executor vanishing
//!   from the extension set, and the only spending wall is our policy.
//!   Versioned by the account's wasm code hash against
//!   [`WALLET_CODE_HASHES`] — the client never declares a version.
//!
//! Three rules make confusing the modes impossible rather than forbidden:
//!
//! 1. **The core never sees a kind.** `decode`/`effects`/`semantic`/policy
//!    evaluation take no mode parameter; a guard test in this module asserts
//!    the core sources do not even mention [`BindingKind`].
//! 2. **One dispatch point.** [`admit`] is the only place that matches a kind
//!    to a profile, exhaustively and with no default arm. Callers that need
//!    to know WHAT to fetch ask [`status_query`] and match on the returned
//!    query — data this module handed them — never on the kind itself.
//! 3. **A profile only refuses.** Core denials are terminal and run first;
//!    the worst a profile bug can produce is a spurious refusal, never a
//!    spurious signature.

use serde::{Deserialize, Serialize};

use crate::hos::AgentStatusView;
use crate::wallet_request_decode::EffectsSet;

// ============================================================================
// Kind
// ============================================================================

/// Which binding mode a record claims. Matches everywhere are exhaustive and
/// default-free on purpose: adding a third mode must break every match until
/// each site states what the new mode means there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingKind {
    HosLease,
    PersonalAccount,
}

impl BindingKind {
    /// Wire name, as the API and job payloads carry it.
    pub fn as_str(self) -> &'static str {
        match self {
            BindingKind::HosLease => "hos_lease",
            BindingKind::PersonalAccount => "personal_account",
        }
    }

    /// Parse a wire name. `None` for anything unknown — callers refuse, they
    /// do not guess.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "hos_lease" => Some(BindingKind::HosLease),
            "personal_account" => Some(BindingKind::PersonalAccount),
            _ => None,
        }
    }
}

// ============================================================================
// Version registries
// ============================================================================

/// Wasm code hashes of wallet contracts the [`PersonalAccount`] profile
/// accepts, sha256 of the exact published artifact. The analogue of
/// [`hos::DECODER_FOR_IMPL`]: it compiles into the measured keystore image,
/// so nothing outside the enclave can teach us to trust other code.
///
/// An account whose code hash is not in this list fails verification — that
/// covers a redeployed account, a wiped account, and a stranger's contract
/// that merely copies the method names.
pub const WALLET_CODE_HASHES: &[[u8; 32]] = &[
    // defuse-wallet-no-sign @ 6095765f (near/intents), built with the crate's
    // pinned toolchain (rust 1.97.1) and the flags from its
    // `[package.metadata.near.reproducible_build]`.
    WALLET_NO_SIGN_6095765F,
];

/// See [`WALLET_CODE_HASHES`]. Named so reports and tests can reference the
/// specific artifact.
///
/// * sha256 hex: `a299f8ce42ee728d4dd7dede98fde3aea966e8f9c4c18e4e29086d3a7282ee66`
/// * base58 (as `view_account.code_hash` reports it): `BwjDnyemmBhrCyuviDGpoQAm9mdjTfrX7ZjqgZB4MHvM`
/// * size: 277,945 bytes
///
/// # Reproducing this hash, byte for byte
///
/// The build is DETERMINISTIC (verified: two container runs, identical hash).
/// Anyone can derive it from public source; nothing about it depends on who
/// built it, which is what publishing the global contract *by hash* requires.
///
/// ```text
/// git clone https://github.com/near/intents
/// cd intents
/// git checkout 6095765f          # "chore: autoimpl `RecoverableDeriveSigner` (#330)", 2026-07-30
/// cd contracts/wallet/signatures/no-sign
/// cargo near build reproducible-wasm
/// shasum -a 256 ../../../../target/near/defuse_wallet_no_sign/defuse_wallet_no_sign.wasm
/// ```
///
/// What pins the toolchain (all inside the repo, nothing supplied from here):
/// * rustc 1.97.1 + target wasm32-unknown-unknown — `rust-toolchain` at the repo root;
/// * cargo-near 0.22.0 in Docker image `sourcescan/cargo-near:0.22.0-rust-1.97.1`,
///   digest `sha256:7467038bdddc86484b73b416eeadce926ff59013e128e53dec5a19e1cb4b2234` —
///   `[package.metadata.near.reproducible_build]` in the crate's Cargo.toml;
/// * cargo flags `--locked --no-default-features --features=contract
///   --abi-features=abi,contract` — same metadata table (`container_build_command`);
/// * `Cargo.lock` at that commit (hence `--locked`).
///
/// Requirements: a running Docker daemon and a CLEAN work tree at the pinned
/// commit — the container builds from the committed source, and local edits
/// or a different commit change the hash. A host (non-container) build does
/// NOT reproduce it: NEP-330 metadata embeds the build command, so
/// `non-reproducible-wasm` output hashes differently by construction.
pub const WALLET_NO_SIGN_6095765F: [u8; 32] = [
    0xa2, 0x99, 0xf8, 0xce, 0x42, 0xee, 0x72, 0x8d, 0x4d, 0xd7, 0xde, 0xde, 0x98, 0xfd, 0xe3,
    0xae, 0xa9, 0x66, 0xe8, 0xf9, 0xc4, 0xc1, 0x8e, 0x4e, 0x29, 0x08, 0x6d, 0x3a, 0x72, 0x82,
    0xee, 0x66,
];

/// Decode a chain-reported base58 code hash (`view_account.code_hash`) into
/// raw bytes. `None` when it is not a 32-byte base58 string.
pub fn parse_code_hash_base58(s: &str) -> Option<[u8; 32]> {
    let bytes = bs58::decode(s).into_vec().ok()?;
    bytes.try_into().ok()
}

/// The base58 all-zeros sentinel `view_account.code_hash` reports for an
/// account that stores no code of its own.
pub const NO_CODE_HASH_B58: &str = "11111111111111111111111111111111";

/// Which hash actually identifies the code an account RUNS.
///
/// NEP-591 split the answer in two: an inline `DeployContract` puts the wasm
/// hash in `code_hash`, but `UseGlobalContract` leaves `code_hash` at the
/// all-zeros sentinel and reports the referenced hash in
/// `global_contract_hash`. A verifier reading only `code_hash` would refuse
/// every account installed the RECOMMENDED way — the setup kit's own path —
/// which is exactly how this function earned its live-probe test.
///
/// `None` = the account runs no code at all (or, fail-closed, references a
/// mutable by-account-id global, whose hash is not statable).
pub fn effective_code_hash_b58(
    code_hash: Option<&str>,
    global_contract_hash: Option<&str>,
) -> Option<String> {
    match (code_hash, global_contract_hash) {
        (Some(NO_CODE_HASH_B58), Some(global)) => Some(global.to_string()),
        (Some(NO_CODE_HASH_B58), None) => None,
        (Some(inline), _) => Some(inline.to_string()),
        (None, global) => global.map(str::to_string),
    }
}

// ============================================================================
// What a profile consumes and produces
// ============================================================================

/// The chain evidence for a `personal_account` binding: extension membership
/// plus the account's code hash. Both come from the chain, never from the
/// caller; a default-constructed value fails verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlainStatus {
    /// `w_is_extension_enabled(executor)` on the bound account.
    pub extension_enabled: bool,
    /// The account's current wasm code hash (raw 32 bytes).
    pub code_hash: [u8; 32],
}

/// Version evidence, one variant per mode. Each profile's
/// [`BindingProfile::version_gate`] accepts exactly its own variant and
/// refuses the other — version claims cannot cross modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVersion {
    /// `hos_lease`: the `impl_version` the asset account reports.
    ImplVersion(u32),
    /// `personal_account`: the account's wasm code hash.
    CodeHash([u8; 32]),
}

/// What a successful verification proved. Carried forward so later stages
/// (profile admission over decoded effects) reason about verified facts, not
/// re-fetched ones. Matches are exhaustive: a new mode must say what its
/// verified state contains.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifiedState {
    /// The full pre-flight view, grant included — admission reads it.
    HosLease { status: AgentStatusView },
    /// Membership held and the code hash was recognized as this one.
    PersonalAccount { code_hash: [u8; 32] },
}

/// Why a binding must not be treated as live. Grouped by how the lifecycle
/// reacts: terminal (the binding is over), reversible (suspend and re-check),
/// and evidence problems (always refuse, never guess).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingFault {
    /// The executor is not (or no longer) in the account's extension set.
    /// Terminal in both modes — for `personal_account` it is the ONLY
    /// lifecycle event that exists.
    ExtensionDisabled,
    /// `hos_lease`: the lease ran out; the account is reclaimable.
    LeaseExpired,
    /// `hos_lease`: the status reports the account itself as expired.
    ///
    /// Defensive: the `OperatingState` this build knows has no such variant
    /// (an ended lease arrives as `lease_until_ns`), so today only a future
    /// contract could produce it. Kept, and kept TERMINAL, so that if one ever
    /// does the answer is "the lane is over" rather than the reversible
    /// `StateNotActive` the catch-all would give it.
    StateExpired,
    /// `hos_lease`: recovery or a manual freeze; reversible.
    Frozen(String),
    /// `hos_lease`: `Parked` / `Suspended` / anything not `Active`.
    StateNotActive(String),
    /// `hos_lease`: the account migrated to an implementation this build has
    /// no decoder for.
    ImplVersionUnsupported(u32),
    /// `personal_account`: the account's code hash is not in
    /// [`WALLET_CODE_HASHES`] — a redeploy, a wipe, or a stranger's contract
    /// with familiar method names. Reversible: the owner may restore the
    /// recognized code. Carries the observed hash, base58, for the log line.
    CodeHashUnknown(String),
    /// The observation handed to [`admit`] belongs to the OTHER mode — a
    /// plumbing bug or a raced kind change. Refuse; never evaluate one
    /// mode's evidence under the other mode's rules.
    EvidenceMismatch,
    /// A field did not parse. Named separately from the lifecycle faults so
    /// schema drift shows up as itself, not as a fake "lease expired".
    Malformed(String),
}

impl BindingFault {
    /// The error CLASS a client switches on, stable across message wording.
    /// Exhaustive and default-free: a new fault must state its own name here
    /// rather than inherit somebody else's.
    pub fn class(&self) -> &'static str {
        match self {
            BindingFault::ExtensionDisabled => "executor_not_in_control_set",
            BindingFault::LeaseExpired => "lease_expired",
            BindingFault::StateExpired => "account_expired",
            BindingFault::Frozen(_) => "account_frozen",
            BindingFault::StateNotActive(_) => "account_not_active",
            BindingFault::ImplVersionUnsupported(_) => "unsupported_wallet_implementation",
            BindingFault::CodeHashUnknown(_) => "unrecognized_wallet_code",
            BindingFault::EvidenceMismatch => "binding_evidence_mismatch",
            BindingFault::Malformed(_) => "chain_status_unreadable",
        }
    }

    /// Is retrying this request pointless?
    ///
    /// The dividing line is whether the SAME request could later succeed with
    /// nobody rewriting it. A freeze can be lifted, a parked account
    /// reactivated, recognized code redeployed — those are worth retrying,
    /// like a gas top-up. A lease that ran out, an executor cut from the
    /// control set, a version this build has no decoder for: the lane is over
    /// and someone has to build a new one.
    pub fn is_terminal(&self) -> bool {
        match self {
            BindingFault::ExtensionDisabled
            | BindingFault::LeaseExpired
            | BindingFault::StateExpired
            | BindingFault::ImplVersionUnsupported(_)
            | BindingFault::EvidenceMismatch
            | BindingFault::Malformed(_) => true,
            BindingFault::Frozen(_)
            | BindingFault::StateNotActive(_)
            | BindingFault::CodeHashUnknown(_) => false,
        }
    }
}

impl std::fmt::Display for BindingFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingFault::ExtensionDisabled => {
                write!(f, "executor is not in the account's extension set")
            }
            BindingFault::LeaseExpired => write!(f, "the account's lease has expired"),
            BindingFault::StateExpired => write!(f, "the account is in the Expired state"),
            BindingFault::Frozen(v) => write!(f, "the account is frozen ({v})"),
            BindingFault::StateNotActive(v) => write!(f, "the account state is {v}, not Active"),
            BindingFault::ImplVersionUnsupported(v) => {
                write!(f, "wallet implementation version {v} is not supported")
            }
            BindingFault::CodeHashUnknown(h) => {
                write!(f, "the account's contract code (hash {h}) is not a recognized wallet build")
            }
            BindingFault::EvidenceMismatch => {
                write!(f, "the chain evidence does not match the binding's mode")
            }
            BindingFault::Malformed(what) => {
                write!(f, "unreadable field in the chain status: {what}")
            }
        }
    }
}

// ============================================================================
// The sealed profile trait
// ============================================================================

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::HosLease {}
    impl Sealed for super::PersonalAccount {}
}

/// A binding mode's rules. Sealed: a third profile cannot appear outside this
/// crate, so every mode that exists is visible from this file.
pub trait BindingProfile: sealed::Sealed {
    const KIND: BindingKind;

    /// The chain evidence this profile verifies. The types are DIFFERENT per
    /// profile on purpose — handing one mode's status to the other mode's
    /// verifier is a compile error, not a runtime surprise.
    type ChainStatus;

    /// Read the evidence fail-closed. `Ok` means the lane is live RIGHT NOW.
    fn verify(status: &Self::ChainStatus, now_ns: u64) -> Result<VerifiedState, BindingFault>;

    /// Gate the mode's version evidence to a decoder version. Refuses the
    /// other mode's evidence variant.
    fn version_gate(version: &ChainVersion) -> Result<u32, BindingFault>;

    /// The mode's OWN rules over the decoded effects — grants and call-form
    /// for the leased mode, nothing for the personal one. Runs AFTER the
    /// core's mode-blind evaluation and may only ADD refusals: an empty
    /// answer changes nothing, and no profile can un-deny what the core
    /// denied. `st` must be this profile's own verified state; anything else
    /// is itself a violation (never a reinterpretation).
    fn admission(fx: &EffectsSet, st: &VerifiedState, now_ns: u64) -> Vec<Violation>;
}

/// One profile-layer refusal: which promise (when attributable), which error
/// CLASS the caller should surface, and a sentence the owner can act on.
///
/// `rule` is the class an API answers with; `subcode` distinguishes the
/// members of a class that share it (every call-form refusal is a
/// `grant_shape_violation`, but the owner still needs to know WHICH form
/// rule). Classes are the ones the integration plan fixes, so that a client
/// switching on them never has to parse a sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub promise_index: Option<usize>,
    pub rule: &'static str,
    pub subcode: Option<&'static str>,
    pub message: String,
}

impl Violation {
    /// The class as an API answers with it: `rule` alone, or `rule:subcode`
    /// where the class has members the owner must tell apart.
    pub fn class(&self) -> String {
        match self.subcode {
            Some(sub) => format!("{}:{}", self.rule, sub),
            None => self.rule.to_string(),
        }
    }

    /// Every profile refusal is terminal, and the reason is structural rather
    /// than a coincidence of the current list: a profile only ever refuses
    /// what the CHAIN would refuse, and the chain's answer does not change
    /// while the request and the grant stay as they are. So retrying is
    /// always the wrong move — the owner must re-grant, re-fund or rewrite the
    /// request. `insufficient_vs_reserve` looks like the exception (funding
    /// the account would clear it) and is deliberately terminal anyway: the
    /// integration plan's error table lists it so, because an agent that
    /// retried it would spin against a floor only its owner can move.
    ///
    /// A method rather than a constant, so that the day a retryable profile
    /// rule exists, this is where it has to say so.
    pub fn is_terminal(&self) -> bool {
        true
    }

    /// Did [`admission`] stop before it looked at a single promise?
    ///
    /// These are the rules the contract answers with on its way IN, before any
    /// promise is charged: the grant gate (`charge_spend` reads the grant and
    /// its expiry once, first) and the refusal to evaluate at all (evidence of
    /// the wrong mode). When one of them fires, the chain never reached a
    /// promise — so a caller must not decorate the answer with promise-level
    /// rules it computed separately, because those describe a stage the request
    /// never got to.
    ///
    /// Concretely: a name transfer aimed at the account's own collection made
    /// with NO grant is a `grant_missing`, not an `own_collection_refused`.
    /// Telling the owner the second sends them to rewrite a request whose only
    /// real problem is that nobody granted them anything.
    ///
    /// A method beside the rule strings, not a list at the call site, so the
    /// two cannot drift; `every_early_return_answers_alone` in `hos` pins it in
    /// both directions.
    pub fn answers_alone(&self) -> bool {
        matches!(
            self.rule,
            "evidence_mismatch" | "grant_missing" | "grant_unreadable" | "grant_expired"
        )
    }
}

/// The partner mode. Verification logic lives in [`hos`], next to the types
/// it reads.
pub struct HosLease;

/// The owner's own account with the upstream no-sign wallet. Verification is
/// exactly two facts: membership and a recognized code hash — there is
/// nothing else to check, and nothing else may be invented here.
pub struct PersonalAccount;

impl BindingProfile for PersonalAccount {
    const KIND: BindingKind = BindingKind::PersonalAccount;
    type ChainStatus = PlainStatus;

    fn verify(status: &PlainStatus, _now_ns: u64) -> Result<VerifiedState, BindingFault> {
        // The CODE first, then the membership. "Is this even a wallet we know?"
        // precedes "are we in its extension set?", and the order decides the
        // lifecycle: an unrecognized code hash is REVERSIBLE (the owner may
        // redeploy the recognized build), while a removed extension is
        // TERMINAL. Asking about membership first would answer a redeployed or
        // wiped account — whose membership view does not even exist, so it
        // reads as `false` — with the terminal fault, ending a binding the
        // owner could have restored.
        if !WALLET_CODE_HASHES.contains(&status.code_hash) {
            return Err(BindingFault::CodeHashUnknown(
                bs58::encode(status.code_hash).into_string(),
            ));
        }
        if !status.extension_enabled {
            return Err(BindingFault::ExtensionDisabled);
        }
        Ok(VerifiedState::PersonalAccount {
            code_hash: status.code_hash,
        })
    }

    fn version_gate(version: &ChainVersion) -> Result<u32, BindingFault> {
        match version {
            ChainVersion::CodeHash(h) => {
                if WALLET_CODE_HASHES.contains(h) {
                    // One recognized build, one decoder. When a second build
                    // lands in the allowlist with a different wire format,
                    // this becomes a lookup like DECODER_FOR_IMPL.
                    Ok(1)
                } else {
                    Err(BindingFault::CodeHashUnknown(
                        bs58::encode(h).into_string(),
                    ))
                }
            }
            ChainVersion::ImplVersion(_) => Err(BindingFault::EvidenceMismatch),
        }
    }

    /// Deliberately empty — and kept empty. The personal mode has no grants,
    /// no lease and no call-form rules: the owner's own contract accepts
    /// bundles, refunds and any deposit, so the only wall is the policy the
    /// CORE already enforced. Inventing extra refusals here would be this
    /// module deciding product rules that nobody wrote down.
    fn admission(_fx: &EffectsSet, st: &VerifiedState, _now_ns: u64) -> Vec<Violation> {
        match st {
            VerifiedState::PersonalAccount { .. } => Vec::new(),
            VerifiedState::HosLease { .. } => vec![Violation {
                promise_index: None,
                rule: "evidence_mismatch",
                subcode: None,
                message: "the verified state belongs to the leased mode, not personal_account"
                    .to_string(),
            }],
        }
    }
}

// ============================================================================
// The single dispatch point
// ============================================================================

/// What a caller must fetch from the chain to verify a binding of `kind`.
/// Data, not behavior: the caller executes the described views mechanically
/// and matches on THIS enum — never on the kind — so the mapping
/// kind → required evidence lives here and only here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusQuery {
    /// `hos_agent_status(executor)` on the asset account. The caller that
    /// tracks lifecycle additionally pins/compares `nft_item_info().rotation_seq`.
    HosAgentStatus,
    /// `w_is_extension_enabled(executor)` + the account's code hash.
    ExtensionAndCodeHash,
}

pub fn status_query(kind: BindingKind) -> StatusQuery {
    match kind {
        BindingKind::HosLease => StatusQuery::HosAgentStatus,
        BindingKind::PersonalAccount => StatusQuery::ExtensionAndCodeHash,
    }
}

/// The chain evidence a caller gathered, still labeled by shape.
///
/// Serializable so a caller may cache the EVIDENCE for a few seconds. Note
/// what is deliberately not cacheable: the verdict. `admit` is re-run on the
/// cached evidence every time, so a lease that ran out during the cache window
/// is caught by the clock rather than papered over by it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChainObservation {
    HosLease(AgentStatusView),
    PersonalAccount(PlainStatus),
}

/// Evidence plus the facts about the ACCOUNT that do not change while it is
/// the same account.
///
/// `collection_id` is the registry an item account belongs to: fixed for the
/// life of the account, and needed on every spend to apply the own-collection
/// rule. Fetching it per call is a view call for an answer that cannot have
/// changed — so it rides along with the observation and is cached with it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedAccount {
    pub observation: ChainObservation,
    /// `None` for an account that is not a leased item, and for a caller that
    /// could not read it — the own-collection rule is then simply not applied,
    /// exactly as before, and the chain still enforces it.
    #[serde(default)]
    pub collection_id: Option<String>,
}

/// Profile-rule dispatch, same exhaustive shape as [`admit`]: which extra
/// refusals a mode adds over effects the CORE already passed.
pub fn admission(
    kind: BindingKind,
    fx: &EffectsSet,
    st: &VerifiedState,
    now_ns: u64,
) -> Vec<Violation> {
    match kind {
        BindingKind::HosLease => HosLease::admission(fx, st, now_ns),
        BindingKind::PersonalAccount => PersonalAccount::admission(fx, st, now_ns),
    }
}

/// K8: refuse to sign for a wallet implementation this build has no decoder
/// for — checked inside the enclave, against a registry compiled into the
/// measured image.
///
/// The point is R9. If the account migrates to a schema where, say, a field
/// was renamed, our v1 decoder would still parse the request and get a
/// DIFFERENT answer — the policy would then be enforced against effects that
/// are not the request's. Refusing an unknown version is the only honest
/// response, and it has to happen where the signing key is, because that is
/// the last place a wrong answer can still be stopped.
///
/// What this can and cannot do, stated plainly. The enclave has no chain
/// access, so the version reaches it as a claim from the coordinator, and a
/// compromised coordinator can understate it. That is why this is the SECOND
/// gate: the coordinator's pre-flight and the worker both read the version
/// from the chain itself, and a `hos_lease` claim with no version at all is
/// refused here rather than waved through. `personal_account` declares no
/// version by design — its code hash is pinned in this same image and verified
/// against the chain by the two components that can read it.
///
/// `Ok(())` for every other operation: nothing else carries a nested request
/// whose schema could drift.
pub fn signing_version_gate(
    method: &str,
    kind: Option<&str>,
    impl_version: Option<u32>,
) -> Result<(), String> {
    if method != "w_execute_extension" {
        return Ok(());
    }
    // Absent kind means the partner mode, exactly as everywhere else — a job
    // queued before the field existed must keep its meaning.
    let kind = match kind {
        None => BindingKind::HosLease,
        Some(s) => BindingKind::parse(s)
            .ok_or_else(|| format!("unknown binding kind '{s}'; refusing to sign"))?,
    };
    match kind {
        BindingKind::HosLease => {
            let Some(version) = impl_version else {
                return Err(
                    "the leased mode must state the wallet implementation version it runs; \
                     refusing to sign a nested request whose schema is unstated"
                        .to_string(),
                );
            };
            HosLease::version_gate(&ChainVersion::ImplVersion(version))
                .map(|_| ())
                .map_err(|fault| fault.to_string())
        }
        // Versioned by the account's wasm code hash, which this enclave cannot
        // read. Pinned in `WALLET_CODE_HASHES` in this image and checked
        // against the chain by the components that can.
        BindingKind::PersonalAccount => Ok(()),
    }
}

/// THE dispatch: a claimed kind plus gathered evidence → one profile's
/// verdict. Exhaustive over both axes, no default arm. Evidence of the wrong
/// shape for the claimed kind is a refusal — the kind in a job or a row is a
/// hint, and a lying hint may only deny.
pub fn admit(
    kind: BindingKind,
    observation: &ChainObservation,
    now_ns: u64,
) -> Result<VerifiedState, BindingFault> {
    match (kind, observation) {
        (BindingKind::HosLease, ChainObservation::HosLease(status)) => {
            HosLease::verify(status, now_ns)
        }
        (BindingKind::PersonalAccount, ChainObservation::PersonalAccount(status)) => {
            PersonalAccount::verify(status, now_ns)
        }
        (BindingKind::HosLease, ChainObservation::PersonalAccount(_))
        | (BindingKind::PersonalAccount, ChainObservation::HosLease(_)) => {
            Err(BindingFault::EvidenceMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_hos() -> AgentStatusView {
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

    fn recognized_hash() -> [u8; 32] {
        WALLET_CODE_HASHES[0]
    }

    #[test]
    fn the_core_never_mentions_a_binding_kind() {
        // The guard the trait design promises: mode-blindness of the core is
        // checked, not assumed. Every core source added later (decode /
        // effects / semantic) goes into this list.
        const CORE_SOURCES: &[(&str, &str)] = &[
            ("wallet_policy.rs", include_str!("wallet_policy.rs")),
        ];
        for (name, source) in CORE_SOURCES {
            assert!(
                !source.contains("BindingKind"),
                "{name} must stay mode-blind: it mentions BindingKind"
            );
        }
    }

    #[test]
    fn admit_dispatches_each_kind_to_its_own_profile() {
        let hos_obs = ChainObservation::HosLease(healthy_hos());
        let personal_obs = ChainObservation::PersonalAccount(PlainStatus {
            extension_enabled: true,
            code_hash: recognized_hash(),
        });

        assert!(matches!(
            admit(BindingKind::HosLease, &hos_obs, 1000),
            Ok(VerifiedState::HosLease { .. })
        ));
        assert!(matches!(
            admit(BindingKind::PersonalAccount, &personal_obs, 1000),
            Ok(VerifiedState::PersonalAccount { .. })
        ));
    }

    #[test]
    fn evidence_of_the_wrong_shape_is_refused_not_reinterpreted() {
        // A lying kind hint may only deny: hos evidence under the personal
        // profile (and vice versa) never reaches either verifier.
        let hos_obs = ChainObservation::HosLease(healthy_hos());
        let personal_obs = ChainObservation::PersonalAccount(PlainStatus {
            extension_enabled: true,
            code_hash: recognized_hash(),
        });
        assert_eq!(
            admit(BindingKind::PersonalAccount, &hos_obs, 1000),
            Err(BindingFault::EvidenceMismatch)
        );
        assert_eq!(
            admit(BindingKind::HosLease, &personal_obs, 1000),
            Err(BindingFault::EvidenceMismatch)
        );
    }

    #[test]
    fn a_personal_binding_needs_membership_and_a_recognized_hash() {
        let ok = PlainStatus { extension_enabled: true, code_hash: recognized_hash() };
        assert!(matches!(
            PersonalAccount::verify(&ok, 0),
            Ok(VerifiedState::PersonalAccount { .. })
        ));

        // Removed from the extension set — the mode's one revocation event.
        let removed = PlainStatus { extension_enabled: false, code_hash: recognized_hash() };
        assert_eq!(
            PersonalAccount::verify(&removed, 0),
            Err(BindingFault::ExtensionDisabled)
        );

        // A stranger's contract with the same method names: same view answers
        // `true`, but the hash gives it away. This is the whole reason the
        // allowlist exists.
        let impostor = PlainStatus { extension_enabled: true, code_hash: [0xAB; 32] };
        assert!(matches!(
            PersonalAccount::verify(&impostor, 0),
            Err(BindingFault::CodeHashUnknown(_))
        ));

        // Unknown code AND no membership — the shape a redeployed or wiped
        // account takes, because a contract without our methods cannot answer
        // the membership view at all. The CODE must be the answer: it is
        // reversible, and `ExtensionDisabled` would end the binding for good.
        let redeployed = PlainStatus { extension_enabled: false, code_hash: [0xAB; 32] };
        assert!(
            matches!(
                PersonalAccount::verify(&redeployed, 0),
                Err(BindingFault::CodeHashUnknown(_))
            ),
            "a redeployed account must be recoverable, not terminally revoked"
        );
    }

    #[test]
    fn version_evidence_cannot_cross_modes() {
        assert_eq!(
            PersonalAccount::version_gate(&ChainVersion::ImplVersion(6)),
            Err(BindingFault::EvidenceMismatch)
        );
        assert_eq!(
            HosLease::version_gate(&ChainVersion::CodeHash(recognized_hash())),
            Err(BindingFault::EvidenceMismatch)
        );
        assert_eq!(
            PersonalAccount::version_gate(&ChainVersion::CodeHash(recognized_hash())),
            Ok(1)
        );
        assert_eq!(HosLease::version_gate(&ChainVersion::ImplVersion(6)), Ok(1));
        assert!(matches!(
            HosLease::version_gate(&ChainVersion::ImplVersion(5)),
            Err(BindingFault::ImplVersionUnsupported(5))
        ));
    }

    #[test]
    fn status_query_names_each_modes_evidence() {
        assert_eq!(status_query(BindingKind::HosLease), StatusQuery::HosAgentStatus);
        assert_eq!(
            status_query(BindingKind::PersonalAccount),
            StatusQuery::ExtensionAndCodeHash
        );
    }

    #[test]
    fn the_core_verdict_is_identical_under_both_profiles() {
        // Differential invariant: one request, both profiles → the CORE
        // verdict is byte-for-byte the same, because the core cannot even be
        // TOLD the kind (no signature accepts one — see the grep-guard
        // above). This test exists so that the day someone adds a kind
        // parameter to the policy engine, they must come here and explain
        // which mode is supposed to see a different core verdict — there is
        // no such mode.
        use crate::wallet_policy::{evaluate, Decision, Op, Policy};

        let policy: Policy = serde_json::from_value(serde_json::json!({
            "rules": {
                "transaction_types": ["call", "transfer"],
                "addresses": { "mode": "whitelist", "list": ["user.near", "agent.tla"] }
            }
        }))
        .unwrap();

        // The extension door (core-denied until the decoder ships) and an
        // ordinary call (core-allowed) — the two verdict classes that exist.
        let ops = [
            Op::Call {
                to: "user.near".into(),
                method: "w_execute_extension".into(),
                args_base64: "e30=".into(),
                gas: "100000000000000".into(),
                deposit: "1".into(),
            },
            Op::Call {
                to: "user.near".into(),
                method: "storage_deposit".into(),
                args_base64: "e30=".into(),
                gas: "30000000000000".into(),
                deposit: "1".into(),
            },
        ];

        for op in &ops {
            let mut verdicts: Vec<String> = Vec::new();
            for _kind in [BindingKind::HosLease, BindingKind::PersonalAccount] {
                // NOTE the absent argument: `_kind` cannot be passed in.
                let decision = evaluate(&policy, op, None, 0);
                verdicts.push(format!("{decision:?}"));
            }
            assert_eq!(verdicts[0], verdicts[1], "core verdict diverged for {op:?}");
        }

        // The profiles may differ ONLY in their own layer: the same healthy
        // evidence admits under its own profile and refuses under the other.
        let hos_obs = ChainObservation::HosLease(healthy_hos());
        assert!(admit(BindingKind::HosLease, &hos_obs, 1000).is_ok());
        assert!(admit(BindingKind::PersonalAccount, &hos_obs, 1000).is_err());
    }

    #[test]
    fn the_effective_code_hash_covers_both_install_paths() {
        // Found by the live kit probe: UseGlobalContract leaves code_hash at
        // the zero sentinel and reports the real hash elsewhere. Reading only
        // code_hash refused every account installed the recommended way.
        let pinned = bs58::encode(WALLET_CODE_HASHES[0]).into_string();

        // Inline deploy: code_hash carries the truth.
        assert_eq!(
            effective_code_hash_b58(Some(&pinned), None),
            Some(pinned.clone())
        );
        // Global reference: the sentinel defers to global_contract_hash.
        assert_eq!(
            effective_code_hash_b58(Some(NO_CODE_HASH_B58), Some(&pinned)),
            Some(pinned.clone())
        );
        // No code at all.
        assert_eq!(effective_code_hash_b58(Some(NO_CODE_HASH_B58), None), None);
        // Inline code wins over a (nonsensical) simultaneous global field —
        // the account RUNS its inline code.
        assert_eq!(
            effective_code_hash_b58(Some(&pinned), Some(NO_CODE_HASH_B58)),
            Some(pinned)
        );
    }

    #[test]
    fn every_fault_names_a_class_and_answers_whether_retrying_helps() {
        // The distinction an agent acts on. Retryable means the SAME request
        // can later succeed with nobody rewriting it; terminal means a human
        // has to do something first, and a client that retries anyway spins
        // while its owner is never told.
        let retryable = [
            BindingFault::Frozen("AuthorityFrozen".into()),
            BindingFault::StateNotActive("Parked".into()),
            BindingFault::CodeHashUnknown("x".into()),
        ];
        let terminal = [
            BindingFault::ExtensionDisabled,
            BindingFault::LeaseExpired,
            BindingFault::StateExpired,
            BindingFault::ImplVersionUnsupported(9),
            BindingFault::EvidenceMismatch,
            BindingFault::Malformed("x".into()),
        ];

        for f in &retryable {
            assert!(!f.is_terminal(), "{f:?} can clear without a new request");
        }
        for f in &terminal {
            assert!(f.is_terminal(), "{f:?} cannot clear by retrying");
        }

        // Classes are distinct — a client routing on them must never see two
        // different conditions arrive under one name.
        let mut classes: Vec<&str> = retryable
            .iter()
            .chain(terminal.iter())
            .map(|f| f.class())
            .collect();
        let total = classes.len();
        classes.sort();
        classes.dedup();
        assert_eq!(classes.len(), total, "two faults share a class: {classes:?}");
    }

    #[test]
    fn a_violation_reports_its_class_with_the_subcode_that_narrows_it() {
        let with_sub = Violation {
            promise_index: Some(1),
            rule: "grant_shape_violation",
            subcode: Some("grant_call_deposit"),
            message: "x".into(),
        };
        assert_eq!(with_sub.class(), "grant_shape_violation:grant_call_deposit");
        assert!(with_sub.is_terminal());

        let bare = Violation {
            promise_index: None,
            rule: "grant_exhausted",
            subcode: None,
            message: "x".into(),
        };
        assert_eq!(bare.class(), "grant_exhausted");
    }

    #[test]
    fn the_enclave_refuses_to_sign_for_an_unstated_or_unknown_implementation() {
        // Ordinary operations carry no nested request — nothing to gate.
        assert!(signing_version_gate("ft_transfer", None, None).is_ok());
        assert!(signing_version_gate("storage_deposit", Some("hos_lease"), None).is_ok());

        // The door, leased mode: the version must be stated AND supported.
        assert!(signing_version_gate("w_execute_extension", Some("hos_lease"), Some(6)).is_ok());
        assert!(signing_version_gate("w_execute_extension", Some("hos_lease"), Some(5)).is_err());
        assert!(
            signing_version_gate("w_execute_extension", Some("hos_lease"), None).is_err(),
            "an unstated version must refuse, not default to the one decoder we happen to have"
        );

        // No kind means the partner mode — same demand, so a dropped field
        // cannot become a way around the gate.
        assert!(signing_version_gate("w_execute_extension", None, None).is_err());
        assert!(signing_version_gate("w_execute_extension", None, Some(6)).is_ok());

        // The personal mode states no version: its code hash is pinned in this
        // image and verified against the chain elsewhere.
        assert!(signing_version_gate("w_execute_extension", Some("personal_account"), None).is_ok());

        // A kind this build does not know is a refusal, never a guess.
        assert!(signing_version_gate("w_execute_extension", Some("delegation"), Some(6)).is_err());
    }

    #[test]
    fn wire_names_round_trip_and_unknown_is_refused() {
        for kind in [BindingKind::HosLease, BindingKind::PersonalAccount] {
            assert_eq!(BindingKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(BindingKind::parse("hos-lease"), None);
        assert_eq!(BindingKind::parse(""), None);
        assert_eq!(BindingKind::parse("HosLease"), None);
    }
}
