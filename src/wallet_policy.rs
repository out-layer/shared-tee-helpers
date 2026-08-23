//! Unified wallet-policy engine shared by the keystore-worker and the coordinator.
//!
//! This is the single source of truth for:
//! 1. The canonical signable operation (`Op`) and its hash (`request_hash`).
//! 2. The bind mode that tells the keystore HOW it is allowed to produce the
//!    artifact it signs (`BindMode`).
//! 3. Policy evaluation (`evaluate`) — one engine, with the STATEFUL clauses
//!    enabled only when the caller supplies `Usage`.
//!
//! Trust split (see development plan §2.4):
//! - The keystore calls `evaluate(policy, op, None, now)` → only the STATELESS
//!   subset is enforced (frozen, transaction_types, allowed_tokens, addresses,
//!   per_transaction, time, capabilities, the multisig trigger). Stateful
//!   clauses are SKIPPED — that is strictly more permissive, so the keystore
//!   never false-denies an op the coordinator would have allowed.
//! - The coordinator calls `evaluate(policy, op, Some(usage), now)` → FULL
//!   enforcement, supplying per-token daily/hourly/monthly spend + tx count
//!   read from its DB.
//!
//! The multisig TRIGGER (RequiresApproval) is stateless by construction (type /
//! per-tx amount / capability / time) so the keystore can decide independently
//! whether approver signatures are required.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Canonical operation
// ---------------------------------------------------------------------------

/// A canonical signable operation. `request_hash = sha256(canonical_json(op))`.
///
/// Field-naming convention (single source of truth): `to` (never `receiver_id`),
/// `amount` as a yocto/raw-unit decimal STRING (never a JSON number).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Op {
    /// Native NEAR transfer. Built: keystore constructs the NEAR tx from these fields.
    Transfer {
        to: String,
        amount: String,
    },

    /// Function call. Built: keystore constructs the NEAR tx. `args_base64` is the
    /// EXACT argument bytes (base64) so they cannot be renormalized by any JSON layer.
    Call {
        to: String,
        method: String,
        args_base64: String,
        gas: String,
        deposit: String,
    },

    /// Delete account. Built.
    Delete { beneficiary: String },

    /// Intents withdrawal. Built: keystore constructs the NEP-413 intent message
    /// (fresh deadline) from these fields.
    Withdraw {
        to: String,
        amount: String,
        token: String,
    },

    /// Internal Intents transfer: move a token balance from the wallet's intents
    /// balance to ANOTHER account's intents balance, staying inside `intents.near`
    /// (the defuse `transfer` intent), gasless via the solver relay. Built: the
    /// keystore constructs the NEP-413 `transfer` intent message (fresh deadline)
    /// from these fields, so the recipient CANNOT be substituted by the coordinator
    /// (strictly stronger than the Trusted swap path). This is a fund-moving op to an
    /// arbitrary recipient, so `to` is carried in `destination()` and it is gated by
    /// the `to` whitelist + per-token amount limit (exactly like `Withdraw`). Distinct
    /// from `Transfer` (native NEAR on-chain) and `Withdraw` (exits intents to a plain
    /// on-chain account): it has its OWN `intents_transfer` type so a `transfer`/
    /// `withdraw` policy does not implicitly permit it. (Verified against the defuse
    /// `Intent` enum in `near/intents`.)
    IntentsTransfer {
        to: String,
        amount: String,
        token: String,
    },

    /// Raw payload signing (e.g. an Ethereum tx). Hash-pinned: the op carries the
    /// payload hash; the keystore signs the supplied bytes iff sha256(bytes)==payload_hash.
    /// Internals are NOT inspected — gated entirely by the `raw_sign` capability.
    Raw {
        chain: String,
        payload_hash: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },

    /// Off-chain auth message (NEP-413 challenge). Hash-pinned. `recipient` MUST be a
    /// non-fund-moving domain (enforced by the keystore — domain separation).
    SignMessage {
        message_hash: String,
        recipient: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
    },

    /// Intents swap. Trusted: the 1Click quote artifact does not exist at approval
    /// time; the keystore checks capability + policy + multisig on these op fields,
    /// then signs the supplied artifact, trusting the generator.
    Swap {
        token_in: String,
        amount_in: String,
        token_out: String,
        min_out: String,
    },

    /// Confidential-intents flow. Trusted (artifact generated after approval by the
    /// external generate-intent endpoint).
    Confidential {
        flow: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to: Option<String>,
        amount: String,
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chain: Option<String>,
        /// SWAP flow only: output asset + minimum received, so a multisig-approved confidential
        /// swap binds the output terms like Op::Swap. None (omitted from the canonical op) for
        /// non-swap flows. The off-chain deposit address stays coordinator-supplied (same routing
        /// tradeoff as Op::Swap).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token_out: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min_amount_out: Option<String>,
    },

    /// Cross-chain withdrawal via 1Click (swap + bridge). Trusted: the 1Click deposit
    /// address (and thus the transfer-to-deposit artifact) only exists after the quote,
    /// so it can't be Built from the op. The mode is fixed by the KIND (always Trusted) —
    /// NOT by artifact-presence — so a same-chain `Withdraw` can never be flipped to
    /// Trusted by supplying an artifact (that would bypass the Built op↔tx binding).
    /// Policy gates exactly like `Withdraw` (`to` whitelist + amount limit + the
    /// `withdraw`/`intents_withdraw` types), at BOTH the pre-flight check and the sign.
    CrossChainWithdraw {
        to: String,
        amount: String,
        token: String,
        chain: String,
    },

    /// Payment check (claimable-link escrow): the wallet's intents balance is moved to a
    /// keystore-derived ephemeral account that the link's holder later claims. This is a
    /// WHITELIST-BYPASS fund primitive — funds reach an arbitrary recipient via the link —
    /// so a `to` whitelist under-gates it (the ephemeral escrow defeats it). Therefore it
    /// carries NO destination and is gated by a default-DENY `payment_check` CAPABILITY
    /// (opt-in, like raw_sign/confidential) plus the per-token amount limit. Trusted: the
    /// coordinator builds the transfer-to-ephemeral artifact.
    PaymentCheck {
        amount: String,
        token: String,
    },

    /// OutLayer coordinator authentication (Bearer-near / register / api-key). The
    /// keystore CONSTRUCTS a domain-separated `<prefix>:<seed>:<ts>[:<vault>]` string
    /// with a fresh timestamp and signs it RAW ed25519 (NOT NEP-413). It is non-fund
    /// (never a 32-byte tx hash), so it is always allowed — no capability or multisig.
    /// `purpose` selects the prefix: `bearer`→`auth`, `register`→`register`,
    /// `api-key`→`api-key`. `vault_id` is only valid for `bearer`.
    Auth {
        purpose: String,
        seed: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault_id: Option<String>,
    },
}

/// Build the exact byte string the OutLayer coordinator's `verify_near_auth_fields`
/// expects for a given auth purpose, with a fresh `timestamp`. MUST stay byte-for-byte
/// identical to the coordinator's formats:
/// - `bearer`   → `auth:<seed>:<ts>` or `auth:<seed>:<ts>:<vault_id>`
/// - `register` → `register:<seed>:<ts>` (no vault in the signed message)
/// - `api-key`  → `api-key:<seed>:<ts>` (no vault in the signed message)
pub fn build_auth_message(
    purpose: &str,
    seed: &str,
    timestamp: u64,
    vault_id: Option<&str>,
) -> Result<String, String> {
    let prefix = match purpose {
        "bearer" => "auth",
        "register" => "register",
        "api-key" => "api-key",
        other => return Err(format!("unknown auth purpose '{}'", other)),
    };
    match (purpose, vault_id) {
        ("bearer", Some(vid)) => Ok(format!("auth:{}:{}:{}", seed, timestamp, vid)),
        (_, Some(_)) => Err(format!(
            "auth purpose '{}' does not carry vault_id in the signed message",
            purpose
        )),
        (_, None) => Ok(format!("{}:{}:{}", prefix, seed, timestamp)),
    }
}

// ---------------------------------------------------------------------------
// Confidential-intents JWT auth challenge (NEP-413, recipient = intents.near)
// ---------------------------------------------------------------------------
//
// Minting a per-account confidential JWT requires a NEP-413 signature over a
// structured auth challenge whose `intents` array is EMPTY — so it is provably
// non-fund-moving (`intents.near` executes nothing) yet is bound to that contract
// as the NEP-413 recipient. This is why it MUST NOT go through `sign_message` (it
// would need `intents.near` in the recipient allowlist, opening a fund-moving
// recipient) — instead the keystore BUILDS this exact challenge itself via the
// `jwt` auth purpose. The builders live here so the keystore and the coordinator's
// verifier produce byte-identical output.

/// Magic prefix of the 32-byte versioned confidential-auth nonce.
pub const AUTH_NONCE_MAGIC: [u8; 4] = [0x56, 0x28, 0xF6, 0xC6];

/// `external_app_data.configs[].expires_in` used by the live confidential auth flow:
/// 36500 days (~100 years) in seconds.
pub const AUTH_CONFIG_EXPIRES_IN_SECS: u64 = 36500 * 86400;

/// Build the 32-byte versioned + salted confidential-auth nonce.
///
/// ```text
/// [0..4)   magic       0x56 28 F6 C6
/// [4..5)   reserved    0x00  (left zero — salt is 4 bytes at [5..9))
/// [5..9)   salt        from intents.near.current_salt()
/// [9..17)  deadline_ns u64 little-endian
/// [17..25) issued_ns   u64 little-endian
/// [25..32) random      7 bytes
/// ```
pub fn build_jwt_versioned_nonce(
    salt: [u8; 4],
    deadline_ns: u64,
    issued_ns: u64,
    random: [u8; 7],
) -> [u8; 32] {
    let mut nc = [0u8; 32];
    nc[0..4].copy_from_slice(&AUTH_NONCE_MAGIC);
    // nc[4] reserved = 0x00 (left zero).
    nc[5..9].copy_from_slice(&salt);
    nc[9..17].copy_from_slice(&deadline_ns.to_le_bytes());
    nc[17..25].copy_from_slice(&issued_ns.to_le_bytes());
    nc[25..32].copy_from_slice(&random);
    nc
}

/// Build the NEP-413 confidential-auth challenge message. Field order is
/// load-bearing — the message is signed and sent verbatim — so it is emitted from
/// a struct (serde preserves declaration order), producing the compact, space-free
/// form the live `/v0/auth/authenticate` flow expects. `deadline_iso` is the
/// caller-formatted `YYYY-MM-DDTHH:MM:SS.000Z` deadline; the `intents` array is
/// always empty (the domain-separation invariant: this challenge moves no funds).
pub fn build_jwt_auth_message(deadline_iso: &str, signer_id: &str) -> String {
    #[derive(Serialize)]
    struct AuthConfig {
        #[serde(rename = "type")]
        kind: &'static str,
        expires_in: u64,
    }
    #[derive(Serialize)]
    struct ExternalAppData {
        configs: Vec<AuthConfig>,
    }
    #[derive(Serialize)]
    struct AuthMessage<'a> {
        deadline: &'a str,
        intents: Vec<serde_json::Value>,
        signer_id: &'a str,
        external_app_data: ExternalAppData,
    }

    let msg = AuthMessage {
        deadline: deadline_iso,
        intents: Vec::new(),
        signer_id,
        external_app_data: ExternalAppData {
            configs: vec![AuthConfig {
                kind: "auth",
                expires_in: AUTH_CONFIG_EXPIRES_IN_SECS,
            }],
        },
    };
    serde_json::to_string(&msg).expect("auth message serialization is infallible")
}

/// How the keystore is permitted to produce the artifact it signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindMode {
    /// Keystore constructs the artifact FROM the op fields → artifact == approved op.
    Built,
    /// Op carries a payload/message hash; keystore signs supplied bytes iff sha256==hash.
    HashPinned,
    /// Artifact cannot exist at approval time; keystore checks capability + policy +
    /// multisig on op fields, then signs the supplied artifact, trusting the generator.
    Trusted,
}

/// The bind mode for an op. Total function over all kinds.
pub fn bind_mode(op: &Op) -> BindMode {
    match op {
        Op::Transfer { .. }
        | Op::Call { .. }
        | Op::Delete { .. }
        | Op::Withdraw { .. }
        | Op::IntentsTransfer { .. } => BindMode::Built,
        Op::Raw { .. } | Op::SignMessage { .. } => BindMode::HashPinned,
        Op::Swap { .. }
        | Op::Confidential { .. }
        | Op::CrossChainWithdraw { .. }
        | Op::PaymentCheck { .. } => BindMode::Trusted,
        // Auth is constructed-from-op (fresh-ts auth string), like the Built kinds.
        Op::Auth { .. } => BindMode::Built,
    }
}

/// Deterministic canonical JSON for an op: serde-serialize, then recursively sort
/// every object's keys, then compact-encode. All amounts are already strings, so no
/// numeric renormalization can occur; the recursive sort defends against any nesting
/// and against `serde_json` builds compiled with the `preserve_order` feature.
pub fn canonical_json(op: &Op) -> String {
    let value = serde_json::to_value(op).expect("Op serialization is infallible");
    let canonical = canonicalize_value(&value);
    serde_json::to_string(&canonical).expect("Value serialization is infallible")
}

// ---------------------------------------------------------------------------
/// A wallet signs with its own key, always. There are no connector sub-keys.
///
/// If a connector ever needs to act under an address of its own, that is a
/// feature to design then, and the hard part is not the derivation: a
/// connector-scoped signature has to move the MESSAGE, the SIGNATURE and the
/// BALANCE the funds leave from to that address together.

/// `sha256(canonical_json(op))` as lowercase hex.
pub fn request_hash(op: &Op) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_json(op).as_bytes());
    hex::encode(hasher.finalize())
}

fn canonicalize_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            // BTreeMap-backed insertion gives sorted keys even under `preserve_order`.
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), canonicalize_value(&map[key]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonicalize_value).collect())
        }
        other => other.clone(),
    }
}

impl Op {
    /// The policy `transaction_types` strings this op is allowed to match against.
    /// Multiple aliases preserve compatibility with policies authored against the
    /// legacy coordinator action names (`intents_withdraw`, `intents_swap`).
    pub fn type_aliases(&self) -> &'static [&'static str] {
        match self {
            Op::Transfer { .. } => &["transfer"],
            Op::Call { .. } => &["call"],
            Op::Delete { .. } => &["delete"],
            Op::Withdraw { .. } => &["withdraw", "intents_withdraw"],
            // Internal intents transfer gets its OWN type (NOT folded into `transfer`, which
            // is native NEAR, nor `withdraw`): a policy must explicitly list `intents_transfer`
            // to permit it. Gated by the `to` whitelist + per-token amount limit like withdraw.
            Op::IntentsTransfer { .. } => &["intents_transfer"],
            // Cross-chain is the riskiest exit (irreversible, leaves NEAR via a bridge),
            // so it is gated by its OWN type — NOT folded into `withdraw`/`intents_withdraw`.
            // A policy must explicitly list `cross_chain_withdraw` to permit it (default-DENY
            // / opt-in); allowing same-chain withdraw does NOT allow cross-chain.
            Op::CrossChainWithdraw { .. } => &["cross_chain_withdraw"],
            Op::PaymentCheck { .. } => &["payment_check"],
            Op::Swap { .. } => &["swap", "intents_swap"],
            Op::Confidential { .. } => &["confidential"],
            Op::Raw { .. } => &["raw"],
            Op::SignMessage { .. } => &["sign_message"],
            Op::Auth { .. } => &["auth"],
        }
    }

    /// Primary type string (for error messages and the multisig trigger).
    pub fn primary_type(&self) -> &'static str {
        self.type_aliases()[0]
    }

    /// Token this op moves, for per-token limit/allowed_tokens lookups. Native NEAR
    /// transfers and function calls are denominated in `"native"` (matches the
    /// deployed policy schema, where `per_transaction` is keyed by `"native"`).
    pub fn token(&self) -> &str {
        match self {
            Op::Transfer { .. } | Op::Call { .. } | Op::Delete { .. } => "native",
            Op::Withdraw { token, .. }
            | Op::IntentsTransfer { token, .. }
            | Op::Confidential { token, .. }
            | Op::CrossChainWithdraw { token, .. }
            | Op::PaymentCheck { token, .. } => token,
            Op::Swap { token_in, .. } => token_in,
            Op::Raw { .. } | Op::SignMessage { .. } | Op::Auth { .. } => "native",
        }
    }

    /// The fund-moving amount in raw units, if this op moves a measurable amount.
    /// `None` for ops that carry no amount (delete, raw, sign_message).
    pub fn amount(&self) -> Option<&str> {
        match self {
            Op::Transfer { amount, .. }
            | Op::Withdraw { amount, .. }
            | Op::IntentsTransfer { amount, .. }
            | Op::Confidential { amount, .. }
            | Op::CrossChainWithdraw { amount, .. }
            | Op::PaymentCheck { amount, .. } => Some(amount),
            Op::Call { deposit, .. } => Some(deposit),
            Op::Swap { amount_in, .. } => Some(amount_in),
            Op::Delete { .. } | Op::Raw { .. } | Op::SignMessage { .. } | Op::Auth { .. } => None,
        }
    }

    /// Destination address subject to the whitelist/blacklist, if any.
    pub fn destination(&self) -> Option<&str> {
        match self {
            Op::Transfer { to, .. }
            | Op::Withdraw { to, .. }
            | Op::IntentsTransfer { to, .. }
            | Op::CrossChainWithdraw { to, .. } => Some(to),
            Op::Call { to, .. } => Some(to),
            Op::Delete { beneficiary, .. } => Some(beneficiary),
            Op::Confidential { to, .. } => to.as_deref(),
            // PaymentCheck carries NO destination on purpose — the ephemeral escrow would
            // defeat a `to` whitelist, so it is gated by the `payment_check` capability +
            // amount limit instead (see the kind's doc).
            Op::Swap { .. }
            | Op::Raw { .. }
            | Op::SignMessage { .. }
            | Op::Auth { .. }
            | Op::PaymentCheck { .. } => None,
        }
    }

    /// Whether this op participates in the generic approval-threshold trigger — the fund-moving
    /// kinds with a WIRED approved-execution path: Built (transfer/call/delete/withdraw) AND the
    /// Trusted kinds swap/confidential/cross_chain_withdraw. For Built/HashPinned the approver
    /// signature binds to exactly what executes (constructed from the op / pinned by hash). For
    /// Trusted the approval is OWNER CONTROL: it gates WHETHER the op runs and binds its
    /// policy-checked token+amount; the coordinator supplies the off-chain artifact (e.g. the
    /// 1Click deposit address) at execution and that destination is coordinator-trusted — a
    /// documented tradeoff (we do not defend against a compromised coordinator, the access path).
    /// EXCLUDED: `payment_check` is Trusted + fund-moving but is NOT wired for approved-execution,
    /// so its creation is gated by its default-DENY capability + per-transaction amount cap
    /// instead (cap-gated, not approval-gated, even on a multisig wallet — wiring it is a future
    /// follow-up). `raw`/`sign_message`/`auth` are non-fund or domain-separated and governed by
    /// their own capability rules.
    fn triggers_generic_approval(&self) -> bool {
        matches!(
            self,
            Op::Transfer { .. }
                | Op::Call { .. }
                | Op::Delete { .. }
                | Op::Withdraw { .. }
                | Op::IntentsTransfer { .. }
                | Op::Swap { .. }
                | Op::Confidential { .. }
                | Op::CrossChainWithdraw { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// Policy schema (deserializes the deployed on-chain shape)
// ---------------------------------------------------------------------------

/// Wallet policy. Deserializes the schema actually produced by the dashboard /
/// coordinator. Unknown top-level fields (`version`, `admin_quorum`,
/// `webhook_url`, `authorized_key_hashes`) are ignored.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub frozen: bool,
    #[serde(default)]
    pub rules: Option<Rules>,
    #[serde(default)]
    pub approval: Option<Approval>,
    #[serde(default)]
    pub capabilities: Option<Capabilities>,
    /// Owner's event-delivery URL. Not a secret — the keystore surfaces ONLY this field
    /// to the coordinator (via check-policy) so it can deliver webhooks; the rest of the
    /// decrypted policy never leaves the keystore.
    #[serde(default)]
    pub webhook_url: Option<String>,
}


#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Rules {
    #[serde(default)]
    pub transaction_types: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_tokens: Option<Vec<String>>,
    /// Deployed schema names this `addresses`; the plan names it `whitelist`. Same shape.
    #[serde(default, alias = "whitelist")]
    pub addresses: Option<Addresses>,
    #[serde(default)]
    pub limits: Option<Limits>,
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
    #[serde(default)]
    pub time_restrictions: Option<TimeRestrictions>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Addresses {
    /// `"whitelist"`, `"blacklist"`, or `"none"`. Absent means `"whitelist"`.
    ///
    /// Any OTHER value refuses the operation rather than being ignored. It
    /// used to be ignored, and that made a typo — `allowlist` for `whitelist`
    /// — switch the address filter off entirely while the policy still listed
    /// the addresses it was no longer enforcing. Nothing reported it; the
    /// owner's only symptom was a payment that went through.
    ///
    /// `"none"` is how an owner asks for no filtering DELIBERATELY, which is
    /// why it is a value here and not the absence of one.
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub list: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Limits {
    /// STATELESS — enforced by the keystore.
    #[serde(default)]
    pub per_transaction: Option<BTreeMap<String, String>>,
    /// STATEFUL — coordinator only.
    #[serde(default)]
    pub daily: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub hourly: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub monthly: Option<BTreeMap<String, String>>,
    /// STATEFUL — coordinator only. Alternative location for the hourly tx-count cap
    /// (the plan's §2.3 places it here; the deployed schema uses `rate_limit.max_per_hour`).
    #[serde(default)]
    pub hourly_tx_count: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RateLimit {
    /// STATEFUL — coordinator only.
    #[serde(default)]
    pub max_per_hour: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeRestrictions {
    #[serde(default)]
    pub timezone: Option<String>,
    /// `[start_hour, end_hour]`, UTC. Wrap-around supported (e.g. `[22, 6]`).
    #[serde(default)]
    pub allowed_hours: Option<Vec<u32>>,
    /// Weekday 1=Mon .. 7=Sun.
    #[serde(default)]
    pub allowed_days: Option<Vec<u32>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Approval {
    #[serde(default)]
    pub threshold: Option<Threshold>,
    #[serde(default)]
    pub approvers: Option<Vec<Approver>>,
    /// Op types exempt from the approval trigger (e.g. quote-driven flows that
    /// expire too fast to wait for multisig).
    #[serde(default)]
    pub excluded_types: Option<Vec<String>>,
}

/// Either a bare number (plan §2.3 `"threshold": N`) or an object
/// (deployed schema `{"required": N}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Threshold {
    Number(i64),
    Object {
        #[serde(default)]
        required: Option<i64>,
    },
}

impl Threshold {
    /// Required number of approvals, defaulting to 2 when unspecified (matches the
    /// deployed default).
    pub fn required(&self) -> i64 {
        match self {
            Threshold::Number(n) => *n,
            Threshold::Object { required } => required.unwrap_or(2),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Approver {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    /// Optional pinned ed25519 pubkey (plan §2.3); the keystore otherwise verifies
    /// key ownership on-chain via RPC.
    #[serde(default)]
    pub pubkey: Option<String>,
}

/// Capabilities gating the non-Built primitives. Absent → per-capability defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub raw_sign: Option<Capability>,
    #[serde(default)]
    pub confidential: Option<Capability>,
    #[serde(default)]
    pub sign_message: Option<Capability>,
    /// Payment-check (claimable-link) capability. Default-DENY: a wallet must explicitly
    /// opt in, because a claimable link routes funds to an arbitrary holder (a `to`
    /// whitelist can't gate it). Honors `requires_approval`; pairs with a per-token amount
    /// limit.
    #[serde(default)]
    pub payment_check: Option<Capability>,
    /// Swap (1Click) capability. Default-DENY. Swap is Trusted (the coordinator supplies
    /// the quote/route/deposit-address artifact, unbound to the structured policy), so even
    /// single-sig it is full coordinator-trust of the input token's balance — opt-in only.
    /// Gating Swap ONLY via `transaction_types` left it ungated when that field was absent;
    /// this capability closes that (default-DENY regardless of transaction_types).
    #[serde(default)]
    pub swap: Option<Capability>,
    /// Cross-chain withdraw (1Click swap+bridge) capability. Default-DENY. The riskiest,
    /// irreversible exit AND Trusted — so, like `swap`, it must be default-DENY regardless of
    /// `transaction_types` (which is absent in a valid policy shape, where the type gate alone
    /// would fall through to Allow). Pairs with the `cross_chain_withdraw` transaction type +
    /// the `to` whitelist + amount limit.
    #[serde(default)]
    pub cross_chain_withdraw: Option<Capability>,
    /// EVM signing (EIP-712 typed-data / EIP-191 personal_sign / raw tx).
    /// **Default-DENY under a policy** — like every other fund-moving capability,
    /// a policy must explicitly set `allowed: true` (a wallet with NO policy is
    /// unrestricted). See [`evm_sign_decision`] for the rationale and the
    /// fund-authority caveat. The `raw_tx` sub-flag on the inner [`Capability`]
    /// (default-OFF) additionally gates raw-transaction signing.
    #[serde(default)]
    pub evm_sign: Option<Capability>,
    /// Solana signing (raw message bytes / serialized transaction message).
    /// **Default-DENY under a policy** — same model as [`Capabilities::evm_sign`]:
    /// a policy must explicitly set `allowed: true` (a wallet with NO policy is
    /// unrestricted). See [`solana_sign_decision`]. The `raw_tx` sub-flag
    /// (default-OFF) additionally gates transaction signing; the base flag
    /// covers message signing only, and the keystore rejects a "message" whose
    /// bytes parse as a valid Solana transaction message so the sub-flag can't
    /// be bypassed through the message endpoint.
    #[serde(default)]
    pub solana_sign: Option<Capability>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capability {
    #[serde(default)]
    pub allowed: Option<bool>,
    #[serde(default)]
    pub requires_approval: Option<bool>,
    /// `raw_sign` only: restrict which chains may be raw-signed. `Some(list)` → the op's
    /// chain must be in the list; absent → all chains (including `near`).
    #[serde(default)]
    pub chains: Option<Vec<String>>,
    /// `sign_message` only: the auth recipients this wallet may sign messages for. The
    /// recipient allowlist is enforced by the keystore (not this engine); the field
    /// lives here so it travels with the on-chain policy. Default-deny: absent/empty
    /// under a policy → no `sign_message` recipient is permitted.
    #[serde(default)]
    pub allowed_recipients: Option<Vec<String>>,
    /// `evm_sign` / `solana_sign` only: additionally permit signing **raw
    /// transactions** (arbitrary contract calls / native-value transfers).
    /// Default-OFF. For EVM this is a kill-switch for arbitrary raw tx only —
    /// it does NOT contain typed-data fund drains (EIP-3009
    /// `transferWithAuthorization` ≈ transfer and EIP-2612 `Permit` ≈ approve
    /// ride the base `evm_sign` capability). For Solana it gates
    /// `sign-transaction`; the message endpoint cannot smuggle a tx past it
    /// (the keystore rejects message bytes that parse as a tx message).
    #[serde(default)]
    pub raw_tx: Option<bool>,
}

// ---------------------------------------------------------------------------
// Usage (stateful state supplied by the coordinator)
// ---------------------------------------------------------------------------

/// Cumulative per-token spend + tx count, read from the coordinator DB. A token is
/// present here only if the policy configures a limit for it (no limit → not tracked).
/// All amounts are raw units.
///
/// NOTE: the engine is stateless — it compares against whatever `Usage` the caller
/// supplies. Cumulative (daily/hourly/monthly + tx-count) enforcement is therefore
/// best-effort under concurrency: simultaneous requests can read the same pre-spend
/// counter and all pass, so caps may be exceeded by an in-flight batch. The caller
/// owns serialization / safety-margins if it needs exact cumulative enforcement; the
/// stateless rules (per-tx, whitelist, time, capability, freeze, multisig trigger) are
/// always exact. See the agent-custody docs.
#[derive(Debug, Clone, Default)]
pub struct Usage {
    pub daily: BTreeMap<String, u128>,
    pub hourly: BTreeMap<String, u128>,
    pub monthly: BTreeMap<String, u128>,
    pub hourly_tx_count: i64,
}

impl Usage {
    /// Build `Usage` from the coordinator's existing `current_usage` JSON shape:
    /// `{ "daily": {tok: "amt"}, "hourly": {...}, "monthly": {...}, "hourly_tx_count": N }`.
    /// Unparseable amounts are treated as 0 (matches the legacy engine).
    pub fn from_current_usage(value: &serde_json::Value) -> Self {
        fn parse_map(v: Option<&serde_json::Value>) -> BTreeMap<String, u128> {
            v.and_then(|m| m.as_object())
                .map(|m| {
                    m.iter()
                        .map(|(k, val)| {
                            let amt = val.as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
                            (k.clone(), amt)
                        })
                        .collect()
                })
                .unwrap_or_default()
        }
        Usage {
            daily: parse_map(value.get("daily")),
            hourly: parse_map(value.get("hourly")),
            monthly: parse_map(value.get("monthly")),
            hourly_tx_count: value
                .get("hourly_tx_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Decision + evaluation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny { reason: String },
    RequiresApproval { threshold: i64 },
    Frozen,
}

/// Evaluate a policy against an op.
///
/// `usage = None` (keystore): only STATELESS clauses are enforced. `usage = Some`
/// (coordinator): full enforcement, including per-token velocity and tx-count.
/// `now_unix` is the current Unix time in seconds (used only by time_restrictions);
/// the function is otherwise pure for reproducible test vectors.
pub fn evaluate(policy: &Policy, op: &Op, usage: Option<&Usage>, now_unix: u64) -> Decision {
    // The wallet's own verdict, decided FIRST and on its own terms.
    let wallet = evaluate_section(
        policy.frozen,
        policy.rules.as_ref(),
        policy.capabilities.as_ref(),
        policy.approval.as_ref(),
        op,
        usage,
        now_unix,
    );

    wallet
}

/// Evaluate one rule set in isolation.
#[allow(clippy::too_many_arguments)]
fn evaluate_section(
    frozen: bool,
    rules: Option<&Rules>,
    capabilities: Option<&Capabilities>,
    approval: Option<&Approval>,
    op: &Op,
    usage: Option<&Usage>,
    now_unix: u64,
) -> Decision {
    // 1. Frozen wallet — reject EVERYTHING, including auth. A freeze fully halts the
    //    wallet; the controller's intent is a hard stop, so even identity proofs are
    //    refused until it is unfrozen.
    if frozen {
        return Decision::Frozen;
    }

    // 2. Auth ops are non-fund identity proofs (raw ed25519 over a domain-separated
    //    `auth:`/`register:`/`api-key:` string — never a 32-byte tx hash). On a wallet
    //    that is NOT frozen they are always allowed: no transaction_types, capability,
    //    or multisig applies (they move no funds and carry no recipient/amount).
    if matches!(op, Op::Auth { .. }) {
        return Decision::Allow;
    }

    // 2a. A limit we cannot read is not a limit we can ignore.
    //
    // `lookup_limit` parses and falls back to `None` on failure, and `None`
    // means "no cap for this token" — so `{"daily":{"native":"0.2"}}`, the
    // shape an owner reaches for first, silently disarms the wallet instead of
    // capping it at 0.2 NEAR. Nothing on the write path rejects it either:
    // the coordinator's `encrypt_policy` hands the JSON to the keystore as
    // given, and its `sign_policy` only forwards a blob for signing; neither
    // looks at a limit string.
    //
    // Checked over the WHOLE limits block rather than at each lookup, so an
    // entry for a token this call does not touch is still caught — the owner
    // hears about the typo before it matters, not on the first call that
    // happens to hit that token.
    //
    // SCOPED to ops that carry an amount, the way the address-rule check below
    // is scoped to ops that carry a destination: a rule refuses the operations
    // it applies to, and no others. `sign_message` moves nothing and reads no
    // limit; freezing it over a typo in a token cap it never consults would be
    // a refusal the owner cannot connect to anything they did.
    if op.amount().is_some() {
        if let Some(decision) = unreadable_limit(rules) {
            return decision;
        }
    }

    // 2b. `w_execute_extension` (defuse-wallet's extension door) — DECODE, then
    //     evaluate the DECODED effects. The outer fields of such a call describe
    //     nothing: `to` is the agent's own wallet-contract account, the deposit
    //     is a required 1-yocto marker, and the real recipients and amounts are
    //     nested inside `args_base64`. So the rules below would otherwise meter
    //     the marker instead of the economic action. Triggered by the METHOD
    //     NAME (part of the signed canonical op — no caller layer can relabel
    //     it), for EVERY account, bound or not: a binding flag would be an
    //     off-switch for whoever supplies flags. Anything that cannot be
    //     decoded and stated is a terminal Deny — before the multisig trigger,
    //     because an approver reading the outer fields would approve blind.
    //     On a pass, the op continues through the standard gates below (the
    //     outer `to` still faces the whitelist, the type gate, the approval
    //     trigger); mode-specific FORM rules are not here — they live in the
    //     binding profiles' admission, this engine is mode-blind.
    if let Op::Call { method, args_base64, .. } = op {
        if method == "w_execute_extension" {
            if let Some(decision) = evaluate_extension_call(rules, args_base64, usage) {
                return decision;
            }
        }
    }

    // 3. transaction_types (STATELESS). Deployed policies may list the legacy
    //    deposit-family types (`intents_deposit`/`storage_deposit`/`cross_chain_deposit`),
    //    which all collapse to `call` (plan §2c) — normalize them on the POLICY side so
    //    old policies keep matching. We do NOT alias the op the other way (that would let
    //    a generic call satisfy a deposit-only policy → coordinator-mislabel hole).
    if let Some(allowed) = rules.and_then(|r| r.transaction_types.as_ref()) {
        // sign_message is a non-fund, capability-gated signature (like auth above): the
        // fund-tx allowlist does NOT apply. It is gated by capabilities.sign_message + the
        // keystore's allowed_recipients allowlist, not transaction_types.
        let ok = matches!(op, Op::SignMessage { .. })
            || op
                .type_aliases()
                .iter()
                .any(|alias| allowed.iter().any(|t| normalize_policy_type(t) == *alias));
        if !ok {
            return deny(format!(
                "Transaction type '{}' is not allowed by policy",
                op.primary_type()
            ));
        }
    }

    // 4. allowed_tokens (STATELESS). `["*"]` means any.
    if let Some(allowed) = rules.and_then(|r| r.allowed_tokens.as_ref()) {
        // sign_message carries no fund token (op.token() == "native") — exempt it too,
        // same rationale as the transaction_types exemption above.
        let any = allowed.iter().any(|t| t == "*");
        if !any && !matches!(op, Op::SignMessage { .. }) && !allowed.iter().any(|t| t == op.token()) {
            return deny(format!("Token '{}' is not allowed by policy", op.token()));
        }
    }

    // 5. address whitelist/blacklist (STATELESS).
    if let (Some(addresses), Some(dest)) = (rules.and_then(|r| r.addresses.as_ref()), op.destination()) {
        if !dest.is_empty() {
            match addresses.mode.as_deref().unwrap_or("whitelist") {
                "whitelist" => {
                    if !addresses.list.iter().any(|a| a == dest) {
                        return deny(format!("Address '{}' is not in whitelist", dest));
                    }
                }
                "blacklist" => {
                    if addresses.list.iter().any(|a| a == dest) {
                        return deny(format!("Address '{}' is blacklisted", dest));
                    }
                }
                // `none` means what it says: the owner wrote an address block
                // and asked for no filtering from it. It is a DOCUMENTED value
                // of this field (see `Addresses::mode`) and the dashboard's own
                // default, so it gets a branch of its own rather than riding on
                // a fall-through.
                "none" => {}
                // Anything else is read at its STRICTEST, never dropped.
                // Falling through to allow meant a single typo — `allowlist`
                // for `whitelist` — silently switched the filter off entirely,
                // with the policy still listing the addresses it was no longer
                // enforcing. The owner is told which word, because the
                // alternative is a wall with no door.
                // The message says what to DO, because the owner cannot fix
                // what they cannot read: the policy is encrypted, so nothing
                // will show them the offending word except this sentence.
                other => {
                    return deny(format!(
                        "this wallet's policy is not readable: address rule mode '{other}' is \
                         not one of whitelist, blacklist, none. Nothing is signed while a rule \
                         cannot be applied — re-save the policy in the dashboard, or contact \
                         support if it was not written there"
                    ))
                }
            }
        }
    }

    // Parse the op amount once (reject a non-integer amount where one is expected).
    let amount: Option<u128> = match op.amount() {
        Some(s) => match s.parse::<u128>() {
            Ok(v) => Some(v),
            Err(_) => return deny(format!("Invalid amount '{}': must be a valid integer", s)),
        },
        None => None,
    };

    if let Some(limits) = rules.and_then(|r| r.limits.as_ref()) {
        let token = op.token();

        // 6. per_transaction cap (STATELESS).
        if let (Some(amt), Some(per_tx)) = (amount, limits.per_transaction.as_ref()) {
            if let Some(limit) = lookup_limit(per_tx, token) {
                if amt > limit {
                    return deny(format!(
                        "Per-transaction limit exceeded for {}: {} > {}",
                        token, amt, limit
                    ));
                }
            }
        }

        // 7. velocity caps (STATEFUL — only when usage is supplied).
        if let Some(usage) = usage {
            if let Some(amt) = amount {
                for (window, configured, current) in [
                    ("Daily", limits.daily.as_ref(), &usage.daily),
                    ("Hourly", limits.hourly.as_ref(), &usage.hourly),
                    ("Monthly", limits.monthly.as_ref(), &usage.monthly),
                ] {
                    if let Some(map) = configured {
                        if let Some(limit) = lookup_limit(map, token) {
                            let spent = current.get(token).copied().unwrap_or(0);
                            if spent.saturating_add(amt) > limit {
                                return deny(format!(
                                    "{} limit exceeded for {}: {} + {} > {}",
                                    window, token, spent, amt, limit
                                ));
                            }
                        }
                    }
                }
            }

            // hourly tx-count cap (STATEFUL). `limits.hourly_tx_count` (plan) or
            // `rate_limit.max_per_hour` (deployed schema) — whichever is stricter.
            let count_cap = [
                limits.hourly_tx_count,
                rules.and_then(|r| r.rate_limit.as_ref()).and_then(|rl| rl.max_per_hour),
            ]
            .into_iter()
            .flatten()
            .min();
            if let Some(max) = count_cap {
                if usage.hourly_tx_count >= max {
                    return deny(format!(
                        "Rate limit exceeded: {} this hour (max: {}). Every request that reached the \
                         chain counts, whether or not it moved anything; one moving both NEAR \
                         and a token counts twice. A request refused before it was sent — by \
                         this policy, or by a pre-flight check — costs nothing",
                        usage.hourly_tx_count, max
                    ));
                }
            }
        }
    } else if let Some(usage) = usage {
        // No `limits` block but a standalone `rate_limit` may still apply (STATEFUL).
        if let Some(max) = rules.and_then(|r| r.rate_limit.as_ref()).and_then(|rl| rl.max_per_hour) {
            if usage.hourly_tx_count >= max {
                return deny(format!(
                    "Rate limit exceeded: {} this hour (max: {}). Every request that reached the \
                         chain counts, whether or not it moved anything; one moving both NEAR \
                         and a token counts twice. A request refused before it was sent — by \
                         this policy, or by a pre-flight check — costs nothing",
                    usage.hourly_tx_count, max
                ));
            }
        }
    }

    // 8. time restrictions (STATELESS — uses `now_unix`).
    if let Some(tr) = rules.and_then(|r| r.time_restrictions.as_ref()) {
        if let Some(decision) = check_time_restrictions(tr, now_unix) {
            return decision;
        }
    }

    // 9. capabilities (STATELESS) — gate the non-Built primitives and decide whether
    // they need approval, independent of the generic threshold.
    if let Some(decision) = check_capabilities(capabilities, approval, op) {
        return decision;
    }

    // 10. generic multisig trigger (STATELESS) for fund-moving kinds.
    if op.triggers_generic_approval() {
        if let Some(approval) = approval {
            let excluded = approval
                .excluded_types
                .as_ref()
                .map(|ex| {
                    op.type_aliases()
                        .iter()
                        .any(|alias| ex.iter().any(|t| t == alias))
                })
                .unwrap_or(false);
            if !excluded {
                if let Some(threshold) = approval.threshold.as_ref() {
                    return Decision::RequiresApproval {
                        threshold: threshold.required(),
                    };
                }
            }
        }
    }

    Decision::Allow
}

fn deny(reason: String) -> Decision {
    Decision::Deny { reason }
}

/// Core evaluation of a `w_execute_extension` call: decode the nested request
/// and hold its DECODED effects against the owner's rules. `Some(decision)`
/// is terminal; `None` means every effect passed and the op continues through
/// the standard pipeline.
///
/// Mode-blind on purpose (see the guard test in `binding.rs`): everything
/// here is a rule ANY mode must enforce — account-control ops, unstatable
/// calls, the owner's address/token/limit rules over what actually moves.
/// Mode-specific FORM rules (standalone/1-yocto/refund_to) are the binding
/// profiles' admission, not this engine.
fn evaluate_extension_call(
    rules: Option<&Rules>,
    args_base64: &str,
    usage: Option<&Usage>,
) -> Option<Decision> {
    use crate::wallet_request_decode::{decode, effects, TokenAmount};
    use base64::Engine;

    let raw = match base64::engine::general_purpose::STANDARD.decode(args_base64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Some(deny(format!(
                "w_execute_extension args are not valid base64: {e}"
            )))
        }
    };
    let envelope = match decode(&raw) {
        Ok(v) => v,
        Err(e) => return Some(deny(e.to_string())),
    };
    let fx = match effects(&envelope, raw.len()) {
        Ok(v) => v,
        Err(e) => return Some(deny(e.to_string())),
    };

    // R4: internal operations are account CONTROL (AddExtension grants a
    // stranger the whole lane) — hard deny, no capability can opt in.
    if fx.has_internal {
        return Some(deny(format!(
            "w_execute_extension carries internal account-control operations ({}) — \
             this lane only spends, it never rewires the account",
            fx.internal_ops.join(", ")
        )));
    }

    // Fail closed on anything whose effects cannot be stated: a call no rule
    // could read could move value no rule counted.
    if let Some(u) = fx.unknown_fund_moving.first() {
        return Some(deny(format!(
            "promise {}: cannot state the effects of {}.{} ({})",
            u.promise_index, u.contract, u.method, u.reason
        )));
    }

    // Address rules over every account the request touches: immediate
    // receivers, refund destinations (they get failed deposits), the LOGICAL
    // recipients of token moves (R3: permitting token.near says nothing about
    // bob.near), and storage-registration beneficiaries.
    if let Some(addresses) = rules.and_then(|r| r.addresses.as_ref()) {
        // Same rule as the scalar path, and it has to be the same: the door
        // route reaches this with the SAME policy document, so a mode the two
        // read differently would leave one request's destinations filtered and
        // another's not, for reasons nobody could see.
        let allowed = |dest: &str| -> bool {
            match addresses.mode.as_deref().unwrap_or("whitelist") {
                "whitelist" => addresses.list.iter().any(|a| a == dest),
                "blacklist" => !addresses.list.iter().any(|a| a == dest),
                "none" => true,
                _ => false,
            }
        };
        let mut touched: Vec<(usize, &str, &str)> = Vec::new();
        for (i, r) in fx.receivers.iter().enumerate() {
            touched.push((i, "receiver", r));
        }
        for (promise_index, r) in &fx.refund_tos {
            touched.push((*promise_index, "refund_to", r));
        }
        for m in &fx.token_moves {
            touched.push((m.promise_index, "token recipient", &m.recipient));
        }

        for s in &fx.storage_registrations {
            if let Some(account) = &s.account {
                touched.push((s.promise_index, "storage beneficiary", account));
            }
        }
        for (promise_index, role, dest) in touched {
            if !allowed(dest) {
                return Some(deny(format!(
                    "promise {promise_index}: {role} '{dest}' is not permitted by the address rules"
                )));
            }
        }
    }

    // Token allowlist: a moved token is a token, whatever the outer op said.
    if let Some(allowed) = rules.and_then(|r| r.allowed_tokens.as_ref()) {
        if !allowed.iter().any(|t| t == "*") {
            for m in &fx.token_moves {
                if !allowed.iter().any(|t| t == &m.token) {
                    return Some(deny(format!(
                        "promise {}: token '{}' is not allowed by policy",
                        m.promise_index, m.token
                    )));
                }
            }
        }
    }

    // Per-token fungible totals across the WHOLE request (R2 aggregate:
    // splitting a payment must not split the rule that meters it).
    let mut token_totals: std::collections::BTreeMap<&str, u128> = std::collections::BTreeMap::new();
    for m in &fx.token_moves {
        if let TokenAmount::Fungible(amount) = m.amount {
            let entry = token_totals.entry(m.token.as_str()).or_insert(0);
            *entry = entry.saturating_add(amount);
        }
    }

    if let Some(limits) = rules.and_then(|r| r.limits.as_ref()) {
        // Per-transaction caps: native first, then each moved token in its
        // own units.
        if let Some(per_tx) = limits.per_transaction.as_ref() {
            if let Some(limit) = lookup_limit(per_tx, "native") {
                if fx.native_total > limit {
                    return Some(deny(format!(
                        "Per-transaction limit exceeded for native: {} > {} (decoded total)",
                        fx.native_total, limit
                    )));
                }
            }
            for (token, total) in &token_totals {
                if let Some(limit) = lookup_limit(per_tx, token) {
                    if *total > limit {
                        return Some(deny(format!(
                            "Per-transaction limit exceeded for {token}: {total} > {limit} (decoded total)"
                        )));
                    }
                }
            }
        }

        // Velocity windows (STATEFUL — coordinator supplies usage), same
        // windows the scalar path enforces, over the decoded totals.
        if let Some(usage) = usage {
            for (window, configured, current) in [
                ("Daily", limits.daily.as_ref(), &usage.daily),
                ("Hourly", limits.hourly.as_ref(), &usage.hourly),
                ("Monthly", limits.monthly.as_ref(), &usage.monthly),
            ] {
                let Some(map) = configured else { continue };
                if fx.native_total > 0 {
                    if let Some(limit) = lookup_limit(map, "native") {
                        let spent = current.get("native").copied().unwrap_or(0);
                        if spent.saturating_add(fx.native_total) > limit {
                            return Some(deny(format!(
                                "{window} limit exceeded for native: {} + {} > {} (decoded total)",
                                spent, fx.native_total, limit
                            )));
                        }
                    }
                }
                for (token, total) in &token_totals {
                    if let Some(limit) = lookup_limit(map, token) {
                        let spent = current.get(*token).copied().unwrap_or(0);
                        if spent.saturating_add(*total) > limit {
                            return Some(deny(format!(
                                "{window} limit exceeded for {token}: {spent} + {total} > {limit} (decoded total)"
                            )));
                        }
                    }
                }
            }
        }
    }

    None
}

/// Normalize a legacy policy `transaction_types` entry. The deposit family
/// (`intents_deposit`/`storage_deposit`/`cross_chain_deposit`) is non-fund-exit and
/// collapses to `call` (plan §2c); all other entries pass through unchanged.
fn normalize_policy_type(t: &str) -> &str {
    match t {
        "intents_deposit" | "storage_deposit" | "cross_chain_deposit" => "call",
        other => other,
    }
}

/// The first limit in the policy that is not a whole number of the token's
/// smallest unit, if any — reported so the owner can fix it, refused so it
/// cannot pass for "unlimited".
///
/// Same posture as the address-rule mode check above: nothing is signed while a
/// rule cannot be applied. The alternative was in production until it was
/// noticed — a decimal like `"0.2"` parsed as nothing, `lookup_limit` returned
/// `None`, and the cap that was meant to be the wallet's tightest became no cap
/// at all.
fn unreadable_limit(rules: Option<&Rules>) -> Option<Decision> {
    let limits = rules.and_then(|r| r.limits.as_ref())?;
    for (window, map) in [
        ("per_transaction", limits.per_transaction.as_ref()),
        ("daily", limits.daily.as_ref()),
        ("hourly", limits.hourly.as_ref()),
        ("monthly", limits.monthly.as_ref()),
    ] {
        let Some(map) = map else { continue };
        for (token, raw) in map {
            if raw.parse::<u128>().is_err() {
                // The offending VALUE is deliberately not quoted back. This
                // refusal reaches the caller, who may be the agent rather than
                // the owner, and gate 2a runs before the type, token,
                // capability and address gates — so someone every later gate
                // would refuse still reads a figure out of a policy that is
                // encrypted precisely so it stays inside the keystore. Naming
                // the window and the token is enough to find and fix it.
                let _ = raw;
                return Some(deny(format!(
                    "this wallet's policy is not readable: the {window} limit for {token} is not \
                     a whole number in the token's smallest unit (yoctoNEAR for native — 0.2 \
                     NEAR is '200000000000000000000000'). Nothing is signed while a rule cannot \
                     be applied — re-save the policy with an integer amount"
                )));
            }
        }
    }
    None
}

/// Token-specific limit, falling back to the `"*"` wildcard. Unparseable caps
/// cannot reach here: [`unreadable_limit`] refuses the whole request first.
fn lookup_limit(map: &BTreeMap<String, String>, token: &str) -> Option<u128> {
    map.get(token)
        .or_else(|| map.get("*"))
        .and_then(|s| s.parse::<u128>().ok())
}

fn check_time_restrictions(tr: &TimeRestrictions, now_unix: u64) -> Option<Decision> {
    // v1: only UTC. Reject other timezones rather than silently checking in the wrong one.
    let tz = tr.timezone.as_deref().unwrap_or("UTC");
    if tz != "UTC" {
        return Some(deny(format!(
            "Unsupported timezone '{}'. Only 'UTC' is supported in v1.",
            tz
        )));
    }

    let secs_in_day = now_unix % 86_400;
    let hour = (secs_in_day / 3_600) as u32;
    // Unix epoch (1970-01-01) was a Thursday (=4). 1=Mon .. 7=Sun.
    let weekday = (((now_unix / 86_400) + 3) % 7 + 1) as u32;

    if let Some(hours) = tr.allowed_hours.as_ref() {
        if hours.len() == 2 {
            let (start, end) = (hours[0], hours[1]);
            let in_range = if start <= end {
                hour >= start && hour < end
            } else {
                hour >= start || hour < end
            };
            if !in_range {
                return Some(deny(format!(
                    "Operation not allowed at this hour ({} UTC). Allowed: {}-{}",
                    hour, start, end
                )));
            }
        }
    }

    if let Some(days) = tr.allowed_days.as_ref() {
        if !days.iter().any(|d| *d == weekday) {
            return Some(deny(format!("Operation not allowed on weekday {}", weekday)));
        }
    }

    None
}

/// Capability gate. Returns `Some(Deny)` when the capability is disabled,
/// `Some(RequiresApproval)` when it demands approval, or `None` to continue.
/// Decision for an EVM signing request (sign-typed-data / sign-message /
/// raw-tx). EVM ops carry no token / amount / recipient for the engine to
/// gate, and EVM signing intentionally has no per-op multisig flow, so they
/// are NOT routed through [`evaluate`] / [`Op`]; this focused check covers the
/// only things that matter: freeze + the `evm_sign` capability (+ the `raw_tx`
/// sub-flag for raw transactions).
///
/// Defaults — **default-DENY when a policy is present**, consistent with every
/// other fund-moving capability (swap / cross_chain_withdraw / payment_check /
/// raw_sign): a wallet whose policy does NOT explicitly set
/// `capabilities.evm_sign.allowed = true` cannot EVM-sign. A wallet with **no
/// policy at all** is single-sig and unrestricted (the `None` arm below), so
/// no-policy trading agents are unaffected — which is exactly why a default-ON
/// gave nothing extra while leaving a fail-open hole for owners who DID lock
/// their wallet down. To enable EVM signing under a policy, opt in explicitly:
/// `"evm_sign": { "allowed": true }` (the dashboard writes this for you).
///
/// CAVEAT (why this must be opt-in): an EIP-712 signature is itself fund-moving
/// (EIP-3009 `transferWithAuthorization` ≈ transfer; EIP-2612 `Permit` ≈
/// approve), so `evm_sign` grants full authority over the EVM EOA's float.
/// `raw_tx` (default-OFF) is a separate kill-switch for *arbitrary raw
/// transactions*, NOT a containment boundary for typed-data drains.
///
/// The **stateless wallet-global gates** — `frozen` and `time_restrictions` —
/// apply to EVM signing exactly as they do in [`evaluate`]; the time check
/// reuses the same [`check_time_restrictions`] helper (no reimplementation).
/// `now_unix` is the current Unix time in seconds (used only by the time gate;
/// pass `0` in tests with no `time_restrictions`). Op-semantic checks
/// (amount/token/recipient limits) and STATEFUL velocity/rate-limits do NOT
/// apply: an EVM signing request carries no amount/token/recipient, and the
/// keystore neither broadcasts nor meters EVM signatures.
///
/// **No connector is in this decision**: a wallet signs with its own key,
/// always. See the note above [`request_hash`].
pub fn evm_sign_decision(policy: Option<&Policy>, want_raw_tx: bool, now_unix: u64) -> Decision {
    chain_sign_decision(policy, |c| c.evm_sign.as_ref(), "EVM", "evm_sign", want_raw_tx, now_unix)
}

/// Decision for a Solana signing request (sign-message / sign-transaction).
/// Identical model to [`evm_sign_decision`] — same defaults, same global
/// gates, same fail-closed `requires_approval`, same `raw_tx` sub-flag for
/// transaction signing — just keyed on `capabilities.solana_sign`.
///
/// CAVEAT (why this must be opt-in, mirroring `evm_sign`): a Solana signature
/// over a transaction message is itself fund-moving, so `solana_sign` +
/// `raw_tx` grants full authority over the wallet's Solana float. The base
/// flag covers message signing only; the keystore additionally rejects
/// "message" bytes that parse as a valid transaction message, so the message
/// endpoint cannot bypass the `raw_tx` sub-flag.
pub fn solana_sign_decision(policy: Option<&Policy>, want_raw_tx: bool, now_unix: u64) -> Decision {
    chain_sign_decision(
        policy,
        |c| c.solana_sign.as_ref(),
        "Solana",
        "solana_sign",
        want_raw_tx,
        now_unix,
    )
}

/// Shared body of [`evm_sign_decision`] / [`solana_sign_decision`] — one
/// implementation so the two chains can't drift on defaults or gate order.
fn chain_sign_decision(
    policy: Option<&Policy>,
    cap_field: fn(&Capabilities) -> Option<&Capability>,
    label: &str,
    cap_name: &str,
    want_raw_tx: bool,
    now_unix: u64,
) -> Decision {
    let policy = match policy {
        // No on-chain policy → single-sig wallet, unrestricted (as today).
        None => return Decision::Allow,
        Some(p) => p,
    };
    if policy.frozen {
        return Decision::Frozen;
    }
    // Owner-set time window gates chain signing too (same stateless global gate
    // as `evaluate` step 8) — reuse the shared helper, don't reimplement time math.
    if let Some(tr) = policy.rules.as_ref().and_then(|r| r.time_restrictions.as_ref()) {
        if let Some(decision) = check_time_restrictions(tr, now_unix) {
            return decision;
        }
    }
    let cap = policy.capabilities.as_ref().and_then(cap_field);

    // Base capability: DEFAULT-DENY under a policy (like raw_sign/swap/etc.).
    // A policy must explicitly set `<cap>.allowed = true` to permit signing.
    if !cap.and_then(|c| c.allowed).unwrap_or(false) {
        return deny(format!(
            "{} signing is not enabled by policy (set capabilities.{}.allowed = true)",
            label, cap_name
        ));
    }

    // Per-op approval is not wired for chain signing in v1. Fail closed rather
    // than silently ignore an owner who set `requires_approval`.
    if cap.and_then(|c| c.requires_approval).unwrap_or(false) {
        return deny(format!(
            "{}.requires_approval is not supported — per-op approval for {} signing is unavailable",
            cap_name, label
        ));
    }

    // Raw transactions need the explicit sub-flag (default-OFF).
    if want_raw_tx && !cap.and_then(|c| c.raw_tx).unwrap_or(false) {
        return deny(format!(
            "Raw {} transaction signing requires capabilities.{}.raw_tx = true",
            label, cap_name
        ));
    }

    Decision::Allow
}

fn check_capabilities(
    caps: Option<&Capabilities>,
    approval: Option<&Approval>,
    op: &Op,
) -> Option<Decision> {
    let (cap, default_allowed) = match op {
        // raw signing is powerful and opaque: default-DENY unless explicitly enabled.
        Op::Raw { .. } => (caps.and_then(|c| c.raw_sign.as_ref()), false),
        // confidential is fund-moving and Trusted: default-DENY unless explicitly enabled.
        Op::Confidential { .. } => (caps.and_then(|c| c.confidential.as_ref()), false),
        // sign_message capability defaults on; the keystore enforces the recipient allowlist.
        Op::SignMessage { .. } => (caps.and_then(|c| c.sign_message.as_ref()), true),
        // payment_check (claimable link) is a whitelist-bypass fund primitive: default-DENY.
        Op::PaymentCheck { .. } => (caps.and_then(|c| c.payment_check.as_ref()), false),
        // swap is Trusted (coordinator-supplied artifact) → default-DENY, even when
        // transaction_types is absent (which would otherwise leave it ungated).
        Op::Swap { .. } => (caps.and_then(|c| c.swap.as_ref()), false),
        // cross_chain_withdraw is Trusted AND the riskiest exit → default-DENY too, even when
        // transaction_types is absent (the type gate alone would fall through to Allow).
        Op::CrossChainWithdraw { .. } => (caps.and_then(|c| c.cross_chain_withdraw.as_ref()), false),
        _ => return None,
    };

    let allowed = cap.and_then(|c| c.allowed).unwrap_or(default_allowed);
    if !allowed {
        return Some(deny(format!(
            "Capability for '{}' is not enabled by policy",
            op.primary_type()
        )));
    }

    // raw_sign chain restriction: when `chains` is configured, the op's chain must be in it.
    if let Op::Raw { chain, .. } = op {
        if let Some(chains) = cap.and_then(|c| c.chains.as_ref()) {
            if !chains.iter().any(|c| c == chain) {
                return Some(deny(format!(
                    "Raw signing is not enabled for chain '{}' by policy",
                    chain
                )));
            }
        }
    }

    if cap.and_then(|c| c.requires_approval).unwrap_or(false) {
        // The threshold comes from the approval block; absent → fail-closed (a
        // capability that demands approval but has no approvers is a misconfiguration).
        match approval.and_then(|a| a.threshold.as_ref()) {
            Some(threshold) => {
                return Some(Decision::RequiresApproval {
                    threshold: threshold.required(),
                })
            }
            None => {
                return Some(deny(format!(
                    "Capability '{}' requires approval but no approval threshold is configured",
                    op.primary_type()
                )))
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy_from(v: serde_json::Value) -> Policy {
        serde_json::from_value(v).expect("policy parse")
    }

    /// A cap the engine cannot read must FREEZE the wallet, not free it.
    ///
    /// `lookup_limit` parses and falls back to `None`, and `None` means "no cap
    /// for this token" — so the single most likely owner typo, writing NEAR
    /// where yoctoNEAR is meant, turned the tightest limit in the policy into
    /// no limit at all. Nothing on the write path caught it either, and every
    /// test in this file wrote well-formed integers, so the suite passed over
    /// it for as long as it existed.
    #[test]
    fn a_limit_we_cannot_parse_denies_instead_of_disappearing() {
        let op = Op::Transfer { to: "a.near".into(), amount: "1".into() };

        // 0.2 NEAR, written the way a person writes it.
        let typo = policy_from(json!({
            "rules": { "limits": { "daily": { "native": "0.2" } } }
        }));
        match evaluate(&typo, &op, None, 0) {
            Decision::Deny { reason } => {
                assert!(
                    reason.contains("daily") && reason.contains("native"),
                    "the owner cannot fix what the refusal does not name: {reason}"
                );
                // And it must NOT quote the value back: this refusal reaches
                // the caller, and the policy is encrypted to keep its figures
                // inside the keystore. `0.2` appears in the message only as
                // part of the worked example, which is why this checks the
                // quoted form.
                assert!(
                    !reason.contains("'0.2'"),
                    "the refusal quotes a figure out of an encrypted policy: {reason}"
                );
            }
            d => panic!("a decimal cap must not read as 'unlimited', got {d:?}"),
        }

        // Caught even when this call could never touch the offending entry —
        // a native transfer against a malformed cap for some token.
        let other_token = policy_from(json!({
            "rules": { "limits": { "monthly": { "usdc.near": "1_000" } } }
        }));
        assert!(
            matches!(evaluate(&other_token, &op, None, 0), Decision::Deny { .. }),
            "a typo waiting in an unused entry is still a policy nobody can apply"
        );

        // The same limit written correctly still allows the transfer, so the
        // check refuses malformed input rather than limits in general.
        let ok = policy_from(json!({
            "rules": { "limits": { "daily": { "native": "200000000000000000000000" } } }
        }));
        assert_eq!(evaluate(&ok, &op, None, 0), Decision::Allow);

        // And it refuses only what it applies to. A signature moves nothing and
        // consults no cap, so a typo in one cannot be a reason to refuse it —
        // the owner would get a refusal about limits for an operation that has
        // no amount, and nothing they could act on.
        let signing = Op::SignMessage {
            message_hash: "00".repeat(32),
            recipient: "app.near".into(),
            purpose: None,
        };
        match evaluate(&typo, &signing, None, 0) {
            Decision::Deny { reason } => assert!(
                !reason.contains("0.2"),
                "sign_message was refused over a limit it never reads: {reason}"
            ),
            _ => {}
        }
    }

    #[test]
    fn evm_sign_capability_defaults_and_raw_tx_subflag() {
        use Decision::*;
        let allow = |d: &Decision| matches!(d, Allow);
        let deny = |d: &Decision| matches!(d, Deny { .. });

        // now_unix only matters when time_restrictions are set; 0 elsewhere.
        let t = 0u64;

        // No policy → single-sig, unrestricted (both typed and raw).
        assert!(allow(&evm_sign_decision(None, false, t)));
        assert!(allow(&evm_sign_decision(None, true, t)));

        // Policy that never mentions evm_sign → DEFAULT-DENY (like raw_sign/swap),
        // for both typed-data and raw-tx.
        let bare = policy_from(json!({
            "rules": { "transaction_types": ["transfer"] },
            "capabilities": { "raw_sign": { "allowed": false } }
        }));
        assert!(deny(&evm_sign_decision(Some(&bare), false, t)), "evm_sign is default-DENY under a policy");
        assert!(deny(&evm_sign_decision(Some(&bare), true, t)));

        // Explicitly enabled → typed-data allowed, but raw-tx stays OFF (sub-flag default).
        let on = policy_from(json!({ "capabilities": { "evm_sign": { "allowed": true } } }));
        assert!(allow(&evm_sign_decision(Some(&on), false, t)));
        assert!(deny(&evm_sign_decision(Some(&on), true, t)), "raw_tx is default-OFF");

        // Explicitly disabled → deny everything EVM.
        let off = policy_from(json!({ "capabilities": { "evm_sign": { "allowed": false } } }));
        assert!(deny(&evm_sign_decision(Some(&off), false, t)));
        assert!(deny(&evm_sign_decision(Some(&off), true, t)));

        // raw_tx opted in (with allowed:true) → raw-tx allowed (and typed-data too).
        let raw_ok = policy_from(json!({ "capabilities": { "evm_sign": { "allowed": true, "raw_tx": true } } }));
        assert!(allow(&evm_sign_decision(Some(&raw_ok), false, t)));
        assert!(allow(&evm_sign_decision(Some(&raw_ok), true, t)));
        // raw_tx:true WITHOUT allowed:true → still denied (base capability default-DENY).
        let raw_no_base = policy_from(json!({ "capabilities": { "evm_sign": { "raw_tx": true } } }));
        assert!(deny(&evm_sign_decision(Some(&raw_no_base), true, t)));

        // requires_approval is not wired for EVM → fail closed (capability is allowed).
        let needs_approval = policy_from(json!({
            "capabilities": { "evm_sign": { "allowed": true, "requires_approval": true } }
        }));
        assert!(deny(&evm_sign_decision(Some(&needs_approval), false, t)));

        // Frozen halts EVM signing too.
        let frozen = policy_from(json!({
            "frozen": true,
            "capabilities": { "evm_sign": { "allowed": true, "raw_tx": true } }
        }));
        assert!(matches!(evm_sign_decision(Some(&frozen), false, t), Frozen));

        // time_restrictions gate EVM signing too (same stateless gate as
        // `evaluate`): allowed_hours [9,17) UTC, with evm_sign explicitly enabled.
        // 12:00 UTC = 43200s → allowed; 20:00 UTC = 72000s → denied by the window.
        let hours = policy_from(json!({
            "rules": { "time_restrictions": { "allowed_hours": [9, 17] } },
            "capabilities": { "evm_sign": { "allowed": true } }
        }));
        assert!(allow(&evm_sign_decision(Some(&hours), false, 43_200)), "within 9-17 UTC → allow");
        assert!(deny(&evm_sign_decision(Some(&hours), false, 72_000)), "outside 9-17 UTC → deny");
        // The window also gates raw-tx when raw_tx is enabled.
        let hours_raw = policy_from(json!({
            "rules": { "time_restrictions": { "allowed_hours": [9, 17] } },
            "capabilities": { "evm_sign": { "allowed": true, "raw_tx": true } }
        }));
        assert!(deny(&evm_sign_decision(Some(&hours_raw), true, 72_000)), "raw-tx outside window → deny");
    }

    #[test]
    fn solana_sign_capability_defaults_and_raw_tx_subflag() {
        use Decision::*;
        let allow = |d: &Decision| matches!(d, Allow);
        let deny = |d: &Decision| matches!(d, Deny { .. });
        let t = 0u64;

        // No policy → single-sig, unrestricted (both message and tx).
        assert!(allow(&solana_sign_decision(None, false, t)));
        assert!(allow(&solana_sign_decision(None, true, t)));

        // Policy that never mentions solana_sign → DEFAULT-DENY (like evm_sign).
        let bare = policy_from(json!({
            "rules": { "transaction_types": ["transfer"] },
            "capabilities": { "evm_sign": { "allowed": true } }
        }));
        assert!(deny(&solana_sign_decision(Some(&bare), false, t)), "solana_sign is default-DENY under a policy");
        assert!(deny(&solana_sign_decision(Some(&bare), true, t)));

        // Explicitly enabled → messages allowed, but tx stays OFF (sub-flag default).
        let on = policy_from(json!({ "capabilities": { "solana_sign": { "allowed": true } } }));
        assert!(allow(&solana_sign_decision(Some(&on), false, t)));
        assert!(deny(&solana_sign_decision(Some(&on), true, t)), "raw_tx is default-OFF");

        // Explicitly disabled → deny everything Solana.
        let off = policy_from(json!({ "capabilities": { "solana_sign": { "allowed": false } } }));
        assert!(deny(&solana_sign_decision(Some(&off), false, t)));
        assert!(deny(&solana_sign_decision(Some(&off), true, t)));

        // raw_tx opted in (with allowed:true) → tx allowed (and messages too).
        let raw_ok = policy_from(json!({ "capabilities": { "solana_sign": { "allowed": true, "raw_tx": true } } }));
        assert!(allow(&solana_sign_decision(Some(&raw_ok), false, t)));
        assert!(allow(&solana_sign_decision(Some(&raw_ok), true, t)));
        // raw_tx:true WITHOUT allowed:true → still denied (base capability default-DENY).
        let raw_no_base = policy_from(json!({ "capabilities": { "solana_sign": { "raw_tx": true } } }));
        assert!(deny(&solana_sign_decision(Some(&raw_no_base), true, t)));

        // requires_approval is not wired for Solana → fail closed.
        let needs_approval = policy_from(json!({
            "capabilities": { "solana_sign": { "allowed": true, "requires_approval": true } }
        }));
        assert!(deny(&solana_sign_decision(Some(&needs_approval), false, t)));

        // Frozen halts Solana signing too.
        let frozen = policy_from(json!({
            "frozen": true,
            "capabilities": { "solana_sign": { "allowed": true, "raw_tx": true } }
        }));
        assert!(matches!(solana_sign_decision(Some(&frozen), false, t), Frozen));

        // time_restrictions gate Solana signing too (shared stateless gate).
        let hours = policy_from(json!({
            "rules": { "time_restrictions": { "allowed_hours": [9, 17] } },
            "capabilities": { "solana_sign": { "allowed": true, "raw_tx": true } }
        }));
        assert!(allow(&solana_sign_decision(Some(&hours), false, 43_200)), "within 9-17 UTC → allow");
        assert!(deny(&solana_sign_decision(Some(&hours), true, 72_000)), "outside 9-17 UTC → deny");

        // The two chains stay independent: evm_sign on ≠ solana_sign on.
        let evm_only = policy_from(json!({ "capabilities": { "evm_sign": { "allowed": true, "raw_tx": true } } }));
        assert!(deny(&solana_sign_decision(Some(&evm_only), false, t)));
        assert!(allow(&evm_sign_decision(Some(&evm_only), true, t)));
    }

    #[test]
    fn sign_message_exempt_from_transaction_types_and_tokens() {
        // sign_message is capability-gated (capabilities.sign_message + the keystore's
        // allowed_recipients allowlist), NOT a fund transaction — the transaction_types /
        // allowed_tokens fund-rules must NOT deny it. Regression for the masked-502 bug
        // (a policy listing only `transfer` used to deny sign_message via transaction_types).
        let policy = policy_from(json!({
            "rules": { "transaction_types": ["transfer"], "allowed_tokens": ["usdc"] },
            "capabilities": { "sign_message": { "allowed": true, "allowed_recipients": ["app.example.near"] } }
        }));
        let op = Op::SignMessage {
            message_hash: "ab".into(),
            recipient: "app.example.near".into(),
            purpose: None };
        assert!(
            matches!(evaluate(&policy, &op, None, 0), Decision::Allow),
            "sign_message must not be denied by transaction_types/allowed_tokens"
        );
    }

    /// Build a `w_execute_extension` op whose args are the given request JSON.
    fn door_op(request_json: &str) -> Op {
        use base64::Engine;
        Op::Call {
            to: "agent.tla".into(),
            method: "w_execute_extension".into(),
            args_base64: base64::engine::general_purpose::STANDARD.encode(request_json),
            gas: "100000000000000".into(),
            deposit: "1".into(),
        }
    }

    /// A policy that permits the door itself and generous native amounts —
    /// what a real bound wallet's owner would set. Every refusal in the tests
    /// below must therefore come from the DECODED effects, not the outer op.
    fn door_policy() -> Policy {
        policy_from(json!({
            "rules": {
                "transaction_types": ["call", "transfer"],
                "addresses": { "mode": "whitelist",
                               "list": ["agent.tla", "token.near", "good.near"] },
                "limits": { "per_transaction": {
                    "native": "1000000000000000000000000",
                    "token.near": "1000000"
                } }
            }
        }))
    }

    #[test]
    fn w_execute_extension_is_evaluated_by_its_decoded_effects() {
        let policy = door_policy();

        // Undecodable args are a terminal Deny — including on a multisig
        // wallet, where escalating to approval would have a human approve
        // fields that describe nothing.
        let opaque = door_op("{}");
        match evaluate(&policy, &opaque, None, 0) {
            Decision::Deny { reason } => assert!(
                reason.contains("w_execute_extension"),
                "the reason must name the method, got: {reason}"
            ),
            other => panic!("expected Deny for undecodable args, got {other:?}"),
        }
        let multisig = policy_from(json!({
            "rules": { "addresses": { "mode": "whitelist", "list": ["agent.tla"] } },
            "approval": { "threshold": { "required": 2 } }
        }));
        assert!(
            matches!(evaluate(&multisig, &opaque, None, 0), Decision::Deny { .. }),
            "must be Deny, never RequiresApproval"
        );

        // A readable request whose every effect passes the rules continues
        // through the standard pipeline (here: to the generic approval-free
        // Allow). Whitelisted recipient, in-limit amount.
        let good = door_op(
            r#"{"request":{"external":[{
                "receiver_id":"good.near",
                "actions":[{"action":"transfer","payload":{"amount":"1000"}}]}]}}"#,
        );
        assert!(matches!(evaluate(&policy, &good, None, 0), Decision::Allow));

        // Other methods on the same account keep their prior behaviour.
        let ordinary = Op::Call {
            to: "agent.tla".into(),
            method: "ft_transfer".into(),
            args_base64: "e30=".into(),
            gas: "100000000000000".into(),
            deposit: "1".into(),
        };
        assert!(matches!(evaluate(&policy, &ordinary, None, 0), Decision::Allow));
    }

    #[test]
    fn r4_internal_operations_are_denied_with_no_capability_escape() {
        // AddExtension inside an otherwise innocent request = handing the
        // whole lane to a stranger. Denied under ANY policy, terminally.
        let op = door_op(
            r#"{"request":{
                "internal":[{"op":"add_extension","payload":{"account_id":"evil.near"}}],
                "external":[{"receiver_id":"good.near",
                             "actions":[{"action":"transfer","payload":{"amount":"1"}}]}]}}"#,
        );
        // "Under ANY policy" includes the EMPTY one, and that case is the one
        // that bites: a wallet with nothing stored on chain is the state every
        // wallet is in immediately after registration, and it is where the
        // keystore used to skip evaluation entirely. If this arm is ever
        // allowed to pass, a freshly registered bound wallet can hand its
        // leased account to a stranger and no component says a word.
        for (label, policy) in [
            ("the owner's own rules", door_policy()),
            ("no policy at all", Policy::default()),
        ] {
            match evaluate(&policy, &op, None, 0) {
                Decision::Deny { reason } => {
                    assert!(reason.contains("add_extension"), "{label}: {reason}");
                    assert!(reason.contains("account-control"), "{label}: {reason}");
                }
                other => panic!("{label}: expected Deny, got {other:?}"),
            }
        }
    }

    /// The other half of what an empty policy must still refuse: effects it
    /// cannot state. A call no rule could read could move value no rule
    /// counted, and "the owner set no rules" is not consent to that.
    #[test]
    fn an_empty_policy_still_refuses_a_request_it_cannot_read() {
        let op = door_op(
            r#"{"request":{"external":[{"receiver_id":"token.near",
                 "actions":[{"action":"function_call","payload":{
                    "function_name":"ft_transfer","args":"!!not base64!!","deposit":"1"}}]}]}}"#,
        );
        match evaluate(&Policy::default(), &op, None, 0) {
            Decision::Deny { reason } => assert!(reason.contains("cannot state"), "{reason}"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    /// The change that made the two tests above possible must not have made
    /// an empty policy restrictive for anything else — it is the default state
    /// of every wallet, and a wallet that cannot transfer after registration
    /// is a worse bug than the one being fixed.
    #[test]
    fn an_empty_policy_allows_every_ordinary_op() {
        let ops = [
            Op::Transfer { to: "bob.near".into(), amount: "1".into() },
            Op::Call {
                to: "token.near".into(),
                method: "ft_transfer".into(),
                args_base64: String::new(),
                gas: "30000000000000".into(),
                deposit: "1".into(),
            },
        ];
        for op in &ops {
            assert!(
                matches!(evaluate(&Policy::default(), op, None, 0), Decision::Allow),
                "an empty policy must not restrict {op:?}"
            );
        }
    }

    #[test]
    fn r2_the_limit_applies_to_the_decoded_amount_not_the_marker() {
        // 250 NEAR hidden in the args, 1 yocto on the outside. The per-tx
        // limit (1 NEAR) must meter the 250.
        let op = door_op(
            r#"{"request":{"external":[{
                "receiver_id":"good.near",
                "actions":[{"action":"transfer","payload":{"amount":"250000000000000000000000000"}}]}]}}"#,
        );
        match evaluate(&door_policy(), &op, None, 0) {
            Decision::Deny { reason } => assert!(reason.contains("Per-transaction"), "{reason}"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn r2_sublimit_pieces_that_sum_over_the_limit_are_denied() {
        // Three transfers of 0.4 NEAR against a 1 NEAR limit: each is fine,
        // the request is not. The request is ONE atomic policy object.
        let op = door_op(
            r#"{"request":{"external":[
                {"receiver_id":"good.near","actions":[{"action":"transfer","payload":{"amount":"400000000000000000000000"}}]},
                {"receiver_id":"good.near","actions":[
                    {"action":"transfer","payload":{"amount":"400000000000000000000000"}},
                    {"action":"transfer","payload":{"amount":"400000000000000000000000"}}]}
            ]}}"#,
        );
        assert!(matches!(
            evaluate(&door_policy(), &op, None, 0),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn r3_the_logical_recipient_is_ruled_not_the_token_contract() {
        use base64::Engine;
        // token.near is whitelisted; bob.near is not. An ft_transfer TO BOB
        // via token.near must be denied — permitting the contract says
        // nothing about the destination.
        let ft = base64::engine::general_purpose::STANDARD
            .encode(r#"{"receiver_id":"bob.near","amount":"5"}"#);
        let op = door_op(&format!(
            r#"{{"request":{{"external":[{{
                "receiver_id":"token.near",
                "actions":[{{"action":"function_call","payload":{{
                    "function_name":"ft_transfer","args":"{ft}","deposit":"1"}}}}]}}]}}}}"#
        ));
        match evaluate(&door_policy(), &op, None, 0) {
            Decision::Deny { reason } => {
                assert!(reason.contains("bob.near"), "{reason}");
                assert!(reason.contains("promise 0"), "{reason}");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn a_refund_destination_faces_the_same_address_rules() {
        // A deposit on a call engineered to revert lands on refund_to; a rule
        // keyed on receivers alone would never see it.
        let op = door_op(
            r#"{"request":{"external":[{
                "receiver_id":"good.near",
                "refund_to":"evil.near",
                "actions":[{"action":"transfer","payload":{"amount":"1"}}]}]}}"#,
        );
        match evaluate(&door_policy(), &op, None, 0) {
            Decision::Deny { reason } => assert!(reason.contains("refund_to"), "{reason}"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn unstatable_calls_are_denied_fail_closed() {
        use base64::Engine;
        // ft_transfer_call's msg reaches a third contract; swap has no
        // semantics at all. Both must refuse, naming the method.
        let ftc = base64::engine::general_purpose::STANDARD
            .encode(r#"{"receiver_id":"good.near","amount":"1","msg":"x"}"#);
        for (method, args) in [("ft_transfer_call", ftc.as_str()), ("swap", "e30=")] {
            let op = door_op(&format!(
                r#"{{"request":{{"external":[{{
                    "receiver_id":"token.near",
                    "actions":[{{"action":"function_call","payload":{{
                        "function_name":"{method}","args":"{args}","deposit":"1"}}}}]}}]}}}}"#
            ));
            match evaluate(&door_policy(), &op, None, 0) {
                Decision::Deny { reason } => assert!(reason.contains(method), "{reason}"),
                other => panic!("expected Deny for {method}, got {other:?}"),
            }
        }
    }

    #[test]
    fn decoded_token_velocity_counts_against_the_windows() {
        use base64::Engine;
        // 600k token units moved with 500k already spent today against a 1M
        // daily cap → denied by the WINDOW, not the per-tx cap.
        let policy = policy_from(json!({
            "rules": {
                "limits": {
                    "per_transaction": { "token.near": "1000000" },
                    "daily": { "token.near": "1000000" }
                }
            }
        }));
        let ft = base64::engine::general_purpose::STANDARD
            .encode(r#"{"receiver_id":"good.near","amount":"600000"}"#);
        let op = door_op(&format!(
            r#"{{"request":{{"external":[{{
                "receiver_id":"token.near",
                "actions":[{{"action":"function_call","payload":{{
                    "function_name":"ft_transfer","args":"{ft}","deposit":"1"}}}}]}}]}}}}"#
        ));

        let mut daily = std::collections::BTreeMap::new();
        daily.insert("token.near".to_string(), 500_000u128);
        let usage = Usage { daily, ..Usage::default() };

        assert!(matches!(
            evaluate(&policy, &op, Some(&usage), 0),
            Decision::Deny { .. }
        ));
        // Without prior spend the same move passes the window.
        assert!(matches!(
            evaluate(&policy, &op, Some(&Usage::default()), 0),
            Decision::Allow
        ));
    }

    #[test]
    fn bind_modes_cover_all_kinds() {
        assert_eq!(
            bind_mode(&Op::Transfer { to: "a.near".into(), amount: "1".into() }),
            BindMode::Built
        );
        assert_eq!(
            bind_mode(&Op::Call {
                to: "c.near".into(),
                method: "m".into(),
                args_base64: "e30=".into(),
                gas: "30000000000000".into(),
                deposit: "0".into() }),
            BindMode::Built
        );
        assert_eq!(bind_mode(&Op::Delete { beneficiary: "a.near".into() }), BindMode::Built);
        assert_eq!(
            bind_mode(&Op::Withdraw { to: "a.near".into(), amount: "1".into(), token: "near".into() }),
            BindMode::Built
        );
        assert_eq!(
            bind_mode(&Op::Raw { chain: "ethereum".into(), payload_hash: "ab".into(), label: None }),
            BindMode::HashPinned
        );
        assert_eq!(
            bind_mode(&Op::SignMessage { message_hash: "ab".into(), recipient: "x".into(), purpose: None }),
            BindMode::HashPinned
        );
        assert_eq!(
            bind_mode(&Op::Swap {
                token_in: "a".into(),
                amount_in: "1".into(),
                token_out: "b".into(),
                min_out: "1".into() }),
            BindMode::Trusted
        );
        assert_eq!(
            bind_mode(&Op::Confidential {
                flow: "withdraw".into(),
                to: Some("a.near".into()),
                amount: "1".into(),
                token: "near".into(),
                chain: Some("near".into()),
                token_out: None,
                min_amount_out: None }),
            BindMode::Trusted
        );
        assert_eq!(
            bind_mode(&Op::CrossChainWithdraw {
                to: "0xabc".into(),
                amount: "1".into(),
                token: "nep141:usdt.tether-token.near".into(),
                chain: "ethereum".into() }),
            BindMode::Trusted
        );
    }

    #[test]
    fn jwt_auth_message_is_non_fund_and_field_ordered() {
        // Field order + empty `intents` are load-bearing: the message is signed and sent
        // verbatim to /v0/auth/authenticate, and the empty intents array is the
        // domain-separation invariant (this challenge can never move funds).
        let msg = build_jwt_auth_message("2026-06-12T00:00:00.000Z", "abc123");
        assert_eq!(
            msg,
            r#"{"deadline":"2026-06-12T00:00:00.000Z","intents":[],"signer_id":"abc123","external_app_data":{"configs":[{"type":"auth","expires_in":3153600000}]}}"#
        );
    }

    #[test]
    fn jwt_versioned_nonce_layout() {
        let salt = [0x11, 0x22, 0x33, 0x44];
        let random = [1, 2, 3, 4, 5, 6, 7];
        let nc = build_jwt_versioned_nonce(salt, 0x0A0B0C0D, 0x01020304, random);
        assert_eq!(&nc[0..4], &AUTH_NONCE_MAGIC); // magic
        assert_eq!(nc[4], 0); // reserved
        assert_eq!(&nc[5..9], &salt);
        assert_eq!(&nc[9..17], &0x0A0B0C0Du64.to_le_bytes());
        assert_eq!(&nc[17..25], &0x01020304u64.to_le_bytes());
        assert_eq!(&nc[25..32], &random);
    }

    #[test]
    fn trusted_kinds_trigger_generic_multisig_when_threshold_set() {
        // Owner control: a wallet with an approval threshold requires approval for Trusted ops
        // too (swap/confidential/cross_chain_withdraw/payment_check). The keystore signs the
        // coordinator-supplied artifact AFTER approval; approval bounds the op's token+amount,
        // while the off-chain destination stays coordinator-trusted (documented tradeoff).
        let policy: Policy = serde_json::from_str(
            r#"{"approval":{"threshold":{"required":2}},
                "capabilities":{"swap":{"allowed":true},"confidential":{"allowed":true},
                "cross_chain_withdraw":{"allowed":true},"payment_check":{"allowed":true}}}"#,
        )
        .unwrap();
        let ops = [
            Op::Swap { token_in: "a".into(), amount_in: "1".into(), token_out: "b".into(), min_out: "1".into() },
            Op::Confidential { flow: "withdraw".into(), to: Some("x".into()), amount: "1".into(), token: "near".into(), chain: Some("near".into()), token_out: None, min_amount_out: None },
            Op::CrossChainWithdraw { to: "0x".into(), amount: "1".into(), token: "nep141:usdt.tether-token.near".into(), chain: "ethereum".into() },
        ];
        for op in &ops {
            assert!(op.triggers_generic_approval(), "Trusted must trigger generic approval: {:?}", op);
            assert!(matches!(evaluate(&policy, op, None, 0), Decision::RequiresApproval { .. }), "Trusted op must require approval on a multisig wallet: {:?}", op);
        }
        // Without an approval threshold the same ops are allowed by their capability (no approval).
        let no_threshold: Policy = serde_json::from_str(
            r#"{"capabilities":{"swap":{"allowed":true},"confidential":{"allowed":true},
                "cross_chain_withdraw":{"allowed":true},"payment_check":{"allowed":true}}}"#,
        )
        .unwrap();
        for op in &ops {
            assert!(matches!(evaluate(&no_threshold, op, None, 0), Decision::Allow), "Trusted op without threshold should allow: {:?}", op);
        }
        // payment_check is Trusted + fund-moving but NOT wired for approved-execution → excluded
        // from the threshold; gated by its capability + per-tx cap (cap-gated, not approval-gated).
        let pc = Op::PaymentCheck { amount: "1".into(), token: "nep141:usdt.tether-token.near".into() };
        assert!(!pc.triggers_generic_approval());
        assert!(matches!(evaluate(&policy, &pc, None, 0), Decision::Allow));
        // Built fund-movers also trigger the threshold.
        assert!(Op::Transfer { to: "a".into(), amount: "1".into() }.triggers_generic_approval());
        assert!(Op::Withdraw { to: "a".into(), amount: "1".into(), token: "near".into() }.triggers_generic_approval());
        assert!(Op::IntentsTransfer { to: "a".into(), amount: "1".into(), token: "nep141:usdt.tether-token.near".into() }.triggers_generic_approval());
    }

    #[test]
    fn intents_transfer_is_built_whitelist_gated() {
        let op = Op::IntentsTransfer {
            to: "partner.near".into(),
            amount: "1000".into(),
            token: "nep141:usdt.tether-token.near".into() };
        // Built (keystore constructs the transfer intent → recipient can't be substituted).
        assert_eq!(bind_mode(&op), BindMode::Built);
        // Its OWN type — NOT folded into native `transfer` or `withdraw`.
        assert_eq!(op.primary_type(), "intents_transfer");
        assert_eq!(op.type_aliases(), &["intents_transfer"]);
        // Accessors expose the fund-moving fields for the whitelist + per-token limit gates.
        assert_eq!(op.token(), "nep141:usdt.tether-token.near");
        assert_eq!(op.amount(), Some("1000"));
        assert_eq!(op.destination(), Some("partner.near"));
        // No capability gate (catch-all `None`) → gated only by transaction_types + whitelist +
        // amount, exactly like Withdraw. A policy that allows `intents_transfer` to a whitelisted
        // `to` permits it; one that doesn't list the type denies it.
        let allow: Policy = serde_json::from_str(
            r#"{"rules":{"transaction_types":["intents_transfer"],"addresses":{"mode":"whitelist","list":["partner.near"]}}}"#,
        )
        .unwrap();
        assert!(matches!(evaluate(&allow, &op, None, 0), Decision::Allow));
        let bad_to = Op::IntentsTransfer { to: "evil.near".into(), amount: "1".into(), token: "nep141:usdt.tether-token.near".into() };
        assert!(matches!(evaluate(&allow, &bad_to, None, 0), Decision::Deny { .. }));
    }

    #[test]
    fn swap_is_default_deny_capability_even_without_transaction_types() {
        // The closed hole: gating Swap only via `transaction_types` left it UNGATED when
        // that field was absent. As a capability it is default-DENY regardless.
        let op = Op::Swap {
            token_in: "nep141:wrap.near".into(),
            amount_in: "1".into(),
            token_out: "nep141:usdt.tether-token.near".into(),
            min_out: "1".into() };
        // No transaction_types, no capabilities → DENY (previously this allowed).
        let bare: Policy = serde_json::from_str(r#"{"rules":{}}"#).unwrap();
        assert!(matches!(evaluate(&bare, &op, None, 0), Decision::Deny { .. }));
        // Even an entirely empty policy object → DENY.
        let empty: Policy = serde_json::from_str(r#"{}"#).unwrap();
        assert!(matches!(evaluate(&empty, &op, None, 0), Decision::Deny { .. }));
        // Capability enabled → Allow.
        let ok: Policy =
            serde_json::from_str(r#"{"capabilities":{"swap":{"allowed":true}}}"#).unwrap();
        assert!(matches!(evaluate(&ok, &op, None, 0), Decision::Allow));
    }

    #[test]
    fn payment_check_is_default_deny_capability_no_whitelist() {
        // Trusted by KIND, carries no destination (the claimable-link escrow defeats a
        // `to` whitelist), gated by the default-DENY `payment_check` capability + amount.
        let op = Op::PaymentCheck { amount: "5".into(), token: "nep141:usdt.tether-token.near".into() };
        assert_eq!(op.type_aliases(), &["payment_check"]);
        assert_eq!(op.destination(), None);
        assert_eq!(op.amount(), Some("5"));
        assert_eq!(op.token(), "nep141:usdt.tether-token.near");
        assert_eq!(bind_mode(&op), BindMode::Trusted);
        // Trusted + fund-moving, but NOT wired for approved-execution → excluded from the generic
        // threshold; gated by its default-DENY capability + per-transaction amount cap.
        assert!(!op.triggers_generic_approval());

        // Capability absent → default-DENY even if the type is allowed.
        let no_cap: Policy = serde_json::from_str(
            r#"{"rules":{"transaction_types":["payment_check"]}}"#,
        )
        .unwrap();
        assert!(matches!(evaluate(&no_cap, &op, None, 0), Decision::Deny { .. }));

        // Capability enabled + within the per-token amount limit → Allow.
        let policy: Policy = serde_json::from_str(
            r#"{"rules":{"transaction_types":["payment_check"],
                "limits":{"per_transaction":{"nep141:usdt.tether-token.near":"10"}}},
                "capabilities":{"payment_check":{"allowed":true}}}"#,
        )
        .unwrap();
        assert!(matches!(evaluate(&policy, &op, None, 0), Decision::Allow));

        // Over the amount limit → Deny.
        let over = Op::PaymentCheck { amount: "50".into(), token: "nep141:usdt.tether-token.near".into() };
        assert!(matches!(evaluate(&policy, &over, None, 0), Decision::Deny { .. }));
    }

    #[test]
    fn cross_chain_withdraw_is_default_deny_own_type() {
        // Trusted by KIND. Gated by its OWN `cross_chain_withdraw` type (NOT folded into
        // `withdraw`): an owner must explicitly opt in, since cross-chain is the riskiest,
        // irreversible exit. Within an opted-in policy the `to` whitelist + amount limit
        // still apply, at check AND sign.
        let op = Op::CrossChainWithdraw {
            to: "0xRecipient".into(),
            amount: "5".into(),
            token: "nep141:usdt.tether-token.near".into(),
            chain: "ethereum".into() };
        assert_eq!(op.type_aliases(), &["cross_chain_withdraw"]);
        assert_eq!(op.destination(), Some("0xRecipient"));
        assert_eq!(op.amount(), Some("5"));
        assert_eq!(op.token(), "nep141:usdt.tether-token.near");
        // Trusted, but participates in the generic threshold (owner control): a wallet with an
        // approval threshold requires approval; without one it resolves via its capability.
        assert!(op.triggers_generic_approval());

        // A withdraw-only policy does NOT permit cross-chain (default-DENY / opt-in).
        let withdraw_only: Policy = serde_json::from_str(
            r#"{"rules":{"transaction_types":["withdraw","intents_withdraw"],
                "addresses":{"mode":"whitelist","list":["0xRecipient"]},
                "limits":{"per_transaction":{"nep141:usdt.tether-token.near":"10"}}}}"#,
        )
        .unwrap();
        assert!(matches!(evaluate(&withdraw_only, &op, None, 0), Decision::Deny { .. }));

        // Even with the type listed, the default-DENY capability must be opted in too.
        let type_only: Policy = serde_json::from_str(
            r#"{"rules":{"transaction_types":["cross_chain_withdraw"],
                "addresses":{"mode":"whitelist","list":["0xRecipient"]},
                "limits":{"per_transaction":{"nep141:usdt.tether-token.near":"10"}}}}"#,
        )
        .unwrap();
        assert!(matches!(evaluate(&type_only, &op, None, 0), Decision::Deny { .. }));

        // Opted-in (type + capability) + whitelisted destination + within per_transaction → Allow.
        let policy: Policy = serde_json::from_str(
            r#"{"rules":{"transaction_types":["cross_chain_withdraw"],
                "addresses":{"mode":"whitelist","list":["0xRecipient"]},
                "limits":{"per_transaction":{"nep141:usdt.tether-token.near":"10"}}},
                "capabilities":{"cross_chain_withdraw":{"allowed":true}}}"#,
        )
        .unwrap();
        assert!(matches!(evaluate(&policy, &op, None, 0), Decision::Allow));

        // The closed hole: NO transaction_types (valid shape) must STILL deny (capability gate),
        // mirroring swap — not fall through to Allow on the riskiest exit.
        let bare: Policy = serde_json::from_str(r#"{"rules":{}}"#).unwrap();
        assert!(matches!(evaluate(&bare, &op, None, 0), Decision::Deny { .. }));
        let empty: Policy = serde_json::from_str(r#"{}"#).unwrap();
        assert!(matches!(evaluate(&empty, &op, None, 0), Decision::Deny { .. }));

        // Over the per_transaction cap → Deny.
        let over = Op::CrossChainWithdraw {
            to: "0xRecipient".into(),
            amount: "50".into(),
            token: "nep141:usdt.tether-token.near".into(),
            chain: "ethereum".into() };
        assert!(matches!(evaluate(&policy, &over, None, 0), Decision::Deny { .. }));

        // Destination not on the whitelist → Deny.
        let bad_to = Op::CrossChainWithdraw {
            to: "0xAttacker".into(),
            amount: "1".into(),
            token: "nep141:usdt.tether-token.near".into(),
            chain: "ethereum".into() };
        assert!(matches!(evaluate(&policy, &bad_to, None, 0), Decision::Deny { .. }));
    }

    #[test]
    fn canonical_json_sorts_keys_and_is_stable() {
        let op = Op::Transfer { to: "a.near".into(), amount: "1000".into() };
        // keys sorted: amount, kind, to
        assert_eq!(canonical_json(&op), r#"{"amount":"1000","kind":"transfer","to":"a.near"}"#);
        // hash reproduces from a JSON round-trip (different field order on the wire).
        let reparsed: Op = serde_json::from_str(r#"{"to":"a.near","amount":"1000","kind":"transfer"}"#).unwrap();
        assert_eq!(request_hash(&op), request_hash(&reparsed));
    }

    #[test]
    fn no_policy_allows() {
        let op = Op::Transfer { to: "a.near".into(), amount: "1".into() };
        assert_eq!(evaluate(&Policy::default(), &op, None, 0), Decision::Allow);
    }

    #[test]
    fn frozen_rejects() {
        let policy = policy_from(json!({ "frozen": true }));
        let op = Op::Transfer { to: "a.near".into(), amount: "1".into() };
        assert_eq!(evaluate(&policy, &op, None, 0), Decision::Frozen);
    }

    #[test]
    fn transaction_type_not_allowed() {
        let policy = policy_from(json!({ "rules": { "transaction_types": ["transfer"] } }));
        let op = Op::Delete { beneficiary: "a.near".into() };
        match evaluate(&policy, &op, None, 0) {
            Decision::Deny { .. } => {}
            d => panic!("expected deny, got {:?}", d),
        }
    }

    #[test]
    fn withdraw_matches_legacy_intents_withdraw_type() {
        let policy = policy_from(json!({ "rules": { "transaction_types": ["intents_withdraw"] } }));
        let op = Op::Withdraw { to: "a.near".into(), amount: "1".into(), token: "near".into() };
        assert_eq!(evaluate(&policy, &op, None, 0), Decision::Allow);
    }

    #[test]
    fn per_transaction_limit_stateless() {
        let policy = policy_from(json!({
            "rules": { "limits": { "per_transaction": { "native": "100" } } }
        }));
        let under = Op::Transfer { to: "a.near".into(), amount: "100".into() };
        let over = Op::Transfer { to: "a.near".into(), amount: "101".into() };
        assert_eq!(evaluate(&policy, &under, None, 0), Decision::Allow);
        match evaluate(&policy, &over, None, 0) {
            Decision::Deny { .. } => {}
            d => panic!("expected deny, got {:?}", d),
        }
    }

    #[test]
    fn daily_limit_skipped_without_usage_enforced_with_usage() {
        let policy = policy_from(json!({
            "rules": { "limits": { "daily": { "native": "100" } } }
        }));
        let op = Op::Transfer { to: "a.near".into(), amount: "60".into() };
        // keystore (usage=None): stateful clause skipped → Allow.
        assert_eq!(evaluate(&policy, &op, None, 0), Decision::Allow);
        // coordinator (usage=Some): 60 already spent + 60 > 100 → Deny.
        let mut usage = Usage::default();
        usage.daily.insert("native".into(), 60);
        match evaluate(&policy, &op, Some(&usage), 0) {
            Decision::Deny { .. } => {}
            d => panic!("expected deny, got {:?}", d),
        }
        // Under the cap → Allow.
        let mut usage2 = Usage::default();
        usage2.daily.insert("native".into(), 30);
        assert_eq!(evaluate(&policy, &op, Some(&usage2), 0), Decision::Allow);
    }

    #[test]
    fn whitelist_blocks_non_listed_destination() {
        let policy = policy_from(json!({
            "rules": { "addresses": { "mode": "whitelist", "list": ["good.near"] } }
        }));
        let bad = Op::Transfer { to: "evil.near".into(), amount: "1".into() };
        let good = Op::Transfer { to: "good.near".into(), amount: "1".into() };
        match evaluate(&policy, &bad, None, 0) {
            Decision::Deny { .. } => {}
            d => panic!("expected deny, got {:?}", d),
        }
        assert_eq!(evaluate(&policy, &good, None, 0), Decision::Allow);
    }

    /// A mode neither path recognises turns the address rule OFF, on both.
    ///
    /// This was the behaviour, and it was fail-OPEN: `"mode": "allowlist"` —
    /// a plausible spelling of the word — silently stopped filtering anything,
    /// while the policy on screen still listed the addresses it was no longer
    /// enforcing. Nothing anywhere said so, and the owner's only symptom would
    /// have been a payment that went through.
    ///
    /// Both paths are asserted because they read the SAME policy document from
    /// two different call routes, so a fix applied to one of them leaves a
    /// wallet whose filtering depends on which door a request came through.
    #[test]
    fn an_unrecognised_address_mode_refuses_on_both_paths() {
        let policy = policy_from(json!({
            "rules": { "addresses": { "mode": "allowlist", "list": ["good.near"] } }
        }));
        // Scalar path: even the address that IS listed is refused, because the
        // rule cannot be applied at all.
        for dest in ["good.near", "evil.near"] {
            let op = Op::Transfer { to: dest.into(), amount: "1".into() };
            match evaluate(&policy, &op, None, 0) {
                Decision::Deny { reason } => {
                    assert!(
                        reason.contains("allowlist"),
                        "the refusal must name the word it did not know: {reason}"
                    );
                    // And what to do about it. The policy is encrypted, so this
                    // sentence is the only thing that will ever show the owner
                    // where the problem is.
                    assert!(
                        reason.contains("dashboard"),
                        "the refusal must tell the owner how to fix it: {reason}"
                    );
                }
                d => panic!("'{dest}' under an unknown mode must be denied, got {d:?}"),
            }
        }

        // Door path: same document, same answer. The destination IS in the
        // list, so anything but a refusal here means the mode was ignored.
        let door = policy_from(json!({
            "rules": {
                "transaction_types": ["call", "transfer"],
                "addresses": { "mode": "allowlist", "list": ["good.near"] }
            }
        }));
        let op = door_op(
            r#"{"request":{"external":[{
                "receiver_id":"good.near",
                "actions":[{"action":"transfer","payload":{"amount":"1"}}]}]}}"#,
        );
        match evaluate(&door, &op, None, 0) {
            Decision::Deny { reason } => assert!(
                reason.contains("address rules"),
                "the door refusal must come from the address rule, not from something \
                 else that happens to deny this request: {reason}"
            ),
            d => panic!("the door path must refuse an unknown address mode too, got {d:?}"),
        }
    }

    /// `none` is a DOCUMENTED value, not an unknown one, and it means no
    /// filtering.
    ///
    /// It rides no fall-through: while the unknown-mode branch was the same
    /// branch `none` used, tightening one tightened the other, and a value the
    /// crate's own `Addresses::mode` documents — and the dashboard defaults to
    /// — would have started refusing every destination. Nothing could have
    /// found the affected wallets afterwards: policies are encrypted, and the
    /// write path takes `rules` as an unvalidated `serde_json::Value`.
    #[test]
    fn the_documented_none_mode_still_means_no_filtering() {
        let policy = policy_from(json!({
            "rules": { "addresses": { "mode": "none", "list": ["good.near"] } }
        }));
        // Including an address the list does NOT name: `none` is not a
        // whitelist spelled differently.
        for dest in ["good.near", "anyone.near"] {
            let op = Op::Transfer { to: dest.into(), amount: "1".into() };
            assert_eq!(
                evaluate(&policy, &op, None, 0),
                Decision::Allow,
                "'{dest}' under mode `none` must pass — the owner asked for no address filter"
            );
        }

        // Door path: same document, same answer.
        let door = policy_from(json!({
            "rules": {
                "transaction_types": ["call", "transfer"],
                "addresses": { "mode": "none", "list": ["good.near"] }
            }
        }));
        let op = door_op(
            r#"{"request":{"external":[{
                "receiver_id":"anyone.near",
                "actions":[{"action":"transfer","payload":{"amount":"1"}}]}]}}"#,
        );
        assert_eq!(
            evaluate(&door, &op, None, 0),
            Decision::Allow,
            "the door path must honour `none` too, or a bound wallet filters where a plain \
             one does not"
        );
    }

    #[test]
    fn approval_triggers_for_fund_moving() {
        let policy = policy_from(json!({ "approval": { "threshold": { "required": 2 } } }));
        let op = Op::Transfer { to: "a.near".into(), amount: "1".into() };
        assert_eq!(
            evaluate(&policy, &op, None, 0),
            Decision::RequiresApproval { threshold: 2 }
        );
    }

    #[test]
    fn approval_threshold_accepts_bare_number() {
        let policy = policy_from(json!({ "approval": { "threshold": 3 } }));
        let op = Op::Transfer { to: "a.near".into(), amount: "1".into() };
        assert_eq!(
            evaluate(&policy, &op, None, 0),
            Decision::RequiresApproval { threshold: 3 }
        );
    }

    #[test]
    fn sign_message_does_not_trigger_generic_approval() {
        let policy = policy_from(json!({ "approval": { "threshold": { "required": 2 } } }));
        let op = Op::SignMessage { message_hash: "ab".into(), recipient: "auth.app".into(), purpose: Some("auth".into()) };
        assert_eq!(evaluate(&policy, &op, None, 0), Decision::Allow);
    }

    #[test]
    fn raw_denied_by_default_allowed_when_capable() {
        let op = Op::Raw { chain: "ethereum".into(), payload_hash: "ab".into(), label: None };
        // No capabilities → raw is default-denied.
        match evaluate(&Policy::default(), &op, None, 0) {
            Decision::Deny { .. } => {}
            d => panic!("expected deny, got {:?}", d),
        }
        // Enabled → allowed.
        let policy = policy_from(json!({ "capabilities": { "raw_sign": { "allowed": true } } }));
        assert_eq!(evaluate(&policy, &op, None, 0), Decision::Allow);
        // Enabled + requires_approval with a threshold → RequiresApproval.
        let policy2 = policy_from(json!({
            "capabilities": { "raw_sign": { "allowed": true, "requires_approval": true } },
            "approval": { "threshold": { "required": 2 } }
        }));
        assert_eq!(
            evaluate(&policy2, &op, None, 0),
            Decision::RequiresApproval { threshold: 2 }
        );
    }

    #[test]
    fn raw_sign_chains_restrict_per_chain() {
        // chains = [ethereum] → ethereum allowed, near denied.
        let policy = policy_from(json!({
            "capabilities": { "raw_sign": { "allowed": true, "chains": ["ethereum"] } }
        }));
        let eth = Op::Raw { chain: "ethereum".into(), payload_hash: "ab".into(), label: None };
        let near = Op::Raw { chain: "near".into(), payload_hash: "ab".into(), label: None };
        assert_eq!(evaluate(&policy, &eth, None, 0), Decision::Allow);
        match evaluate(&policy, &near, None, 0) {
            Decision::Deny { .. } => {}
            d => panic!("expected deny for near, got {:?}", d),
        }
        // No chains key → all chains allowed (incl near).
        let policy_all = policy_from(json!({ "capabilities": { "raw_sign": { "allowed": true } } }));
        assert_eq!(evaluate(&policy_all, &near, None, 0), Decision::Allow);
    }

    #[test]
    fn auth_message_formats_match_coordinator() {
        // bearer → `auth:<seed>:<ts>` (+ optional vault).
        assert_eq!(
            build_auth_message("bearer", "default", 1_700_000_000, None).unwrap(),
            "auth:default:1700000000"
        );
        assert_eq!(
            build_auth_message("bearer", "default", 1_700_000_000, Some("v1.vault.near")).unwrap(),
            "auth:default:1700000000:v1.vault.near"
        );
        // register / api-key → `<prefix>:<seed>:<ts>`, no vault in the signed message.
        assert_eq!(
            build_auth_message("register", "s", 42, None).unwrap(),
            "register:s:42"
        );
        assert_eq!(
            build_auth_message("api-key", "s", 42, None).unwrap(),
            "api-key:s:42"
        );
        // register/api-key reject a vault_id; unknown purpose rejected.
        assert!(build_auth_message("register", "s", 42, Some("v")).is_err());
        assert!(build_auth_message("nope", "s", 42, None).is_err());
    }

    #[test]
    fn auth_allowed_under_restrictive_policy_but_blocked_when_frozen() {
        let op = Op::Auth { purpose: "bearer".into(), seed: "default".into(), vault_id: None };
        assert_eq!(bind_mode(&op), BindMode::Built);
        // Allowed under a restrictive (non-frozen) policy with no auth capability.
        let restrictive = policy_from(json!({
            "rules": { "transaction_types": ["transfer"] },
            "approval": { "threshold": { "required": 2 } }
        }));
        assert_eq!(evaluate(&restrictive, &op, None, 0), Decision::Allow);
        assert_eq!(evaluate(&Policy::default(), &op, None, 0), Decision::Allow);
        // But a freeze halts everything, including auth.
        let frozen = policy_from(json!({ "frozen": true }));
        assert_eq!(evaluate(&frozen, &op, None, 0), Decision::Frozen);
    }

    #[test]
    fn legacy_deposit_types_normalize_to_call() {
        // A deployed policy listing the legacy `intents_deposit` must still admit a
        // `call` op (deposits collapse to call).
        let policy = policy_from(json!({ "rules": { "transaction_types": ["intents_deposit"] } }));
        let call = Op::Call {
            to: "wrap.near".into(),
            method: "ft_transfer_call".into(),
            args_base64: "e30=".into(),
            gas: "30000000000000".into(),
            deposit: "1".into() };
        assert_eq!(evaluate(&policy, &call, None, 0), Decision::Allow);
        // But it must NOT admit a transfer (only the deposit family → call).
        let transfer = Op::Transfer { to: "a.near".into(), amount: "1".into() };
        match evaluate(&policy, &transfer, None, 0) {
            Decision::Deny { .. } => {}
            d => panic!("expected deny, got {:?}", d),
        }
    }

    #[test]
    fn confidential_default_denied_allowed_when_enabled() {
        let op = Op::Confidential {
            flow: "withdraw".into(),
            to: Some("a.near".into()),
            amount: "1".into(),
            token: "near".into(),
            chain: Some("near".into()),
            token_out: None,
            min_amount_out: None };
        // No capabilities → confidential is now default-denied (like raw_sign).
        match evaluate(&Policy::default(), &op, None, 0) {
            Decision::Deny { .. } => {}
            d => panic!("expected deny, got {:?}", d),
        }
        // Explicitly enabled → allowed.
        let policy = policy_from(json!({ "capabilities": { "confidential": { "allowed": true } } }));
        assert_eq!(evaluate(&policy, &op, None, 0), Decision::Allow);
    }

    #[test]
    fn confidential_swap_output_binds_into_hash_non_swap_unchanged() {
        // A non-swap confidential op with the new fields = None must hash IDENTICALLY to one
        // that omits them entirely (skip_serializing_if) → the legacy reference vectors and any
        // already-stored op_canonical reproduce. This is the "non-swap canonical unchanged"
        // invariant the FIX 2 acceptance requires.
        let legacy: Op = serde_json::from_str(
            r#"{"kind":"confidential","flow":"withdraw","to":"alice.near","amount":"5000000","token":"nep141:usdt.tether-token.near","chain":"near"}"#,
        )
        .unwrap();
        let explicit_none = Op::Confidential {
            flow: "withdraw".into(),
            to: Some("alice.near".into()),
            amount: "5000000".into(),
            token: "nep141:usdt.tether-token.near".into(),
            chain: Some("near".into()),
            token_out: None,
            min_amount_out: None };
        assert_eq!(canonical_json(&legacy), canonical_json(&explicit_none));
        assert_eq!(request_hash(&legacy), request_hash(&explicit_none));
        assert_eq!(
            request_hash(&legacy),
            "e5088673f947e97b88d2869b56ef1891f9abe550dca86764ef103718ca040795",
            "non-swap confidential hash must match the pre-change reference vector"
        );

        // A SWAP-flow confidential op that carries token_out + min_amount_out hashes
        // DIFFERENTLY → the output terms are now bound into what approvers sign.
        let swap_bound = Op::Confidential {
            flow: "swap".into(),
            to: Some("0xdeadbeef".into()),
            amount: "5000000".into(),
            token: "nep141:usdt.tether-token.near".into(),
            chain: Some("near".into()),
            token_out: Some("nep141:wrap.near".into()),
            min_amount_out: Some("4900000".into()) };
        let swap_unbound = Op::Confidential {
            flow: "swap".into(),
            to: Some("0xdeadbeef".into()),
            amount: "5000000".into(),
            token: "nep141:usdt.tether-token.near".into(),
            chain: Some("near".into()),
            token_out: None,
            min_amount_out: None };
        // Sanity: the unbound variant omits both fields from the canonical form.
        assert!(!canonical_json(&swap_unbound).contains("token_out"));
        assert!(!canonical_json(&swap_unbound).contains("min_amount_out"));
        // Binding the output changes the hash (a coordinator can no longer swap the output
        // terms after approvers signed).
        assert!(canonical_json(&swap_bound).contains("\"token_out\":\"nep141:wrap.near\""));
        assert!(canonical_json(&swap_bound).contains("\"min_amount_out\":\"4900000\""));
        assert_ne!(request_hash(&swap_bound), request_hash(&swap_unbound));
    }

    #[test]
    fn rate_limit_is_stateful() {
        let policy = policy_from(json!({ "rules": { "rate_limit": { "max_per_hour": 3 } } }));
        let op = Op::Transfer { to: "a.near".into(), amount: "1".into() };
        // keystore: skipped.
        assert_eq!(evaluate(&policy, &op, None, 0), Decision::Allow);
        // coordinator at the cap → deny.
        let usage = Usage { hourly_tx_count: 3, ..Default::default() };
        match evaluate(&policy, &op, Some(&usage), 0) {
            Decision::Deny { .. } => {}
            d => panic!("expected deny, got {:?}", d),
        }
    }

    #[test]
    fn time_restriction_rejects_outside_hours() {
        let policy = policy_from(json!({
            "rules": { "time_restrictions": { "timezone": "UTC", "allowed_hours": [9, 17] } }
        }));
        let op = Op::Transfer { to: "a.near".into(), amount: "1".into() };
        // 03:00 UTC (3 * 3600) → outside 9-17 → deny.
        match evaluate(&policy, &op, None, 3 * 3600) {
            Decision::Deny { .. } => {}
            d => panic!("expected deny, got {:?}", d),
        }
        // 10:00 UTC → allowed.
        assert_eq!(evaluate(&policy, &op, None, 10 * 3600), Decision::Allow);
    }

    #[test]
    fn invalid_amount_is_rejected() {
        let policy = policy_from(json!({
            "rules": { "limits": { "per_transaction": { "native": "100" } } }
        }));
        let op = Op::Transfer { to: "a.near".into(), amount: "not-a-number".into() };
        match evaluate(&policy, &op, None, 0) {
            Decision::Deny { .. } => {}
            d => panic!("expected deny, got {:?}", d),
        }
    }

    // ---- Reference vectors --------------------------------------------------

    #[derive(Deserialize)]
    struct Vector {
        name: String,
        op: Op,
        #[serde(default)]
        policy: Policy,
        #[serde(default)]
        current_usage: Option<serde_json::Value>,
        #[serde(default)]
        now_unix: u64,
        request_hash: String,
        bind_mode: BindMode,
        decision: Decision,
    }

    #[test]
    fn reference_vectors_match() {
        let raw = include_str!("../tests/vectors.json");
        let vectors: Vec<Vector> = serde_json::from_str(raw).expect("vectors.json parse");
        assert!(vectors.len() >= 8, "expect a vector per kind");
        for v in &vectors {
            let usage = v.current_usage.as_ref().map(Usage::from_current_usage);
            assert_eq!(request_hash(&v.op), v.request_hash, "request_hash for {}", v.name);
            assert_eq!(bind_mode(&v.op), v.bind_mode, "bind_mode for {}", v.name);
            assert_eq!(
                evaluate(&v.policy, &v.op, usage.as_ref(), v.now_unix),
                v.decision,
                "decision for {}",
                v.name
            );
        }
    }
}
