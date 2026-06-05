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
    Transfer { to: String, amount: String },

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
    PaymentCheck { amount: String, token: String },

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
        Op::Transfer { .. } | Op::Call { .. } | Op::Delete { .. } | Op::Withdraw { .. } => {
            BindMode::Built
        }
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

// ---------------------------------------------------------------------------
// Op accessors used by policy evaluation
// ---------------------------------------------------------------------------

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

    /// Whether this op participates in the generic approval-threshold trigger.
    /// Fund-moving kinds do; `raw` and `sign_message` are governed by their own
    /// capability flags (so auth challenges don't demand a multisig and raw isn't
    /// double-gated).
    fn triggers_generic_approval(&self) -> bool {
        matches!(
            self,
            Op::Transfer { .. }
                | Op::Call { .. }
                | Op::Delete { .. }
                | Op::Withdraw { .. }
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
    /// `"whitelist"`, `"blacklist"`, or `"none"`.
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
    // 1. Frozen wallet — reject EVERYTHING, including auth. A freeze fully halts the
    //    wallet; the controller's intent is a hard stop, so even identity proofs are
    //    refused until it is unfrozen.
    if policy.frozen {
        return Decision::Frozen;
    }

    // 2. Auth ops are non-fund identity proofs (raw ed25519 over a domain-separated
    //    `auth:`/`register:`/`api-key:` string — never a 32-byte tx hash). On a wallet
    //    that is NOT frozen they are always allowed: no transaction_types, capability,
    //    or multisig applies (they move no funds and carry no recipient/amount).
    if matches!(op, Op::Auth { .. }) {
        return Decision::Allow;
    }

    let rules = policy.rules.as_ref();

    // 2. transaction_types (STATELESS). Deployed policies may list the legacy
    //    deposit-family types (`intents_deposit`/`storage_deposit`/`cross_chain_deposit`),
    //    which all collapse to `call` (plan §2c) — normalize them on the POLICY side so
    //    old policies keep matching. We do NOT alias the op the other way (that would let
    //    a generic call satisfy a deposit-only policy → coordinator-mislabel hole).
    if let Some(allowed) = rules.and_then(|r| r.transaction_types.as_ref()) {
        let ok = op
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

    // 3. allowed_tokens (STATELESS). `["*"]` means any.
    if let Some(allowed) = rules.and_then(|r| r.allowed_tokens.as_ref()) {
        let any = allowed.iter().any(|t| t == "*");
        if !any && !allowed.iter().any(|t| t == op.token()) {
            return deny(format!("Token '{}' is not allowed by policy", op.token()));
        }
    }

    // 4. address whitelist/blacklist (STATELESS).
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
                _ => {}
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

        // 5. per_transaction cap (STATELESS).
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

        // 6. velocity caps (STATEFUL — only when usage is supplied).
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
                        "Rate limit exceeded: {} transactions this hour (max: {})",
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
                    "Rate limit exceeded: {} transactions this hour (max: {})",
                    usage.hourly_tx_count, max
                ));
            }
        }
    }

    // 7. time restrictions (STATELESS — uses `now_unix`).
    if let Some(tr) = rules.and_then(|r| r.time_restrictions.as_ref()) {
        if let Some(decision) = check_time_restrictions(tr, now_unix) {
            return decision;
        }
    }

    // 8. capabilities (STATELESS) — gate the non-Built primitives and decide whether
    // they need approval, independent of the generic threshold.
    if let Some(decision) = check_capabilities(policy, op) {
        return decision;
    }

    // 9. generic multisig trigger (STATELESS) for fund-moving kinds.
    if op.triggers_generic_approval() {
        if let Some(approval) = policy.approval.as_ref() {
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

/// Normalize a legacy policy `transaction_types` entry. The deposit family
/// (`intents_deposit`/`storage_deposit`/`cross_chain_deposit`) is non-fund-exit and
/// collapses to `call` (plan §2c); all other entries pass through unchanged.
fn normalize_policy_type(t: &str) -> &str {
    match t {
        "intents_deposit" | "storage_deposit" | "cross_chain_deposit" => "call",
        other => other,
    }
}

/// Token-specific limit, falling back to the `"*"` wildcard. An unparseable cap is
/// treated as no limit (`None`).
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
fn check_capabilities(policy: &Policy, op: &Op) -> Option<Decision> {
    let caps = policy.capabilities.as_ref();
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
        match policy.approval.as_ref().and_then(|a| a.threshold.as_ref()) {
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
                deposit: "0".into()
            }),
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
                min_out: "1".into()
            }),
            BindMode::Trusted
        );
        assert_eq!(
            bind_mode(&Op::Confidential {
                flow: "withdraw".into(),
                to: Some("a.near".into()),
                amount: "1".into(),
                token: "near".into(),
                chain: Some("near".into())
            }),
            BindMode::Trusted
        );
        assert_eq!(
            bind_mode(&Op::CrossChainWithdraw {
                to: "0xabc".into(),
                amount: "1".into(),
                token: "nep141:usdc.near".into(),
                chain: "ethereum".into()
            }),
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
    fn swap_is_default_deny_capability_even_without_transaction_types() {
        // The closed hole: gating Swap only via `transaction_types` left it UNGATED when
        // that field was absent. As a capability it is default-DENY regardless.
        let op = Op::Swap {
            token_in: "nep141:wrap.near".into(),
            amount_in: "1".into(),
            token_out: "nep141:usdc.near".into(),
            min_out: "1".into(),
        };
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
        let op = Op::PaymentCheck { amount: "5".into(), token: "nep141:usdc.near".into() };
        assert_eq!(op.type_aliases(), &["payment_check"]);
        assert_eq!(op.destination(), None);
        assert_eq!(op.amount(), Some("5"));
        assert_eq!(op.token(), "nep141:usdc.near");
        assert_eq!(bind_mode(&op), BindMode::Trusted);
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
                "limits":{"per_transaction":{"nep141:usdc.near":"10"}}},
                "capabilities":{"payment_check":{"allowed":true}}}"#,
        )
        .unwrap();
        assert!(matches!(evaluate(&policy, &op, None, 0), Decision::Allow));

        // Over the amount limit → Deny.
        let over = Op::PaymentCheck { amount: "50".into(), token: "nep141:usdc.near".into() };
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
            token: "nep141:usdc.near".into(),
            chain: "ethereum".into(),
        };
        assert_eq!(op.type_aliases(), &["cross_chain_withdraw"]);
        assert_eq!(op.destination(), Some("0xRecipient"));
        assert_eq!(op.amount(), Some("5"));
        assert_eq!(op.token(), "nep141:usdc.near");
        assert!(op.triggers_generic_approval());

        // A withdraw-only policy does NOT permit cross-chain (default-DENY / opt-in).
        let withdraw_only: Policy = serde_json::from_str(
            r#"{"rules":{"transaction_types":["withdraw","intents_withdraw"],
                "addresses":{"mode":"whitelist","list":["0xRecipient"]},
                "limits":{"per_transaction":{"nep141:usdc.near":"10"}}}}"#,
        )
        .unwrap();
        assert!(matches!(evaluate(&withdraw_only, &op, None, 0), Decision::Deny { .. }));

        // Opted-in + whitelisted destination + within per_transaction → Allow.
        let policy: Policy = serde_json::from_str(
            r#"{"rules":{"transaction_types":["cross_chain_withdraw"],
                "addresses":{"mode":"whitelist","list":["0xRecipient"]},
                "limits":{"per_transaction":{"nep141:usdc.near":"10"}}}}"#,
        )
        .unwrap();
        assert!(matches!(evaluate(&policy, &op, None, 0), Decision::Allow));

        // Over the per_transaction cap → Deny.
        let over = Op::CrossChainWithdraw {
            to: "0xRecipient".into(),
            amount: "50".into(),
            token: "nep141:usdc.near".into(),
            chain: "ethereum".into(),
        };
        assert!(matches!(evaluate(&policy, &over, None, 0), Decision::Deny { .. }));

        // Destination not on the whitelist → Deny.
        let bad_to = Op::CrossChainWithdraw {
            to: "0xAttacker".into(),
            amount: "1".into(),
            token: "nep141:usdc.near".into(),
            chain: "ethereum".into(),
        };
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
            deposit: "1".into(),
        };
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
        };
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
