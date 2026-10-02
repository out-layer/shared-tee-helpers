//! Whose key signed: what the chain says of a public key on an account.
//!
//! An owner's word — a vote on a multisig approval, an update of their
//! secrets, a sign-in, a confirmation, the auth of a deterministic wallet —
//! counts only when signed by a FULL-ACCESS key of the account. A function-call
//! key is held by whatever application the owner once logged into, which signs
//! with it with no wallet and no owner in the loop; it speaks for nobody.
//!
//! The key of an implicit account that does not exist yet also speaks for it:
//! the account comes into being, by any transfer to it, with exactly that key
//! as its full-access key.
//!
//! Pure readers plus one driver ([`signer_key_by`]) whose transport and error
//! type the caller supplies, so the coordinator and the keystore ask the same
//! question the same way.

use serde_json::Value;

/// What the chain says of a key on an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerKey {
    /// A full-access key of the account, or the key of an implicit account
    /// that does not exist yet.
    FullAccess,
    /// A key of the account that may only call functions.
    FunctionCall,
    /// No such key on the account, or no such account.
    Absent,
}

impl SignerKey {
    pub fn is_full_access(self) -> bool {
        self == SignerKey::FullAccess
    }
}

/// Read a `query` / `view_access_key` answer. "No such key", "no such account"
/// and a request the node cannot parse (a malformed account or key is nobody's
/// key) are answers; anything else the node says, a permission this build does
/// not know included, is no answer (`None`).
pub fn read_access_key_answer(answer: &Value) -> Option<SignerKey> {
    if let Some(error) = answer.get("error") {
        if error.get("name").and_then(|n| n.as_str()) == Some("REQUEST_VALIDATION_ERROR") {
            return Some(SignerKey::Absent);
        }
        let cause = error.get("cause").and_then(|c| c.get("name")).and_then(|n| n.as_str());
        return match cause {
            Some("UNKNOWN_ACCESS_KEY" | "UNKNOWN_ACCOUNT" | "INVALID_ACCOUNT") => Some(SignerKey::Absent),
            _ => None,
        };
    }
    let result = answer.get("result")?;
    match result.get("error").and_then(|e| e.as_str()) {
        Some(said) if said.contains("does not exist") => Some(SignerKey::Absent),
        Some(_) => None,
        None if result.get("nonce").is_some() => match result.get("permission")? {
            Value::String(full) if full == "FullAccess" => Some(SignerKey::FullAccess),
            Value::Object(limited) if limited.len() == 1 && limited.contains_key("FunctionCall") => {
                Some(SignerKey::FunctionCall)
            }
            _ => None,
        },
        None => None,
    }
}

/// Is `account` the implicit account of `public_key`: the 64 lowercase hex of
/// its 32 bytes?
pub fn is_implicit_of(account: &str, public_key: &str) -> bool {
    public_key
        .strip_prefix("ed25519:")
        .and_then(|key| bs58::decode(key).into_vec().ok())
        .is_some_and(|bytes| bytes.len() == 32 && hex::encode(bytes) == account)
}

/// Read a `query` / `view_account` answer: does the account exist? Anything
/// the node says other than the account or its absence is no answer.
pub fn read_account_exists(answer: &Value) -> Option<bool> {
    if let Some(error) = answer.get("error") {
        return match error.get("cause").and_then(|c| c.get("name")).and_then(|n| n.as_str()) {
            Some("UNKNOWN_ACCOUNT") => Some(false),
            _ => None,
        };
    }
    let result = answer.get("result")?;
    match result.get("error").and_then(|e| e.as_str()) {
        Some(said) if said.contains("does not exist") => Some(false),
        Some(_) => None,
        None if result.get("amount").is_some() => Some(true),
        None => None,
    }
}

/// What the chain says of `public_key` on `account`.
///
/// `query` sends `query` params (without a block reference — the caller adds
/// its own) and returns the whole JSON-RPC response; `unread(what)` builds the
/// caller's error for an answer that says nothing about the key.
///
/// The node says the same of a missing key and a missing account; only the
/// account's own answer tells an implicit account not made yet from one whose
/// key was taken away.
pub async fn signer_key_by<Q, F, E>(
    account: &str,
    public_key: &str,
    query: Q,
    unread: impl Fn(&str) -> E,
) -> Result<SignerKey, E>
where
    Q: Fn(Value) -> F,
    F: std::future::Future<Output = Result<Value, E>>,
{
    let answer = query(serde_json::json!({
        "request_type": "view_access_key",
        "account_id": account,
        "public_key": public_key,
    }))
    .await?;
    match read_access_key_answer(&answer).ok_or_else(|| unread("a key"))? {
        SignerKey::Absent if is_implicit_of(account, public_key) => {
            let answer = query(serde_json::json!({ "request_type": "view_account", "account_id": account })).await?;
            match read_account_exists(&answer).ok_or_else(|| unread("an account"))? {
                true => Ok(SignerKey::Absent),
                false => Ok(SignerKey::FullAccess),
            }
        }
        said => Ok(said),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Recorded answers: a full-access key, a function-call key, the embedded
    /// "does not exist" this RPC sends for a missing key or account, and a
    /// request it cannot parse (2026-10-02, testnet).
    #[test]
    fn an_answer_says_full_access_function_call_absent_or_nothing() {
        let full = json!({"result": {"nonce": 5, "permission": "FullAccess", "block_height": 1}});
        assert_eq!(read_access_key_answer(&full), Some(SignerKey::FullAccess));
        let limited = json!({"result": {"nonce": 5, "block_height": 1, "permission": {"FunctionCall": {
            "allowance": null, "receiver_id": "app.near", "method_names": []}}}});
        assert_eq!(read_access_key_answer(&limited), Some(SignerKey::FunctionCall));
        let missing = json!({"result": {"error":
            "access key ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp does not exist while viewing",
            "logs": [], "block_height": 1}});
        assert_eq!(read_access_key_answer(&missing), Some(SignerKey::Absent));
        let malformed = json!({"error": {"name": "REQUEST_VALIDATION_ERROR", "cause": {"name": "PARSE_ERROR"}}});
        assert_eq!(read_access_key_answer(&malformed), Some(SignerKey::Absent));
        for cause in ["UNKNOWN_ACCESS_KEY", "UNKNOWN_ACCOUNT", "INVALID_ACCOUNT"] {
            let r = json!({"error": {"name": "HANDLER_ERROR", "cause": {"name": cause}}});
            assert_eq!(read_access_key_answer(&r), Some(SignerKey::Absent), "{cause}");
        }

        for nothing in [
            json!({"error": {"name": "HANDLER_ERROR", "cause": {"name": "TIMEOUT_ERROR"}}}),
            json!({"result": {"error": "node is syncing"}}),
            json!({"result": {"nonce": 5, "permission": {"GasKeyFullAccess": {}}}}),
            json!({"result": {"nonce": 5}}),
            json!({"result": {}}),
            json!({}),
        ] {
            assert_eq!(read_access_key_answer(&nothing), None, "{nothing}");
        }
    }

    #[test]
    fn an_implicit_account_is_the_hex_of_its_key() {
        let key = [0xabu8; 32];
        let near = format!("ed25519:{}", bs58::encode(key).into_string());
        let account = hex::encode(key);
        assert!(is_implicit_of(&account, &near));
        assert!(!is_implicit_of(&account.to_uppercase(), &near), "an account id is lowercase");
        assert!(!is_implicit_of(&"cd".repeat(32), &near), "another key's account");
        assert!(!is_implicit_of("alice.near", &near));
        assert!(!is_implicit_of(&account, &near.replace("ed25519:", "secp256k1:")));
        assert!(!is_implicit_of(&account, "ed25519:not-base58-0OIl"));
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
    }

    #[test]
    fn the_key_of_an_implicit_account_not_made_yet_speaks_for_it_and_no_other_does() {
        let key = [3u8; 32];
        let near = format!("ed25519:{}", bs58::encode(key).into_string());
        let implicit = hex::encode(key);
        let no_key = json!({"result": {"error": "access key does not exist while viewing"}});
        let no_account = json!({"error": {"cause": {"name": "UNKNOWN_ACCOUNT"}}});
        let an_account = json!({"result": {"amount": "1"}});
        let full = json!({"result": {"nonce": 5, "permission": "FullAccess"}});

        let ask = |account: &str, key_answer: Value, account_answer: Option<Value>| {
            let asked = std::cell::RefCell::new(Vec::new());
            let verdict = block_on(signer_key_by(
                account,
                &near,
                |params: Value| {
                    let kind = params["request_type"].as_str().unwrap().to_string();
                    asked.borrow_mut().push(kind.clone());
                    std::future::ready(match kind.as_str() {
                        "view_access_key" => Ok(key_answer.clone()),
                        _ => account_answer.clone().ok_or_else(|| "asked about the account".to_string()),
                    })
                },
                |what| format!("unread {what}"),
            ));
            (verdict, asked.into_inner())
        };

        assert_eq!(ask(&implicit, no_key.clone(), Some(no_account)), (Ok(SignerKey::FullAccess), vec!["view_access_key".into(), "view_account".into()]));
        assert_eq!(ask(&implicit, no_key.clone(), Some(an_account)).0, Ok(SignerKey::Absent), "a made account whose key was taken away");
        assert_eq!(ask("alice.near", no_key, None), (Ok(SignerKey::Absent), vec!["view_access_key".into()]));
        assert_eq!(ask(&implicit, full, None), (Ok(SignerKey::FullAccess), vec!["view_access_key".into()]));
        let (verdict, _) = ask("alice.near", json!({"result": {}}), None);
        assert_eq!(verdict, Err("unread a key".to_string()));
    }
}
