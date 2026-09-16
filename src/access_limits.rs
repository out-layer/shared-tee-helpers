//! Bounds on an `AccessCondition` tree, the same at every door that stores or
//! judges one.
//!
//! A condition is owner-written and the contract prices it only by the byte,
//! so nothing else bounds what it may ask for. Two things have to be bounded
//! because the cost of either lands somewhere other than on whoever wrote it.
//!
//! The first is regular expressions: a pattern's compiled size is not its text
//! size (`\pL{200}` is 8 bytes of text and megabytes compiled), and the
//! keystore compiles every pattern of a condition before it judges a decrypt.
//! The second is chain reads: `NearBalance`, `FtBalance`, `NftOwned` and
//! `DaoMember` are
//! answered by asking the chain, one after another, so a wide condition holds
//! a shared keystore for as long as the round trips take.
//!
//! A condition past either bound is refused whole — before a pattern is
//! compiled and before the chain is asked once — and the contract refuses to
//! store one (`contract/src/secrets.rs`, the same numbers). A legitimate
//! condition names a few accounts, one or two shapes of account, and asks the
//! chain about one or two things.

/// The most `AccountPattern` leaves one condition may hold.
pub const MAX_ACCOUNT_PATTERNS: usize = 16;

/// The most leaves one condition may hold that can only be answered by ASKING
/// THE CHAIN: `NearBalance`, `FtBalance`, `NftOwned` and `DaoMember`.
///
/// Each of them is a view call from inside the enclave against a contract the
/// ROW'S OWNER chose, and they are answered one after another. Five are under
/// a second against a healthy chain; against a slow or hostile one each can
/// take as long as the read client waits, which is why the number bounds the
/// round trips and the keystore puts a DEADLINE on the evaluation as a whole
/// (`judge_access`) — the count alone bounds the multiplier, not the duration.
/// The cost lands on a shared keystore rather than on whoever wrote the
/// condition, which is why it is bounded at the door. A condition that needs
/// more than five chain reads to say who may read one secret is describing
/// something else.
pub const MAX_CHAIN_READ_LEAVES: usize = 5;
/// The most bytes of pattern text one condition may hold, all leaves together.
pub const MAX_ACCOUNT_PATTERN_BYTES: usize = 4096;
/// The most a single compiled pattern may take, in bytes — an account id is
/// at most 64 bytes, so a pattern that needs more than this to match one is
/// not a pattern for account ids.
pub const REGEX_SIZE_LIMIT: usize = 256 * 1024;

/// Whether `condition` (the contract's JSON shape) is within bounds; `Err`
/// says which bound it passed, worded for the refusal.
pub fn condition_bounds(condition: &serde_json::Value) -> Result<(), String> {
    let (leaves, bytes, chain_reads) = count(condition);
    if chain_reads > MAX_CHAIN_READ_LEAVES {
        return Err(format!(
            "it asks the chain {chain_reads} times; at most {MAX_CHAIN_READ_LEAVES} such leaves are judged"
        ));
    }
    if leaves > MAX_ACCOUNT_PATTERNS {
        return Err(format!(
            "it holds {leaves} AccountPattern leaves; at most {MAX_ACCOUNT_PATTERNS} are judged"
        ));
    }
    if bytes > MAX_ACCOUNT_PATTERN_BYTES {
        return Err(format!(
            "its AccountPattern text is {bytes} bytes in all; at most {MAX_ACCOUNT_PATTERN_BYTES} are judged"
        ));
    }
    Ok(())
}

/// `(AccountPattern leaves, bytes of pattern text)` in a condition. Shapes
/// other than the contract's are counted as nothing: a door that receives an
/// unknown shape refuses it on its own terms.
/// `(AccountPattern leaves, bytes of pattern text, leaves that ask the chain)`.
fn count(condition: &serde_json::Value) -> (usize, usize, usize) {
    let Some(object) = condition.as_object() else {
        return (0, 0, 0);
    };
    if let Some(pattern) = object.get("AccountPattern").and_then(|p| p.get("pattern")).and_then(|p| p.as_str()) {
        return (1, pattern.len(), 0);
    }
    if ["NearBalance", "FtBalance", "NftOwned", "DaoMember"].iter().any(|k| object.contains_key(*k)) {
        return (0, 0, 1);
    }
    if let Some(conditions) = object.get("Logic").and_then(|l| l.get("conditions")).and_then(|c| c.as_array()) {
        return conditions
            .iter()
            .map(count)
            .fold((0, 0, 0), |(l, b, c), (l2, b2, c2)| (l + l2, b + b2, c + c2));
    }
    if let Some(inner) = object.get("Not").and_then(|n| n.get("condition")) {
        return count(inner);
    }
    // A `Predecessor` wrapper re-judges its condition on another account;
    // every leaf inside it is compiled and asked exactly as it would be outside.
    if let Some(inner) = object.get("Predecessor").and_then(|p| p.get("condition")) {
        return count(inner);
    }
    (0, 0, 0)
}

#[cfg(test)]
mod a_condition_past_the_bounds_is_refused_whole {
    use super::*;
    use serde_json::json;

    fn pattern(text: &str) -> serde_json::Value {
        json!({ "AccountPattern": { "pattern": text } })
    }
    fn or(conditions: Vec<serde_json::Value>) -> serde_json::Value {
        json!({ "Logic": { "operator": "Or", "conditions": conditions } })
    }

    #[test]
    fn the_shapes_the_interfaces_write_are_far_inside() {
        assert!(condition_bounds(&json!("AllowAll")).is_ok());
        assert!(condition_bounds(&json!({ "Whitelist": { "accounts": ["a.near"] } })).is_ok());
        let dated = json!({ "Logic": { "operator": "And", "conditions": [
            { "Whitelist": { "accounts": ["agent.near"] } }, { "ValidUntil": { "until_ns": "1" } } ] } });
        assert!(condition_bounds(&or(vec![pattern(r".*\.agents\.near"), dated])).is_ok());
    }

    #[test]
    fn sixteen_leaves_pass_and_seventeen_do_not_wherever_they_sit() {
        let sixteen: Vec<_> = (0..16).map(|i| pattern(&format!("a{i}\\.near"))).collect();
        assert!(condition_bounds(&or(sixteen.clone())).is_ok());
        let mut seventeen = sixteen;
        seventeen.push(json!({ "Not": { "condition": pattern("b\\.near") } }));
        let err = condition_bounds(&or(seventeen)).unwrap_err();
        assert!(err.contains("17 AccountPattern leaves"), "{err}");
    }

    /// A calling-account wrapper hides nothing from the count: seventeen
    /// patterns inside one are seventeen.
    #[test]
    fn leaves_inside_a_predecessor_wrapper_are_counted() {
        let seventeen: Vec<_> = (0..17).map(|i| pattern(&format!("a{i}\\.near"))).collect();
        let wrapped = json!({ "Predecessor": { "condition": or(seventeen) } });
        let err = condition_bounds(&wrapped).unwrap_err();
        assert!(err.contains("17 AccountPattern leaves"), "{err}");
        let six_reads: Vec<_> = (0..6).map(|_| json!({ "DaoMember": { "dao_contract": "d.near", "role": "council" } })).collect();
        let err = condition_bounds(&json!({ "Predecessor": { "condition": or(six_reads) } })).unwrap_err();
        assert!(err.contains("asks the chain 6 times"), "{err}");
    }

    #[test]
    fn the_text_bound_counts_every_leaf_together() {
        let half = "a".repeat(2048);
        assert!(condition_bounds(&or(vec![pattern(&half), pattern(&half)])).is_ok());
        let err = condition_bounds(&or(vec![pattern(&half), pattern(&half), pattern("b")])).unwrap_err();
        assert!(err.contains("4097 bytes"), "{err}");
    }

    #[test]
    fn an_unknown_shape_counts_as_nothing() {
        assert!(condition_bounds(&json!({ "SomethingNewer": { "x": 1 } })).is_ok());
        assert!(condition_bounds(&json!(null)).is_ok());
    }

    fn chain_read() -> serde_json::Value {
        json!({ "NearBalance": { "operator": "Gte", "value": "1" } })
    }

    #[test]
    fn five_chain_reads_are_judged_and_a_sixth_is_not() {
        let five: Vec<_> = (0..5).map(|_| chain_read()).collect();
        assert!(condition_bounds(&or(five)).is_ok());
        let six: Vec<_> = (0..6).map(|_| chain_read()).collect();
        let err = condition_bounds(&or(six)).unwrap_err();
        assert!(err.contains("asks the chain 6 times"), "{err}");
    }

    #[test]
    fn every_kind_of_chain_read_counts_wherever_it_sits() {
        let nested = json!({ "Not": { "condition": {
            "Logic": { "operator": "And", "conditions": [
                { "FtBalance": { "contract": "ft.near", "operator": "Gte", "value": "1" } },
                { "DaoMember": { "dao_contract": "dao.near", "role": "council" } },
                { "NearBalance": { "operator": "Gte", "value": "1" } },
                { "NftOwned": { "contract": "nft.near", "token_id": "2" } },
                { "DaoMember": { "dao_contract": "dao.near", "role": "member" } },
                { "NearBalance": { "operator": "Gte", "value": "2" } }
            ] }
        } } });
        let err = condition_bounds(&nested).unwrap_err();
        assert!(err.contains("asks the chain 6 times"), "{err}");
    }

    /// Two things at once, and the second is the one with teeth: a whitelist is
    /// answered from the condition itself, so neither its SIZE nor the NUMBER
    /// of whitelist leaves may count against a bound. Six of them would be
    /// refused if `Whitelist` ever joined the chain-read set.
    #[test]
    fn a_whitelist_asks_the_chain_nothing_however_many_there_are() {
        let many: Vec<String> = (0..2000).map(|i| format!("a{i}.near")).collect();
        assert!(condition_bounds(&json!({ "Whitelist": { "accounts": many } })).is_ok());

        let six: Vec<serde_json::Value> = (0..6)
            .map(|i| json!({ "Whitelist": { "accounts": [format!("a{i}.near")] } }))
            .collect();
        assert!(condition_bounds(&or(six)).is_ok(), "a whitelist leaf is not a chain read");

        // And the shapes that are free for the same reason.
        assert!(condition_bounds(&or(vec![
            json!("AllowAll"),
            json!({ "ValidUntil": { "until_ns": "1" } }),
            json!({ "ValidUntil": { "until_ns": "2" } }),
            json!({ "ValidUntil": { "until_ns": "3" } }),
            json!({ "ValidUntil": { "until_ns": "4" } }),
            json!({ "ValidUntil": { "until_ns": "5" } }),
            json!({ "ValidUntil": { "until_ns": "6" } }),
        ]))
        .is_ok());
    }

}
