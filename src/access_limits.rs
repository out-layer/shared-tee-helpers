//! Bounds on an `AccessCondition` tree, the same at every door that stores or
//! judges one.
//!
//! A condition is owner-written and the contract prices it only by the byte,
//! so nothing else bounds how many `AccountPattern` leaves it holds or how
//! long each is — and a regular expression's compiled size is not its text
//! size (`\pL{200}` is 8 bytes of text and megabytes compiled). The keystore
//! compiles every pattern of a condition before it judges a decrypt, so a
//! condition past these bounds is refused whole, before a single pattern is
//! compiled; the contract refuses to store one (`contract/src/secrets.rs`,
//! the same numbers). A legitimate condition names a few accounts or one or
//! two shapes of account; sixteen patterns and four kibibytes of pattern text
//! are far past that.

/// The most `AccountPattern` leaves one condition may hold.
pub const MAX_ACCOUNT_PATTERNS: usize = 16;
/// The most bytes of pattern text one condition may hold, all leaves together.
pub const MAX_ACCOUNT_PATTERN_BYTES: usize = 4096;
/// The most a single compiled pattern may take, in bytes — an account id is
/// at most 64 bytes, so a pattern that needs more than this to match one is
/// not a pattern for account ids.
pub const REGEX_SIZE_LIMIT: usize = 256 * 1024;

/// Whether `condition` (the contract's JSON shape) is within bounds; `Err`
/// says which bound it passed, worded for the refusal.
pub fn account_pattern_bounds(condition: &serde_json::Value) -> Result<(), String> {
    let (leaves, bytes) = count(condition);
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
fn count(condition: &serde_json::Value) -> (usize, usize) {
    let Some(object) = condition.as_object() else {
        return (0, 0);
    };
    if let Some(pattern) = object.get("AccountPattern").and_then(|p| p.get("pattern")).and_then(|p| p.as_str()) {
        return (1, pattern.len());
    }
    if let Some(conditions) = object.get("Logic").and_then(|l| l.get("conditions")).and_then(|c| c.as_array()) {
        return conditions.iter().map(count).fold((0, 0), |(l, b), (l2, b2)| (l + l2, b + b2));
    }
    if let Some(inner) = object.get("Not").and_then(|n| n.get("condition")) {
        return count(inner);
    }
    (0, 0)
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
        assert!(account_pattern_bounds(&json!("AllowAll")).is_ok());
        assert!(account_pattern_bounds(&json!({ "Whitelist": { "accounts": ["a.near"] } })).is_ok());
        let dated = json!({ "Logic": { "operator": "And", "conditions": [
            { "Whitelist": { "accounts": ["agent.near"] } }, { "ValidUntil": { "until_ns": "1" } } ] } });
        assert!(account_pattern_bounds(&or(vec![pattern(r".*\.agents\.near"), dated])).is_ok());
    }

    #[test]
    fn sixteen_leaves_pass_and_seventeen_do_not_wherever_they_sit() {
        let sixteen: Vec<_> = (0..16).map(|i| pattern(&format!("a{i}\\.near"))).collect();
        assert!(account_pattern_bounds(&or(sixteen.clone())).is_ok());
        let mut seventeen = sixteen;
        seventeen.push(json!({ "Not": { "condition": pattern("b\\.near") } }));
        let err = account_pattern_bounds(&or(seventeen)).unwrap_err();
        assert!(err.contains("17 AccountPattern leaves"), "{err}");
    }

    #[test]
    fn the_text_bound_counts_every_leaf_together() {
        let half = "a".repeat(2048);
        assert!(account_pattern_bounds(&or(vec![pattern(&half), pattern(&half)])).is_ok());
        let err = account_pattern_bounds(&or(vec![pattern(&half), pattern(&half), pattern("b")])).unwrap_err();
        assert!(err.contains("4097 bytes"), "{err}");
    }

    #[test]
    fn an_unknown_shape_counts_as_nothing() {
        assert!(account_pattern_bounds(&json!({ "SomethingNewer": { "x": 1 } })).is_ok());
        assert!(account_pattern_bounds(&json!(null)).is_ok());
    }
}
