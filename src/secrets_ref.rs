//! The shape a `secrets_ref` must have to name a row the OutLayer contract
//! could hold, and the sentence every door refuses it with.
//!
//! The contract is the authority: `store_secrets` refuses a profile that is
//! not 1–64 BYTES of letters, digits, '-' or '_' (`contract/src/secrets.rs`,
//! `profile_shape_error`), and NEAR itself refuses an account id outside its
//! own shape. A reference that fails either matches no row anywhere, so the
//! worker (before any keystore round trip) and the coordinator (at the HTTPS
//! door, before a job exists) refuse it here, naming the rule — the same
//! words at every door, one implementation for both mirrors. Bytes, not
//! characters: storage is priced by the byte and the row is keyed by the
//! bytes, so a 64-character profile of two-byte letters is not a profile.
//!
//! One deliberate asymmetry. "Letter" means `char::is_alphanumeric`, whose
//! table is the Unicode version baked into each std: the contract builds on
//! Rust 1.85 (Unicode 16.0), the worker and the keystore on 1.93 (Unicode
//! 17.0), the coordinator on whatever stable its image carries (17.0 today).
//! A letter added in Unicode 17 — `U+10940`, say — is therefore a letter to
//! every door and not to the contract. So the doors judge only what every
//! table agrees on — the byte length, and ASCII — and let any non-ASCII
//! character through to the contract's own verdict. A door must never refuse
//! a row the contract holds; a reference the contract would refuse costs one
//! "not found" instead, which is the outcome for any unknown profile.

/// The most bytes a profile name may have.
pub const PROFILE_MAX_BYTES: usize = 64;
/// The shape of a profile name, as every refusal words it.
pub const PROFILE_RULE: &str = "1–64 bytes of letters, digits, '-' or '_'";

/// Why a profile cannot name a stored row: `None` when it is well formed,
/// otherwise the half of the rule it fails, worded for the refusal
/// (`got N bytes`, `it contains '/'`). ASCII is judged here; a non-ASCII
/// character is the contract's to judge (see the module doc).
pub fn profile_shape_error(profile: &str) -> Option<String> {
    let n = profile.len();
    if !(1..=PROFILE_MAX_BYTES).contains(&n) {
        return Some(format!("got {n} bytes"));
    }
    profile
        .chars()
        .find(|c| c.is_ascii() && !(c.is_ascii_alphanumeric() || *c == '-' || *c == '_'))
        .map(|c| format!("it contains {c:?}"))
}

/// NEAR's shape for an account id: 2–64 bytes of lowercase letters, digits
/// and the separators '_', '-', '.'; a separator may not come first, last,
/// or right after another separator.
pub fn account_id_is_well_formed(account_id: &str) -> bool {
    if !(2..=64).contains(&account_id.len()) {
        return false;
    }
    let mut previous_was_separator = true; // so a leading separator is refused
    for b in account_id.bytes() {
        let separator = matches!(b, b'_' | b'-' | b'.');
        if !(separator || b.is_ascii_lowercase() || b.is_ascii_digit()) {
            return false;
        }
        if separator && previous_was_separator {
            return false;
        }
        previous_was_separator = separator;
    }
    !previous_was_separator
}

/// Which half of a reference the rule refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsRefField {
    Profile,
    AccountId,
}

/// A reference no row could match: which half failed and why. `Display`
/// calls the halves `secrets_ref.profile` / `secrets_ref.account_id`; a door
/// that calls them something else (a manifest's `author_secrets`) asks
/// [`SecretsRefError::sentence`] with its own names, so a caller-written
/// value is never rewritten by a text substitution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretsRefError {
    pub field: SecretsRefField,
    /// The parenthesised reason for a profile; the quoted, clipped id for an account.
    detail: String,
}

impl SecretsRefError {
    /// The sentence the caller sees, with the halves named as the door names them.
    pub fn sentence(&self, profile_field: &str, account_field: &str) -> String {
        match self.field {
            SecretsRefField::Profile => format!(
                "{profile_field} must be {PROFILE_RULE} ({}); the contract stores no such profile",
                self.detail
            ),
            SecretsRefField::AccountId => format!(
                "{account_field} {} is not a NEAR account id (2–64 lowercase letters, digits, '_', '-', '.'); no secret can be stored under it",
                self.detail
            ),
        }
    }
}

impl std::fmt::Display for SecretsRefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.sentence("secrets_ref.profile", "secrets_ref.account_id"))
    }
}

impl std::error::Error for SecretsRefError {}

/// The whole reference. `Err` says which half failed and why, and renders as
/// the sentence the caller sees.
pub fn well_formed_secrets_ref(profile: &str, account_id: &str) -> Result<(), SecretsRefError> {
    if let Some(why) = profile_shape_error(profile) {
        return Err(SecretsRefError { field: SecretsRefField::Profile, detail: why });
    }
    if !account_id_is_well_formed(account_id) {
        let shown: String = account_id.chars().take(80).collect();
        return Err(SecretsRefError { field: SecretsRefField::AccountId, detail: format!("{shown:?}") });
    }
    Ok(())
}

#[cfg(test)]
mod a_reference_no_row_could_match_is_refused_with_the_contracts_own_rule {
    //! The contract's own cases (`contract/src/execution.rs`,
    //! `the_door_and_the_store_agree_on_the_rule`) and a few of this door's
    //! own, with the verdict and the reason this mirror must give for each.
    use super::*;

    #[test]
    fn what_the_contract_stores_passes() {
        for ok in ["sec", "a-b_c9", "default", &"x".repeat(64), &"ж".repeat(32)] {
            assert!(well_formed_secrets_ref(ok, "alice.near").is_ok(), "{ok:?}");
        }
        for account in [&*"a".repeat(64), "ab", "a-b.c_d.near", "agt1-a366b0.zavodil.testnet", "a1.b2-c3_d4.near"] {
            assert!(well_formed_secrets_ref("p", account).is_ok(), "{account:?}");
        }
    }

    #[test]
    fn a_non_ascii_character_is_the_contracts_to_judge() {
        // Letters on every Unicode table pass; so do non-ASCII punctuation
        // and a letter the contract's older table does not know (U+10940,
        // Unicode 17) — one "not found" is the price of never refusing a row
        // the contract holds under a table this door lacks.
        for through in ["профиль", "a\u{2019}b", "\u{10940}"] {
            assert!(profile_shape_error(through).is_none(), "{through:?}");
        }
        // ASCII is judged here, on every table alike.
        assert_eq!(profile_shape_error("a'b").as_deref(), Some("it contains '\\''"));
    }

    #[test]
    fn a_profile_outside_the_length_names_its_bytes() {
        for (bad, why) in [
            ("", "got 0 bytes"),
            (&*"x".repeat(65), "got 65 bytes"),
            (&*"ж".repeat(64), "got 128 bytes"),
            (&*"p".repeat(10_240), "got 10240 bytes"),
        ] {
            let err = well_formed_secrets_ref(bad, "alice.near").expect_err(why).to_string();
            assert!(err.contains(PROFILE_RULE) && err.contains(why), "{err}");
            assert!(err.contains("the contract stores no such profile"), "{err}");
        }
    }

    #[test]
    fn a_profile_with_a_stray_character_names_it() {
        for (bad, why) in [("sec/../author", "it contains '/'"), ("a b", "it contains ' '"), ("a:b", "it contains ':'"), ("   ", "it contains ' '")] {
            let err = well_formed_secrets_ref(bad, "alice.near").expect_err(why).to_string();
            assert!(err.contains(why), "{bad:?}: {err}");
        }
    }

    #[test]
    fn a_non_account_is_refused_naming_it() {
        for bad in [
            "", "a", &*"a".repeat(65), "A.near", "ünï.near", "alice.near:prod", " alice.near",
            // separators first, last, or doubled — NEAR refuses every one
            ".alice", "alice.", "alice..near", "-alice.near", "alice-.near", "a--b.near", "a-_b", "alice._near", "a_", "_a", "a.-b",
        ] {
            let err = well_formed_secrets_ref("sec", bad).expect_err(bad).to_string();
            assert!(err.contains("is not a NEAR account id"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn the_profile_is_judged_before_the_account() {
        // One sentence per refusal: a reference wrong on both counts is told
        // about the profile, the field a caller most often mistypes.
        let err = well_formed_secrets_ref("", "").unwrap_err();
        assert_eq!(err.field, SecretsRefField::Profile);
        assert!(err.to_string().starts_with("secrets_ref.profile"), "{err}");
    }

    #[test]
    fn a_door_names_the_halves_its_own_way_without_rewriting_the_value() {
        let err = well_formed_secrets_ref("author", "secrets_ref.account_id.").unwrap_err();
        assert_eq!(err.field, SecretsRefField::AccountId);
        let s = err.sentence("author_secrets.profile", "author_secrets.owner");
        assert!(s.starts_with("author_secrets.owner \"secrets_ref.account_id.\" is not a NEAR account id"), "{s}");
        let p = well_formed_secrets_ref("", "alice.near").unwrap_err().sentence("author_secrets.profile", "author_secrets.owner");
        assert!(p.starts_with("author_secrets.profile must be"), "{p}");
    }
}
