//! Reading the hash of the code a NEAR account runs, as `view_account`
//! reports it.

/// Decode a chain-reported base58 code hash (`view_account.code_hash`) into
/// raw bytes. `None` when it is not a 32-byte base58 string.
pub fn parse_code_hash_base58(s: &str) -> Option<[u8; 32]> {
    let bytes = bs58::decode(s).into_vec().ok()?;
    bytes.try_into().ok()
}

/// The base58 all-zeros sentinel `view_account.code_hash` reports for an
/// account that stores no code of its own.
pub const NO_CODE_HASH_B58: &str = "11111111111111111111111111111111";

/// Which hash identifies the code an account RUNS.
///
/// NEP-591 split the answer in two: an inline `DeployContract` puts the wasm
/// hash in `code_hash`, but `UseGlobalContract` leaves `code_hash` at the
/// all-zeros sentinel and reports the referenced hash in
/// `global_contract_hash`. A reader of `code_hash` alone would see no code on
/// every account that references a global contract by hash.
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

#[cfg(test)]
mod tests {
    use super::*;

    const SOME_HASH_B58: &str = "BwjDnyemmBhrCyuviDGpoQAm9mdjTfrX7ZjqgZB4MHvM";

    #[test]
    fn the_effective_code_hash_covers_both_install_paths() {
        // Inline deploy: code_hash carries the truth.
        assert_eq!(
            effective_code_hash_b58(Some(SOME_HASH_B58), None),
            Some(SOME_HASH_B58.to_string())
        );
        // Global reference: the sentinel defers to global_contract_hash.
        assert_eq!(
            effective_code_hash_b58(Some(NO_CODE_HASH_B58), Some(SOME_HASH_B58)),
            Some(SOME_HASH_B58.to_string())
        );
        // No code at all.
        assert_eq!(effective_code_hash_b58(Some(NO_CODE_HASH_B58), None), None);
        // Inline code wins over a simultaneous global field: the account
        // runs its inline code.
        assert_eq!(
            effective_code_hash_b58(Some(SOME_HASH_B58), Some(NO_CODE_HASH_B58)),
            Some(SOME_HASH_B58.to_string())
        );
    }

    #[test]
    fn a_code_hash_is_thirty_two_bytes_of_base58() {
        assert!(parse_code_hash_base58(SOME_HASH_B58).is_some());
        assert_eq!(parse_code_hash_base58(NO_CODE_HASH_B58), Some([0u8; 32]));
        assert!(parse_code_hash_base58("not base58 0OIl").is_none());
        assert!(parse_code_hash_base58("1111").is_none());
    }
}
