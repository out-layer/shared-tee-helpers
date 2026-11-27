//! Whether an account is a wallet contract the TEE signs for.
//!
//! One rule, checked on what the chain says about the account at the moment
//! of the request. Everything else about the account (its own access keys,
//! its balance) is the owner's and is not looked at.

use std::fmt;

use crate::halves::PublicKeyPair;

/// What the chain says about an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The hash of the account's code: its own, or its global contract's.
    pub code_hash: [u8; 32],
    /// `w_public_key()`.
    pub public_key: String,
    /// `w_extensions()`.
    pub extensions: Vec<String>,
    /// `w_is_signature_allowed()`.
    pub signature_allowed: bool,
}

/// An account that passed [`admit`], with the pair of keys in its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    pub pair: PublicKeyPair,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// The account does not run the published build of the two-key standard.
    CodeHash,
    /// The contract has an extension: an account with full control of it.
    Extension(String),
    /// The contract does not accept signatures.
    SignatureDisabled,
    /// `w_public_key()` is not a pair of keys.
    PublicKey,
    /// The pair's TEE key is not this wallet's.
    TeeKey,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CodeHash => f.write_str(
                "the account does not run the published build of the two-key wallet contract",
            ),
            Self::Extension(account) => write!(
                f,
                "the wallet contract has an extension, `{account}`, which has full control of it"
            ),
            Self::SignatureDisabled => f.write_str("the wallet contract does not accept signatures"),
            Self::PublicKey => f.write_str("the wallet contract's public key is not a pair of keys"),
            Self::TeeKey => f.write_str(
                "the wallet contract was not set up for this wallet: its TEE key is another wallet's",
            ),
        }
    }
}

/// Admit an account as the wallet contract of the wallet whose TEE key is
/// `tee`: it runs the build `code_hash`, has no extension, accepts
/// signatures, and holds a pair whose TEE key is `tee`.
///
/// The second line behind the request's shape (`message`): the TEE signs
/// nothing that adds an extension, and a wallet contract that has one anyway
/// is not served, since the extension can move its funds past both
/// signatures. Every one of these four checks stays.
pub fn admit(code_hash: &[u8; 32], tee: &[u8; 32], observed: &Observed) -> Result<Admitted, Fault> {
    if &observed.code_hash != code_hash {
        return Err(Fault::CodeHash);
    }
    if let Some(extension) = observed.extensions.first() {
        return Err(Fault::Extension(extension.clone()));
    }
    if !observed.signature_allowed {
        return Err(Fault::SignatureDisabled);
    }
    let pair = PublicKeyPair::parse(&observed.public_key).ok_or(Fault::PublicKey)?;
    if &pair.tee != tee {
        return Err(Fault::TeeKey);
    }
    Ok(Admitted { pair })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    const CODE_HASH: [u8; 32] = [0xc0; 32];

    fn pair() -> PublicKeyPair {
        PublicKeyPair {
            agent: SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
            tee: SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes(),
        }
    }

    fn observed() -> Observed {
        Observed {
            code_hash: CODE_HASH,
            public_key: pair().to_string(),
            extensions: Vec::new(),
            signature_allowed: true,
        }
    }

    fn admitted(observed: &Observed) -> Result<Admitted, Fault> {
        admit(&CODE_HASH, &pair().tee, observed)
    }

    #[test]
    fn the_one_admitted_case() {
        assert_eq!(admitted(&observed()), Ok(Admitted { pair: pair() }));
    }

    #[test]
    fn each_fault() {
        let swapped = PublicKeyPair { agent: pair().tee, tee: pair().agent };
        let cases = [
            (Observed { code_hash: [0; 32], ..observed() }, Fault::CodeHash),
            (
                Observed { extensions: vec!["owner.near".to_string()], ..observed() },
                Fault::Extension("owner.near".to_string()),
            ),
            (Observed { signature_allowed: false, ..observed() }, Fault::SignatureDisabled),
            (Observed { public_key: String::new(), ..observed() }, Fault::PublicKey),
            (Observed { public_key: pair().to_string().to_uppercase(), ..observed() }, Fault::PublicKey),
            (
                Observed { public_key: hex::encode([pair().tee, pair().tee].concat()), ..observed() },
                Fault::PublicKey,
            ),
            (Observed { public_key: swapped.to_string(), ..observed() }, Fault::TeeKey),
        ];
        for (observed, fault) in cases {
            assert_eq!(admitted(&observed), Err(fault), "{observed:?}");
        }

        // the same account, asked about as another wallet's
        let other = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        assert_eq!(admit(&CODE_HASH, &other, &observed()), Err(Fault::TeeKey));
    }

    /// An account that fails more than one check is refused all the same.
    #[test]
    fn faults_do_not_cancel() {
        let observed = Observed {
            code_hash: [0; 32],
            public_key: String::new(),
            extensions: vec!["owner.near".to_string()],
            signature_allowed: false,
        };
        assert!(admitted(&observed).is_err());
    }
}
