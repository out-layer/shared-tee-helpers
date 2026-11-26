//! The moves out of a wallet contract, and the request built for each.
//!
//! [`build`] is the only way a [`RequestMessage`] comes to exist in the
//! product: from a [`Move`], never from bytes a caller sent. A move is one
//! promise from the wallet contract to another account.

use std::fmt;

use crate::message::{Action, Promise, RequestMessage};

const TGAS: u64 = 1_000_000_000_000;

/// The gas of `mt_transfer` on the Intents contract.
pub const MT_TRANSFER_GAS: u64 = 30 * TGAS;

/// The gas of `ft_withdraw` on the Intents contract: its own work, the
/// token's `ft_transfer` and the callback that resolves it.
pub const FT_WITHDRAW_GAS: u64 = 80 * TGAS;

/// The most gas a [`Move::Call`] may name: what is left of a transaction's
/// 300 Tgas after the wallet contract's own execution.
pub const MAX_CALL_GAS: u64 = 250 * TGAS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Move {
    /// NEAR from the wallet contract's balance to `to`.
    NearTransfer { to: String, amount: u128 },
    /// A function call from the wallet contract.
    Call { to: String, method: String, args: Vec<u8>, gas: u64, deposit: u128 },
    /// A token inside NEAR Intents from the wallet contract's balance to
    /// `to`'s: `mt_transfer` on the Intents contract.
    IntentsTransfer { to: String, token_id: String, amount: u128 },
    /// A NEP-141 token out of NEAR Intents to the NEAR account `to`:
    /// `ft_withdraw` on the Intents contract.
    IntentsWithdraw { token: String, to: String, amount: u128 },
}

/// Where and when a request is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// `mainnet` or `testnet`.
    pub chain_id: String,
    /// The admitted wallet contract.
    pub wallet_contract: String,
    /// The Intents contract of the chain.
    pub intents_contract: String,
    pub nonce: u32,
    /// Nanoseconds since the Unix epoch.
    pub created_at_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Not a NEAR account id.
    AccountId(String),
    /// Not a token id of NEAR Intents.
    TokenId(String),
    /// A move of nothing.
    ZeroAmount,
    /// The wallet contract does not call itself.
    ToItself,
    /// A call that names more gas than a transaction can give it.
    Gas(u64),
    /// A method name the chain does not take.
    Method(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccountId(id) => write!(f, "`{id}` is not a NEAR account id"),
            Self::TokenId(id) => write!(f, "`{id}` is not a token id of NEAR Intents"),
            Self::ZeroAmount => f.write_str("the amount is zero"),
            Self::ToItself => f.write_str("a wallet contract does not send a request to itself"),
            Self::Gas(gas) => {
                write!(f, "a call can name at most {MAX_CALL_GAS} gas; this one names {gas}")
            }
            Self::Method(method) => write!(f, "`{method}` is not a method name"),
        }
    }
}

/// A NEAR account id: 2 to 64 characters, lowercase letters and digits in
/// parts joined by one of `.`, `-`, `_`.
fn account_id(id: &str) -> Result<String, Refusal> {
    let valid = (2..=64).contains(&id.len())
        && id.split(['.', '-', '_']).all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
    valid.then(|| id.to_string()).ok_or_else(|| Refusal::AccountId(id.to_string()))
}

/// A token id inside NEAR Intents, `nep141:<account>` or `nep245:<account>:<id>`:
/// printable ASCII with no quote and no backslash, so it is written into JSON
/// as it is.
fn token_id(id: &str) -> Result<&str, Refusal> {
    let valid = (1..=256).contains(&id.len())
        && id.contains(':')
        && id.bytes().all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\');
    valid.then_some(id).ok_or_else(|| Refusal::TokenId(id.to_string()))
}

fn amount(amount: u128) -> Result<u128, Refusal> {
    (amount != 0).then_some(amount).ok_or(Refusal::ZeroAmount)
}

/// The request for `mv` from the wallet contract of `ctx`.
pub fn build(mv: &Move, ctx: &Context) -> Result<RequestMessage, Refusal> {
    let intents = || account_id(&ctx.intents_contract);
    let (receiver_id, action) = match mv {
        Move::NearTransfer { to, amount: yocto } => {
            (account_id(to)?, Action::Transfer { amount: amount(*yocto)? })
        }
        Move::Call { to, method, args, gas, deposit } => {
            if method.is_empty() || method.len() > 256 || !method.is_ascii() {
                return Err(Refusal::Method(method.clone()));
            }
            if *gas == 0 || *gas > MAX_CALL_GAS {
                return Err(Refusal::Gas(*gas));
            }
            (
                account_id(to)?,
                Action::FunctionCall {
                    function_name: method.clone(),
                    args: args.clone(),
                    deposit: *deposit,
                    gas: *gas,
                },
            )
        }
        Move::IntentsTransfer { to, token_id: token, amount: units } => (
            intents()?,
            Action::FunctionCall {
                function_name: "mt_transfer".to_string(),
                args: format!(
                    r#"{{"receiver_id":"{}","token_id":"{}","amount":"{}"}}"#,
                    account_id(to)?,
                    token_id(token)?,
                    amount(*units)?,
                )
                .into_bytes(),
                deposit: 1,
                gas: MT_TRANSFER_GAS,
            },
        ),
        Move::IntentsWithdraw { token, to, amount: units } => (
            intents()?,
            Action::FunctionCall {
                function_name: "ft_withdraw".to_string(),
                args: format!(
                    r#"{{"token":"{}","receiver_id":"{}","amount":"{}"}}"#,
                    account_id(token)?,
                    account_id(to)?,
                    amount(*units)?,
                )
                .into_bytes(),
                deposit: 1,
                gas: FT_WITHDRAW_GAS,
            },
        ),
    };

    let signer_id = account_id(&ctx.wallet_contract)?;
    if receiver_id == signer_id {
        return Err(Refusal::ToItself);
    }
    Ok(RequestMessage {
        chain_id: ctx.chain_id.clone(),
        signer_id,
        nonce: ctx.nonce,
        created_at_ns: ctx.created_at_ns,
        promise: Promise { receiver_id, action },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context {
            chain_id: "mainnet".to_string(),
            wallet_contract: "trader.alice.near".to_string(),
            intents_contract: "intents.near".to_string(),
            nonce: 41,
            created_at_ns: 1_800_000_000_000_000_000,
        }
    }

    fn args(msg: &RequestMessage) -> &str {
        match &msg.promise.action {
            Action::FunctionCall { args, .. } => std::str::from_utf8(args).unwrap(),
            Action::Transfer { .. } => panic!("a transfer has no arguments"),
        }
    }

    #[test]
    fn a_near_transfer() {
        let msg = build(&Move::NearTransfer { to: "bob.near".to_string(), amount: 5 }, &ctx()).unwrap();
        assert_eq!(
            msg,
            RequestMessage {
                chain_id: "mainnet".to_string(),
                signer_id: "trader.alice.near".to_string(),
                nonce: 41,
                created_at_ns: 1_800_000_000_000_000_000,
                promise: Promise {
                    receiver_id: "bob.near".to_string(),
                    action: Action::Transfer { amount: 5 },
                },
            }
        );
    }

    #[test]
    fn a_call_carries_its_fields_unchanged() {
        let mv = Move::Call {
            to: "app.near".to_string(),
            method: "do".to_string(),
            args: vec![0, 255, b'"'],
            gas: 30 * TGAS,
            deposit: 7,
        };
        let msg = build(&mv, &ctx()).unwrap();
        assert_eq!(msg.promise.receiver_id, "app.near");
        assert_eq!(
            msg.promise.action,
            Action::FunctionCall {
                function_name: "do".to_string(),
                args: vec![0, 255, b'"'],
                deposit: 7,
                gas: 30 * TGAS,
            }
        );
    }

    #[test]
    fn an_intents_transfer_is_mt_transfer_on_the_intents_contract() {
        let mv = Move::IntentsTransfer {
            to: "0".repeat(64),
            token_id: "nep141:wrap.near".to_string(),
            amount: 1_000,
        };
        let msg = build(&mv, &ctx()).unwrap();
        assert_eq!(msg.promise.receiver_id, "intents.near");
        assert_eq!(
            args(&msg),
            format!(
                r#"{{"receiver_id":"{}","token_id":"nep141:wrap.near","amount":"1000"}}"#,
                "0".repeat(64)
            )
        );
        assert!(matches!(
            msg.promise.action,
            Action::FunctionCall { ref function_name, deposit: 1, gas: MT_TRANSFER_GAS, .. }
                if function_name == "mt_transfer"
        ));
    }

    #[test]
    fn an_intents_withdrawal_is_ft_withdraw_on_the_intents_contract() {
        let mv = Move::IntentsWithdraw {
            token: "wrap.near".to_string(),
            to: "bob.near".to_string(),
            amount: 1_000,
        };
        let msg = build(&mv, &ctx()).unwrap();
        assert_eq!(msg.promise.receiver_id, "intents.near");
        assert_eq!(args(&msg), r#"{"token":"wrap.near","receiver_id":"bob.near","amount":"1000"}"#);
        assert!(matches!(
            msg.promise.action,
            Action::FunctionCall { ref function_name, deposit: 1, gas: FT_WITHDRAW_GAS, .. }
                if function_name == "ft_withdraw"
        ));
    }

    #[test]
    fn what_is_refused() {
        let transfer = |to: &str, amount| Move::NearTransfer { to: to.to_string(), amount };
        let call = |to: &str, method: &str, gas| Move::Call {
            to: to.to_string(),
            method: method.to_string(),
            args: Vec::new(),
            gas,
            deposit: 0,
        };
        let intents = |to: &str, token: &str, amount| Move::IntentsTransfer {
            to: to.to_string(),
            token_id: token.to_string(),
            amount,
        };
        let withdraw = |token: &str, to: &str, amount| Move::IntentsWithdraw {
            token: token.to_string(),
            to: to.to_string(),
            amount,
        };
        let id = |id: &str| Refusal::AccountId(id.to_string());

        let cases = [
            (transfer("bob.near", 0), Refusal::ZeroAmount),
            (transfer("Bob.near", 1), id("Bob.near")),
            (transfer("b", 1), id("b")),
            (transfer("bob..near", 1), id("bob..near")),
            (transfer(".bob.near", 1), id(".bob.near")),
            (transfer("bob.near\",\"x\":\"", 1), id("bob.near\",\"x\":\"")),
            (transfer(&"a".repeat(65), 1), id(&"a".repeat(65))),
            (transfer("trader.alice.near", 1), Refusal::ToItself),
            (call("trader.alice.near", "w_execute_signed", TGAS), Refusal::ToItself),
            (call("app.near", "", TGAS), Refusal::Method(String::new())),
            (call("app.near", "do", 0), Refusal::Gas(0)),
            (call("app.near", "do", MAX_CALL_GAS + 1), Refusal::Gas(MAX_CALL_GAS + 1)),
            (intents("bob.near", "nep141:wrap.near", 0), Refusal::ZeroAmount),
            (intents("bob.near", "wrap.near", 1), Refusal::TokenId("wrap.near".to_string())),
            (
                intents("bob.near", "nep141:wrap.near\"", 1),
                Refusal::TokenId("nep141:wrap.near\"".to_string()),
            ),
            (intents("bob.near", "nep141:wrap\\.near", 1), Refusal::TokenId("nep141:wrap\\.near".to_string())),
            (intents("bob.near", "nep141:wrap near", 1), Refusal::TokenId("nep141:wrap near".to_string())),
            (intents("bob\"", "nep141:wrap.near", 1), id("bob\"")),
            (withdraw("nep141:wrap.near", "bob.near", 1), id("nep141:wrap.near")),
            (withdraw("wrap.near", "bob.near", 0), Refusal::ZeroAmount),
            (withdraw("wrap.near", "0xABC", 1), id("0xABC")),
        ];
        for (mv, refusal) in cases {
            assert_eq!(build(&mv, &ctx()), Err(refusal), "{mv:?}");
        }
    }

    /// The Intents contract is the receiver of a move inside Intents and is
    /// never the wallet contract.
    #[test]
    fn a_wallet_contract_named_as_the_intents_contract_is_refused() {
        let ctx = Context { intents_contract: "trader.alice.near".to_string(), ..ctx() };
        let mv = Move::IntentsWithdraw {
            token: "wrap.near".to_string(),
            to: "bob.near".to_string(),
            amount: 1,
        };
        assert_eq!(build(&mv, &ctx), Err(Refusal::ToItself));
    }
}
