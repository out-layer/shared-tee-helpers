//! Which move out of a wallet contract an operation is.
//!
//! An agent with on-chain custody asks for an operation in the words every
//! wallet uses ([`Op`]). The policy judges that operation; this file says what
//! the wallet contract then does for it, or that it does nothing. One match,
//! one arm per kind: a new kind of operation does not compile until it is
//! placed here.
//!
//! What a wallet contract does is a [`Move`], and nothing else: a move is one
//! promise to another account with one action (`custody_core::message`). A
//! kind refused here is refused for good: none is ever served by building a
//! wallet operation (an extension, the signature mode) or a request of another
//! shape, since the TEE's half over such a request would let an extension move
//! the contract's funds with no signature and no policy. Such a kind is done
//! from the agent's working account.

use std::fmt;

use base64::Engine;
use custody_core::moves::Move;

use crate::wallet_policy::{is_intents_contract, is_keystore_dao_contract, Op};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The wallet contract does not do this kind of operation.
    Kind(&'static str),
    /// A field of the operation is not what its kind takes.
    Field(&'static str),
    /// A call the wallet contract does not make.
    Call(&'static str),
    /// A 1Click deposit address is required for this kind and given for no
    /// other.
    DepositAddress,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kind(kind) => write!(
                f,
                "A wallet contract does not do `{kind}`. Move what the operation needs to the \
                 agent's working account and do it from there"
            ),
            Self::Field(field) => write!(f, "`{field}` is not valid for this operation"),
            Self::Call(why) => write!(f, "A wallet contract does not make this call: {why}"),
            Self::DepositAddress => f.write_str(
                "A swap and a cross-chain withdrawal take a 1Click deposit address, and no other \
                 operation does",
            ),
        }
    }
}

fn units(field: &'static str, text: &str) -> Result<u128, Refusal> {
    custody_core::text::decimal(text).ok_or(Refusal::Field(field))
}

/// The move for `op`. `deposit_address` is the 1Click deposit address of the
/// quote made for a swap or a cross-chain withdrawal: the account inside NEAR
/// Intents the input is sent to.
pub fn move_for(op: &Op, deposit_address: Option<&str>) -> Result<Move, Refusal> {
    let to_deposit_address = |token: &str, amount: &str| {
        Ok(Move::IntentsTransfer {
            to: deposit_address.ok_or(Refusal::DepositAddress)?.to_string(),
            token_id: token.to_string(),
            amount: units("amount", amount)?,
        })
    };

    let mv = match op {
        Op::Swap { token_in, amount_in, token_out: _, min_out: _ } => {
            return to_deposit_address(token_in, amount_in);
        }
        Op::CrossChainWithdraw { to: _, amount, token, chain: _ } => {
            return to_deposit_address(token, amount);
        }

        Op::Transfer { to, amount } => {
            Move::NearTransfer { to: to.clone(), amount: units("amount", amount)? }
        }
        Op::Call { to, method, args_base64, gas, deposit } => {
            if is_intents_contract(to) {
                return Err(Refusal::Call(
                    "it is to a NEAR Intents contract. Use a transfer, a swap or a withdrawal",
                ));
            }
            if is_keystore_dao_contract(to) {
                return Err(Refusal::Call("it is to the keystore DAO contract"));
            }
            if method.starts_with("w_execute_") {
                return Err(Refusal::Call("it executes a request on a wallet contract"));
            }
            Move::Call {
                to: to.clone(),
                method: method.clone(),
                args: base64::engine::general_purpose::STANDARD
                    .decode(args_base64)
                    .map_err(|_| Refusal::Field("args_base64"))?,
                gas: units("gas", gas)?.try_into().map_err(|_| Refusal::Field("gas"))?,
                deposit: units("deposit", deposit)?,
            }
        }
        Op::Withdraw { to, amount, token } => Move::IntentsWithdraw {
            token: token.strip_prefix("nep141:").ok_or(Refusal::Field("token"))?.to_string(),
            to: to.clone(),
            amount: units("amount", amount)?,
        },
        Op::IntentsTransfer { to, amount, token } => Move::IntentsTransfer {
            to: to.clone(),
            token_id: token.clone(),
            amount: units("amount", amount)?,
        },

        Op::Delete { .. } => return Err(Refusal::Kind("delete")),
        Op::IntentsStorageDeposit { .. } => return Err(Refusal::Kind("intents_storage_deposit")),
        Op::Raw { .. } => return Err(Refusal::Kind("raw")),
        Op::SignMessage { .. } => return Err(Refusal::Kind("sign_message")),
        Op::Confidential { .. } => return Err(Refusal::Kind("confidential")),
        Op::LimitOrder { .. } => return Err(Refusal::Kind("limit_order")),
        Op::PaymentCheck { .. } => return Err(Refusal::Kind("payment_check")),
        Op::Auth { .. } => return Err(Refusal::Kind("auth")),
        Op::PolicyUpdate { .. } => return Err(Refusal::Kind("policy_update")),
    };

    match deposit_address {
        None => Ok(mv),
        Some(_) => Err(Refusal::DepositAddress),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_policy::RecipientType;

    const DEPOSIT: &str = "d4c0000000000000000000000000000000000000000000000000000000000001";
    const USDT: &str = "nep141:usdt.tether-token.near";

    fn s(text: &str) -> String {
        text.to_string()
    }

    fn call(to: &str, method: &str) -> Op {
        Op::Call { to: s(to), method: s(method), args_base64: s("e30="), gas: s("30000000000000"), deposit: s("1") }
    }

    /// One row per kind: the move it is, or that it is none.
    #[test]
    fn every_kind_is_placed() {
        let served = [
            (
                Op::Transfer { to: s("bob.near"), amount: s("5") },
                None,
                Move::NearTransfer { to: s("bob.near"), amount: 5 },
            ),
            (
                call("app.near", "do"),
                None,
                Move::Call { to: s("app.near"), method: s("do"), args: b"{}".to_vec(), gas: 30_000_000_000_000, deposit: 1 },
            ),
            (
                Op::Withdraw { to: s("bob.near"), amount: s("7"), token: s(USDT) },
                None,
                Move::IntentsWithdraw { token: s("usdt.tether-token.near"), to: s("bob.near"), amount: 7 },
            ),
            (
                Op::IntentsTransfer { to: s("bob.near"), amount: s("7"), token: s(USDT) },
                None,
                Move::IntentsTransfer { to: s("bob.near"), token_id: s(USDT), amount: 7 },
            ),
            (
                Op::Swap { token_in: s(USDT), amount_in: s("9"), token_out: s("nep141:wrap.near"), min_out: s("1") },
                Some(DEPOSIT),
                Move::IntentsTransfer { to: s(DEPOSIT), token_id: s(USDT), amount: 9 },
            ),
            (
                Op::CrossChainWithdraw { to: s("0xabc"), amount: s("9"), token: s(USDT), chain: s("ethereum") },
                Some(DEPOSIT),
                Move::IntentsTransfer { to: s(DEPOSIT), token_id: s(USDT), amount: 9 },
            ),
        ];
        for (op, deposit_address, mv) in served {
            assert_eq!(move_for(&op, deposit_address), Ok(mv), "{op:?}");
        }

        let not_served = [
            (Op::Delete { beneficiary: s("bob.near") }, "delete"),
            (
                Op::IntentsStorageDeposit { contract_id: s("usdt.tether-token.near"), account_id: s("bob.near"), amount: s("1") },
                "intents_storage_deposit",
            ),
            (Op::Raw { chain: s("near"), payload_hash: s("00"), label: None }, "raw"),
            (Op::SignMessage { message_hash: s("00"), recipient: s("x"), purpose: None }, "sign_message"),
            (
                Op::Confidential { flow: s("shield"), to: None, amount: s("1"), token: s(USDT), chain: None, token_out: None, min_amount_out: None },
                "confidential",
            ),
            (
                Op::LimitOrder { to: s("bob.near"), to_type: RecipientType::Intents, amount: s("1"), token: s(USDT), token_out: s(USDT), min_amount_out: s("1") },
                "limit_order",
            ),
            (Op::PaymentCheck { amount: s("1"), token: s(USDT) }, "payment_check"),
            (Op::Auth { purpose: s("bearer"), seed: s("x"), vault_id: None, key_hash: None }, "auth"),
            (
                Op::PolicyUpdate { wallet_pubkey: s("ed25519:x"), policy_hash: s("00"), version: 1, locked: true, caller: s("alice.near") },
                "policy_update",
            ),
        ];
        for (op, kind) in not_served {
            assert_eq!(move_for(&op, None), Err(Refusal::Kind(kind)), "{op:?}");
            assert_eq!(move_for(&op, Some(DEPOSIT)), Err(Refusal::Kind(kind)), "{op:?}");
            // the name in the refusal is the kind's own
            assert_eq!(serde_json::to_value(&op).unwrap()["kind"], kind);
        }
    }

    #[test]
    fn calls_a_wallet_contract_does_not_make() {
        for op in [
            call("intents.near", "mt_transfer"),
            call("intents.near", "add_public_key"),
            call("intents.far", "ft_withdraw"),
            call("Intents.Near", "mt_transfer"),
            call("dao.outlayer.near", "initiate_exit"),
            call("dao.outlayer.testnet", "initiate_exit"),
            call("other.near", "w_execute_extension"),
            call("other.near", "w_execute_signed"),
        ] {
            assert!(matches!(move_for(&op, None), Err(Refusal::Call(_))), "{op:?}");
        }
    }

    #[test]
    fn a_deposit_address_is_for_a_swap_and_a_cross_chain_withdrawal_only() {
        let swap = Op::Swap { token_in: s(USDT), amount_in: s("9"), token_out: s("nep141:wrap.near"), min_out: s("1") };
        let cross = Op::CrossChainWithdraw { to: s("0xabc"), amount: s("9"), token: s(USDT), chain: s("ethereum") };
        assert_eq!(move_for(&swap, None), Err(Refusal::DepositAddress));
        assert_eq!(move_for(&cross, None), Err(Refusal::DepositAddress));

        for op in [
            Op::Transfer { to: s("bob.near"), amount: s("5") },
            call("app.near", "do"),
            Op::Withdraw { to: s("bob.near"), amount: s("7"), token: s(USDT) },
            Op::IntentsTransfer { to: s("bob.near"), amount: s("7"), token: s(USDT) },
        ] {
            assert_eq!(move_for(&op, Some(DEPOSIT)), Err(Refusal::DepositAddress), "{op:?}");
        }
    }

    #[test]
    fn fields_that_are_not_what_the_kind_takes() {
        let transfer = |amount: &str| Op::Transfer { to: s("bob.near"), amount: s(amount) };
        for amount in ["", "+5", "-5", "5.0", "0x5", " 5", "5 ", "1e3", "340282366920938463463374607431768211456"] {
            assert_eq!(move_for(&transfer(amount), None), Err(Refusal::Field("amount")), "{amount}");
        }

        let with = |args: &str, gas: &str, deposit: &str| Op::Call {
            to: s("app.near"),
            method: s("do"),
            args_base64: s(args),
            gas: s(gas),
            deposit: s(deposit),
        };
        assert_eq!(move_for(&with("not base64!", "1", "0"), None), Err(Refusal::Field("args_base64")));
        assert_eq!(move_for(&with("e30=", "18446744073709551616", "0"), None), Err(Refusal::Field("gas")));
        assert_eq!(move_for(&with("e30=", "1", "x"), None), Err(Refusal::Field("deposit")));

        // only a NEP-141 token leaves NEAR Intents for a NEAR account
        for token in ["usdt.tether-token.near", "nep245:v2_1.omni.hot.tg:137_x", ""] {
            let op = Op::Withdraw { to: s("bob.near"), amount: s("7"), token: s(token) };
            assert_eq!(move_for(&op, None), Err(Refusal::Field("token")), "{token}");
        }
    }
}
