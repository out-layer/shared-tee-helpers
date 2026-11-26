//! The wallet contract's request message, as far as this product builds one.
//!
//! These types mirror the contract's `RequestMessage` and can express only
//! what is served: one promise to another account, carrying one function call
//! or one transfer. There is no wallet operation (no extension, no signature
//! mode), no state-init action, no `refund_to` and no `pay_for_gas`; the
//! encoder writes those as empty or false. There is no decoder: a request is
//! built here from an operation, never read from a caller.

use base64::Engine;
use borsh::BorshSerialize;
use sha3::{Digest, Sha3_256};

use crate::{REQUEST_DOMAIN, TIMEOUT_SECS};

/// A request to a wallet contract, with the fields a signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize), serde(deny_unknown_fields))]
pub struct RequestMessage {
    /// `mainnet` or `testnet`.
    pub chain_id: String,
    /// The wallet contract's account.
    pub signer_id: String,
    /// Never accepted twice by the contract within the timeout.
    pub nonce: u32,
    /// Nanoseconds since the Unix epoch. The contract accepts the request
    /// from this moment for [`TIMEOUT_SECS`]. In JSON: a decimal string.
    #[cfg_attr(feature = "serde", serde(with = "json::decimal"))]
    pub created_at_ns: u64,
    pub promise: Promise,
}

/// One receipt to `receiver_id`, with one action.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize), serde(deny_unknown_fields))]
pub struct Promise {
    pub receiver_id: String,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)
)]
pub enum Action {
    FunctionCall {
        function_name: String,
        /// In JSON: base64.
        #[cfg_attr(feature = "serde", serde(with = "json::base64"))]
        args: Vec<u8>,
        /// yoctoNEAR. In JSON: a decimal string.
        #[cfg_attr(feature = "serde", serde(with = "json::decimal"))]
        deposit: u128,
        /// The exact gas of the call. In JSON: a decimal string.
        #[cfg_attr(feature = "serde", serde(with = "json::decimal"))]
        gas: u64,
    },
    Transfer {
        /// yoctoNEAR. In JSON: a decimal string.
        #[cfg_attr(feature = "serde", serde(with = "json::decimal"))]
        amount: u128,
    },
}

impl RequestMessage {
    /// The contract's canonical hash:
    /// `SHA3-256("NEAR_WALLET_CONTRACT/V1" ‖ borsh(msg))`.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new_with_prefix(REQUEST_DOMAIN);
        hasher.update(self.to_borsh());
        hasher.finalize().into()
    }

    /// The contract's Borsh encoding of this message.
    pub fn to_borsh(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh: writing to a Vec does not fail")
    }
}

impl RequestMessage {
    /// The arguments of the contract's `w_execute_signed(msg, proof)`, as
    /// JSON.
    pub fn execute_signed_args(&self, proof: &str) -> Vec<u8> {
        format!(r#"{{"msg":{},"proof":{}}}"#, self.to_json(), json_string(proof)).into_bytes()
    }

    /// The contract's JSON form of this message.
    pub fn to_json(&self) -> String {
        let action = match &self.promise.action {
            Action::FunctionCall { function_name, args, deposit, gas } => format!(
                r#"{{"action":"function_call","payload":{{"function_name":{},"args":"{}","deposit":"{deposit}","gas":"{gas}","gas_weight":"0"}}}}"#,
                json_string(function_name),
                base64::engine::general_purpose::STANDARD.encode(args),
            ),
            Action::Transfer { amount } => {
                format!(r#"{{"action":"transfer","payload":{{"amount":"{amount}"}}}}"#)
            }
        };
        format!(
            r#"{{"chain_id":{},"signer_id":{},"nonce":{},"created_at":"{}","timeout_secs":{TIMEOUT_SECS},"request":{{"external":[{{"receiver_id":{},"actions":[{action}]}}]}}}}"#,
            json_string(&self.chain_id),
            json_string(&self.signer_id),
            self.nonce,
            rfc3339(self.created_at_ns),
            json_string(&self.promise.receiver_id),
        )
    }
}

/// `text` as a JSON string.
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r"\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!(r"\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Nanoseconds since the Unix epoch as an RFC 3339 time in UTC, with nine
/// digits of the second's fraction.
fn rfc3339(ns: u64) -> String {
    let (secs, nanos) = (ns / 1_000_000_000, ns % 1_000_000_000);
    let (days, rem) = (secs / 86_400, secs % 86_400);

    // days since the epoch to a civil date (Howard Hinnant's `civil_from_days`)
    let z = days + 719_468;
    let (era, doe) = (z / 146_097, z % 146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{nanos:09}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60,
    )
}

/// How this crate's own JSON form of a message writes numbers and bytes. The
/// form carries a built request between the services and the agent; it is not
/// the contract's ([`RequestMessage::to_json`]).
#[cfg(feature = "serde")]
mod json {
    pub mod decimal {
        use std::{fmt::Display, str::FromStr};

        use serde::{de::Error, Deserialize, Deserializer, Serializer};

        pub fn serialize<T: Display, S: Serializer>(value: &T, s: S) -> Result<S::Ok, S::Error> {
            s.collect_str(value)
        }

        pub fn deserialize<'de, T: FromStr, D: Deserializer<'de>>(d: D) -> Result<T, D::Error> {
            let text = String::deserialize(d)?;
            // digits only: `from_str` also takes a leading `+`
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err(D::Error::custom("not a decimal number"));
            }
            text.parse().map_err(|_| D::Error::custom("the number is out of range"))
        }
    }

    pub mod base64 {
        use ::base64::{engine::general_purpose::STANDARD, Engine};
        use serde::{de::Error, Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&STANDARD.encode(bytes))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            STANDARD.decode(String::deserialize(d)?).map_err(|_| D::Error::custom("not base64"))
        }
    }
}

impl BorshSerialize for RequestMessage {
    fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        false.serialize(w)?; // pay_for_gas
        self.chain_id.serialize(w)?;
        self.signer_id.serialize(w)?;
        self.nonce.serialize(w)?;
        self.created_at_ns.serialize(w)?;
        TIMEOUT_SECS.serialize(w)?;
        0u32.serialize(w)?; // request.internal: no wallet operation
        1u32.serialize(w)?; // request.external: one promise
        self.promise.receiver_id.serialize(w)?;
        0u8.serialize(w)?; // refund_to: none
        1u32.serialize(w)?; // actions: one
        match &self.promise.action {
            Action::FunctionCall { function_name, args, deposit, gas } => {
                2u8.serialize(w)?;
                function_name.serialize(w)?;
                args.serialize(w)?;
                deposit.serialize(w)?;
                gas.serialize(w)?;
                0u64.serialize(w) // gas_weight: no share of the unused gas
            }
            Action::Transfer { amount } => {
                3u8.serialize(w)?;
                amount.serialize(w)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        for (ns, text) in [
            (0, "1970-01-01T00:00:00.000000000Z"),
            (1, "1970-01-01T00:00:00.000000001Z"),
            (951_782_399_999_999_999, "2000-02-28T23:59:59.999999999Z"),
            (951_782_400_000_000_000, "2000-02-29T00:00:00.000000000Z"),
            (1_800_000_000_123_000_000, "2027-01-15T08:00:00.123000000Z"),
            (4_107_542_399_000_000_000, "2100-02-28T23:59:59.000000000Z"),
            (4_107_542_400_000_000_000, "2100-03-01T00:00:00.000000000Z"),
        ] {
            assert_eq!(rfc3339(ns), text);
        }
    }

    #[test]
    fn its_own_json_form_round_trips() {
        let msg = RequestMessage {
            chain_id: "mainnet".to_string(),
            signer_id: "trader.alice.near".to_string(),
            nonce: 3,
            created_at_ns: u64::MAX,
            promise: Promise {
                receiver_id: "app.near".to_string(),
                action: Action::FunctionCall {
                    function_name: "do".to_string(),
                    args: vec![0, 255],
                    deposit: u128::MAX,
                    gas: 5,
                },
            },
        };
        let text = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            text,
            r#"{"chain_id":"mainnet","signer_id":"trader.alice.near","nonce":3,"created_at_ns":"18446744073709551615","promise":{"receiver_id":"app.near","action":{"action":"function_call","function_name":"do","args":"AP8=","deposit":"340282366920938463463374607431768211455","gas":"5"}}}"#
        );
        assert_eq!(serde_json::from_str::<RequestMessage>(&text).unwrap(), msg);

        for refused in [
            text.replace(r#""gas":"5""#, r#""gas":"+5""#),
            text.replace(r#""gas":"5""#, r#""gas":5"#),
            text.replace(r#""nonce":3"#, r#""nonce":3,"pay_for_gas":true"#),
            text.replace(r#""receiver_id""#, r#""refund_to":"x.near","receiver_id""#),
            text.replace("function_call", "deterministic_state_init"),
        ] {
            assert!(serde_json::from_str::<RequestMessage>(&refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn strings() {
        assert_eq!(json_string("plain"), r#""plain""#);
        assert_eq!(json_string(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(json_string("a\nb\u{1}"), r#""a\u000ab\u0001""#);
    }
}
