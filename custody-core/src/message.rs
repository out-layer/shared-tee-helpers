//! The wallet contract's request message, as far as this product builds one.
//!
//! These types mirror the contract's `RequestMessage` and can express only
//! what is served: one promise to another account, carrying one function call
//! or one transfer. There is no wallet operation (no extension, no signature
//! mode), no state-init action, no `refund_to` and no `pay_for_gas`; the
//! encoder writes those as empty or false. There is no decoder: a request is
//! built here from an operation, never read from a caller.

use borsh::BorshSerialize;
use sha3::{Digest, Sha3_256};

use crate::{REQUEST_DOMAIN, TIMEOUT_SECS};

/// A request to a wallet contract, with the fields a signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMessage {
    /// `mainnet` or `testnet`.
    pub chain_id: String,
    /// The wallet contract's account.
    pub signer_id: String,
    /// Never accepted twice by the contract within the timeout.
    pub nonce: u32,
    /// Nanoseconds since the Unix epoch. The contract accepts the request
    /// from this moment for [`TIMEOUT_SECS`].
    pub created_at_ns: u64,
    pub promise: Promise,
}

/// One receipt to `receiver_id`, with one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Promise {
    pub receiver_id: String,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    FunctionCall {
        function_name: String,
        args: Vec<u8>,
        /// yoctoNEAR.
        deposit: u128,
        /// The exact gas of the call.
        gas: u64,
    },
    /// yoctoNEAR.
    Transfer { amount: u128 },
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
