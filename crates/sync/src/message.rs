//! Messages: what a group's graph is made of.
//!
//! Every message carries its author and a signature, so a third party can say
//! who wrote what. That is what a group needs and what Bramble leaves to each
//! client to invent separately.
//!
//! Spec: `spec/50-sync.md` §2, §3, §7.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use onestein_crypto::{HASH_LEN, hash};
use onestein_identity::IdentityId;

use crate::{
    Error, GroupId, MAX_MESSAGE_BODY_LEN, MESSAGE_SIGNATURE_LABEL, MessageId, SYNC_VERSION,
};

/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Length of a message payload before the body.
pub const MESSAGE_HEADER_LEN: usize = HASH_LEN + 8 + HASH_LEN + HASH_LEN + SIGNATURE_LEN;

/// A message, before or after signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message<'a> {
    /// The group it belongs to.
    pub group_id: GroupId,
    /// When its author says it was written, in milliseconds since the Unix
    /// epoch. What the sender wrote, not what anyone can check.
    pub timestamp_ms: u64,
    /// Who wrote it.
    pub author: IdentityId,
    /// The device signing key that signs it, which a verifier resolves to a
    /// certificate before believing anything.
    pub device_key: [u8; HASH_LEN],
    /// The body, opaque to this layer.
    pub body: &'a [u8],
}

impl Message<'_> {
    /// The message identifier.
    ///
    /// # Errors
    ///
    /// [`Error::MessageBodyTooLong`].
    pub fn id(&self) -> Result<MessageId, Error> {
        MessageId::derive(
            &self.group_id,
            self.timestamp_ms,
            &self.author,
            &self.device_key,
            self.body,
        )
    }

    /// What the device key signs.
    ///
    /// # Errors
    ///
    /// As [`Message::id`].
    pub fn to_sign(&self) -> Result<[u8; HASH_LEN], Error> {
        Ok(hash(&[
            MESSAGE_SIGNATURE_LABEL,
            &[SYNC_VERSION],
            self.id()?.as_bytes(),
        ]))
    }

    /// Writes the payload of a MESSAGE record.
    ///
    /// # Errors
    ///
    /// [`Error::MessageBodyTooLong`].
    pub fn encode(&self, signature: &[u8; SIGNATURE_LEN]) -> Result<Vec<u8>, Error> {
        if self.body.len() > MAX_MESSAGE_BODY_LEN {
            return Err(Error::MessageBodyTooLong(self.body.len()));
        }
        let mut out = Vec::with_capacity(MESSAGE_HEADER_LEN.saturating_add(self.body.len()));
        out.extend_from_slice(self.group_id.as_bytes());
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        out.extend_from_slice(self.author.as_bytes());
        out.extend_from_slice(&self.device_key);
        out.extend_from_slice(signature);
        out.extend_from_slice(self.body);
        Ok(out)
    }
}

/// A message with the signature that was sent with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedMessage<'a> {
    /// The message.
    pub message: Message<'a>,
    /// Its signature, not yet checked.
    pub signature: [u8; SIGNATURE_LEN],
}

impl SignedMessage<'_> {
    /// Checks the signature against the device key the message names.
    ///
    /// This says the holder of that device key wrote the message. Whether
    /// that device belongs to the author is a question for the identity
    /// layer, and this function does not answer it.
    ///
    /// # Errors
    ///
    /// [`Error::BadSignature`].
    pub fn verify(&self) -> Result<(), Error> {
        let key =
            VerifyingKey::from_bytes(&self.message.device_key).map_err(|_| Error::BadSignature)?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify(&self.message.to_sign()?, &signature)
            .map_err(|_| Error::BadSignature)
    }
}

/// Reads the payload of a MESSAGE record.
///
/// # Errors
///
/// [`Error::Malformed`] if it is shorter than a header or longer than a
/// message may be.
pub fn decode_message(payload: &[u8]) -> Result<SignedMessage<'_>, Error> {
    let body = payload.get(MESSAGE_HEADER_LEN..).ok_or(Error::Malformed)?;
    if body.len() > MAX_MESSAGE_BODY_LEN {
        return Err(Error::Malformed);
    }
    let at = |offset: usize, length: usize| -> Result<&[u8], Error> {
        payload
            .get(offset..offset.saturating_add(length))
            .ok_or(Error::Malformed)
    };
    let fixed = |bytes: &[u8]| -> Result<[u8; HASH_LEN], Error> {
        <[u8; HASH_LEN]>::try_from(bytes).map_err(|_| Error::Malformed)
    };

    let group_id = GroupId::from_bytes(fixed(at(0, HASH_LEN)?)?);
    let timestamp_ms =
        u64::from_be_bytes(<[u8; 8]>::try_from(at(HASH_LEN, 8)?).map_err(|_| Error::Malformed)?);
    let author = IdentityId::from_bytes(fixed(at(HASH_LEN + 8, HASH_LEN)?)?);
    let device_key = fixed(at(HASH_LEN + 8 + HASH_LEN, HASH_LEN)?)?;
    let signature = <[u8; SIGNATURE_LEN]>::try_from(at(HASH_LEN * 3 + 8, SIGNATURE_LEN)?)
        .map_err(|_| Error::Malformed)?;

    Ok(SignedMessage {
        message: Message {
            group_id,
            timestamp_ms,
            author,
            device_key,
            body,
        },
        signature,
    })
}
