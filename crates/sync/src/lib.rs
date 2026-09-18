//! Sync: identifiers for groups and messages.
//!
//! Data is organised into groups, and groups hold message graphs. Both are
//! named by hashes rather than by assigned numbers, so two devices that never
//! meet still agree on what a group is and what a message is. Getting these
//! hashes wrong does not look like an error: it looks like messages that
//! quietly never arrive.
//!
//! Spec: `spec/50-sync.md`.

#![forbid(unsafe_code)]

use onestein_crypto::{HASH_LEN, hash};
use onestein_identity::IdentityId;

const GROUP_ID_LABEL: &[u8] = b"org.onestein.sync/GROUP_ID";
const MESSAGE_BLOCK_LABEL: &[u8] = b"org.onestein.sync/MESSAGE_BLOCK";
const MESSAGE_ID_LABEL: &[u8] = b"org.onestein.sync/MESSAGE_ID";

/// Sync layer version. Inside every identifier, so a version change puts the
/// same inputs in different groups rather than in the same group with a
/// different meaning.
pub const SYNC_VERSION: u8 = 1;

/// The longest group descriptor BSP accepts, in bytes.
pub const MAX_GROUP_DESCRIPTOR_LEN: usize = 16 * 1024;

/// The longest message body BSP accepts, in bytes.
pub const MAX_MESSAGE_BODY_LEN: usize = 32 * 1024;

/// Why a group or message could not be named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The group descriptor was longer than [`MAX_GROUP_DESCRIPTOR_LEN`].
    GroupDescriptorTooLong(usize),
    /// The message body was longer than [`MAX_MESSAGE_BODY_LEN`].
    MessageBodyTooLong(usize),
}

/// A group identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupId([u8; HASH_LEN]);

/// A message identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageId([u8; HASH_LEN]);

impl GroupId {
    /// Derives the identifier of a group.
    ///
    /// # Errors
    ///
    /// [`Error::GroupDescriptorTooLong`] if the descriptor exceeds
    /// [`MAX_GROUP_DESCRIPTOR_LEN`].
    pub fn derive(
        client_id: &str,
        client_major_version: u32,
        group_descriptor: &[u8],
    ) -> Result<Self, Error> {
        if group_descriptor.len() > MAX_GROUP_DESCRIPTOR_LEN {
            return Err(Error::GroupDescriptorTooLong(group_descriptor.len()));
        }
        Ok(Self(hash(&[
            GROUP_ID_LABEL,
            &[SYNC_VERSION],
            client_id.as_bytes(),
            &client_major_version.to_be_bytes(),
            group_descriptor,
        ])))
    }

    /// The identifier as bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl MessageId {
    /// Derives the identifier of a message from its group, its timestamp in
    /// milliseconds since the Unix epoch, its author, the device key that
    /// signs it, and its body.
    ///
    /// # Errors
    ///
    /// [`Error::MessageBodyTooLong`] if the body exceeds
    /// [`MAX_MESSAGE_BODY_LEN`].
    pub fn derive(
        group: &GroupId,
        timestamp_ms: u64,
        author: &IdentityId,
        author_device_key: &[u8],
        body: &[u8],
    ) -> Result<Self, Error> {
        let body_hash = body_hash(body)?;
        Ok(Self(hash(&[
            MESSAGE_ID_LABEL,
            &[SYNC_VERSION],
            group.as_bytes(),
            &timestamp_ms.to_be_bytes(),
            author.as_bytes(),
            author_device_key,
            &body_hash,
        ])))
    }

    /// The identifier as bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

/// Hashes a message body on its own.
///
/// The body is hashed separately from the identifier so that a device can
/// keep the position of a deleted message in the graph without keeping the
/// body it deleted.
///
/// # Errors
///
/// [`Error::MessageBodyTooLong`] if the body exceeds
/// [`MAX_MESSAGE_BODY_LEN`].
pub fn body_hash(body: &[u8]) -> Result<[u8; HASH_LEN], Error> {
    if body.len() > MAX_MESSAGE_BODY_LEN {
        return Err(Error::MessageBodyTooLong(body.len()));
    }
    Ok(hash(&[MESSAGE_BLOCK_LABEL, &[SYNC_VERSION], body]))
}
