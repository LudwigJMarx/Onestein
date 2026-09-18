//! Revocations: how a device stops being accepted.
//!
//! A revocation is the certificate's opposite and shares its shape, which is
//! exactly why it does not share its label. Four of the five field names are
//! the same, so one label would mean a signature keeps its meaning while the
//! fields around it are reinterpreted.
//!
//! Spec: `spec/40-identity.md` §5.

use onestein_bdf::Value;
use onestein_crypto::{HASH_LEN, hash};

use crate::certificate::{REVOCATION_LABEL, exact, integer, open_container, raw};
use crate::{Error, IDENTITY_VERSION, IdentityId, RootKeys};

/// What a revocation says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revocation {
    /// The identity withdrawing the device.
    pub identity_id: IdentityId,
    /// The device signing key that is no longer accepted.
    pub device_signing_pub: [u8; HASH_LEN],
    /// The device set epoch this revocation belongs to.
    pub epoch: u64,
}

impl Revocation {
    /// Encodes the revocation as canonical BDF: the bytes that are signed.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] if the epoch does not fit BDF's signed integer.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let epoch = i64::try_from(self.epoch).map_err(|_| Error::OutOfRange)?;
        let fields = Value::Dict(vec![
            (
                "dev".to_owned(),
                Value::Raw(self.device_signing_pub.to_vec()),
            ),
            ("epoch".to_owned(), Value::Int(epoch)),
            (
                "id".to_owned(),
                Value::Raw(self.identity_id.as_bytes().to_vec()),
            ),
            ("v".to_owned(), Value::Int(i64::from(IDENTITY_VERSION))),
        ]);
        debug_assert!(
            fields.is_canonical(),
            "the field order above is the canonical one"
        );
        Ok(onestein_bdf::to_bytes(&fields))
    }

    /// The value both root keys sign.
    ///
    /// # Errors
    ///
    /// As [`Revocation::encode`].
    pub fn to_sign(&self) -> Result<[u8; HASH_LEN], Error> {
        Ok(hash(&[REVOCATION_LABEL, &self.encode()?]))
    }
}

/// Verifies a revocation container against a contact's root keys.
///
/// # Errors
///
/// [`Error::Malformed`], [`Error::WrongIdentity`], [`Error::BadSignature`].
pub fn verify_revocation(
    container: &[u8],
    root_ed25519: &[u8],
    root_mldsa: &[u8],
) -> Result<Revocation, Error> {
    let (body, expected_identity) =
        open_container(container, root_ed25519, root_mldsa, REVOCATION_LABEL)?;

    if integer(&body, "v")? != i64::from(IDENTITY_VERSION) {
        return Err(Error::Malformed);
    }
    if raw(&body, "id")? != expected_identity.as_bytes() {
        return Err(Error::WrongIdentity);
    }
    let epoch = integer(&body, "epoch")?;

    Ok(Revocation {
        identity_id: expected_identity,
        device_signing_pub: exact(raw(&body, "dev")?)?,
        epoch: u64::try_from(epoch).map_err(|_| Error::Malformed)?,
    })
}

impl RootKeys {
    /// Signs a revocation with both root keys.
    ///
    /// # Errors
    ///
    /// As [`RootKeys::sign_certificate`].
    pub fn sign_revocation(&self, revocation: &Revocation) -> Result<Vec<u8>, Error> {
        self.sign_with_label(REVOCATION_LABEL, revocation.encode()?)
    }
}

/// Applies the epoch rule a contact keeps per identity, and returns the
/// epoch to record.
///
/// An epoch below the recorded one is refused. Not because it is forged, but
/// because accepting it would let an old certificate be replayed to a contact
/// that already learned of the revocation, and resurrect a device that is
/// gone.
///
/// An epoch equal to the recorded one is accepted: two devices certified in
/// one epoch is an ordinary thing to do.
///
/// # Errors
///
/// [`Error::EpochInThePast`].
pub fn accept_epoch(recorded_highest: u64, epoch: u64) -> Result<u64, Error> {
    if epoch < recorded_highest {
        return Err(Error::EpochInThePast {
            recorded: recorded_highest,
            given: epoch,
        });
    }
    Ok(epoch)
}
