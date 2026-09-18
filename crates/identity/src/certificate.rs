//! Device certificates: what binds a device's keys to an identity.
//!
//! The root key signs, the device is named, and every contact can check it
//! against root keys it already holds. That is what lets a new device appear
//! without anyone meeting again.
//!
//! Spec: `spec/40-identity.md` §4.

use ed25519_dalek::{
    Signature as EdSignature, Signer, SigningKey as EdSigningKey, Verifier,
    VerifyingKey as EdVerifyingKey,
};
use ml_dsa::{
    B32, EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Signature as PqSignature,
    SigningKey as PqSigningKey, VerifyingKey as PqVerifyingKey,
};
use onestein_bdf::{Value, from_bytes_canonical, to_bytes};
use onestein_crypto::{HASH_LEN, hash};

use crate::{Error, IDENTITY_VERSION, IdentityId};

const CERTIFICATE_LABEL: &[u8] = b"org.onestein.identity/DEVICE_CERTIFICATE";

/// A revocation's label. Different from the certificate's because the two
/// structures share four of their field names, and one label would let a
/// signature keep its meaning while the fields around it are reinterpreted
/// (`spec/40-identity.md` §5).
pub(crate) const REVOCATION_LABEL: &[u8] = b"org.onestein.identity/DEVICE_REVOCATION";

/// ML-DSA takes a context string and it is empty here, in every signature
/// this stack makes. The domain separation is in `to_sign`, and a second
/// mechanism saying the same thing is a second one to get wrong
/// (`spec/40-identity.md` §4).
const MLDSA_CONTEXT: &[u8] = b"";

/// Length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Length of an ML-DSA-65 signature.
pub const MLDSA_SIGNATURE_LEN: usize = 3309;

/// Length of an X25519 public key.
pub const X25519_LEN: usize = 32;

/// Length of an ML-KEM-768 encapsulation key.
pub const KEM_ENCAPSULATION_KEY_LEN: usize = 1184;

/// What a device certificate says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceCertificate {
    /// The identity this device belongs to.
    pub identity_id: IdentityId,
    /// The device's Ed25519 signing public key.
    pub device_signing_pub: [u8; HASH_LEN],
    /// The device's static X25519 public key.
    pub dh_static_pub: [u8; X25519_LEN],
    /// The device's static ML-KEM encapsulation key.
    pub kem_static_pub: [u8; KEM_ENCAPSULATION_KEY_LEN],
    /// The device set epoch this certificate belongs to.
    pub epoch: u64,
    /// When the device was certified, in milliseconds since the Unix epoch.
    pub from_ms: u64,
}

impl DeviceCertificate {
    /// Encodes the certificate as canonical BDF: exactly the bytes that are
    /// signed and exactly the bytes a verifier hashes.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] if a timestamp or epoch does not fit the signed
    /// integer BDF uses.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let epoch = i64::try_from(self.epoch).map_err(|_| Error::OutOfRange)?;
        let from = i64::try_from(self.from_ms).map_err(|_| Error::OutOfRange)?;
        // In canonical order, which is the order a verifier will see.
        let fields = Value::Dict(vec![
            (
                "dev".to_owned(),
                Value::Raw(self.device_signing_pub.to_vec()),
            ),
            ("dh".to_owned(), Value::Raw(self.dh_static_pub.to_vec())),
            ("epoch".to_owned(), Value::Int(epoch)),
            ("from".to_owned(), Value::Int(from)),
            (
                "id".to_owned(),
                Value::Raw(self.identity_id.as_bytes().to_vec()),
            ),
            ("kem".to_owned(), Value::Raw(self.kem_static_pub.to_vec())),
            ("v".to_owned(), Value::Int(i64::from(IDENTITY_VERSION))),
        ]);
        debug_assert!(
            fields.is_canonical(),
            "the field order above is the canonical one"
        );
        Ok(to_bytes(&fields))
    }

    /// The value both root keys sign.
    ///
    /// # Errors
    ///
    /// As [`DeviceCertificate::encode`].
    pub fn to_sign(&self) -> Result<[u8; HASH_LEN], Error> {
        Ok(hash(&[CERTIFICATE_LABEL, &self.encode()?]))
    }
}

/// An identity's root secret keys.
///
/// Derived from the recovery seed, which is why the same seed rebuilds the
/// same identity on any device, forever.
pub struct RootKeys {
    ed25519: EdSigningKey,
    mldsa: PqSigningKey<MlDsa65>,
}

impl RootKeys {
    /// Builds the root keys from the two seeds `spec/40-identity.md` §6
    /// derives from the recovery seed.
    #[must_use]
    pub fn from_seeds(ed25519_seed: &[u8; 32], mldsa_seed: &[u8; 32]) -> Self {
        Self {
            ed25519: EdSigningKey::from_bytes(ed25519_seed),
            mldsa: PqSigningKey::<MlDsa65>::from_seed(&B32::from(*mldsa_seed)),
        }
    }

    /// The Ed25519 root public key.
    #[must_use]
    pub fn ed25519_public(&self) -> [u8; HASH_LEN] {
        self.ed25519.verifying_key().to_bytes()
    }

    /// The ML-DSA root public key.
    #[must_use]
    pub fn mldsa_public(&self) -> Vec<u8> {
        self.mldsa.verifying_key().encode().to_vec()
    }

    /// The identifier of this identity.
    ///
    /// # Errors
    ///
    /// As [`IdentityId::derive`].
    pub fn identity_id(&self) -> Result<IdentityId, Error> {
        IdentityId::derive(&self.ed25519_public(), &self.mldsa_public())
    }

    /// Signs a certificate with both root keys and returns the container that
    /// carries all three.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] from encoding, [`Error::Signing`] if ML-DSA
    /// refuses.
    pub fn sign_certificate(&self, certificate: &DeviceCertificate) -> Result<Vec<u8>, Error> {
        self.sign_with_label(CERTIFICATE_LABEL, certificate.encode()?)
    }

    /// Signs any of this layer's structures and wraps it with both
    /// signatures. The label is what decides which structure it is.
    pub(crate) fn sign_with_label(&self, label: &[u8], encoded: Vec<u8>) -> Result<Vec<u8>, Error> {
        let to_sign = hash(&[label, &encoded]);

        let ed25519 = self.ed25519.sign(&to_sign).to_bytes();
        let mldsa = self
            .mldsa
            .expanded_key()
            .sign_deterministic(&to_sign, MLDSA_CONTEXT)
            .map_err(|_| Error::Signing)?
            .encode();

        let container = Value::Dict(vec![
            ("c".to_owned(), Value::Raw(encoded)),
            ("e".to_owned(), Value::Raw(ed25519.to_vec())),
            ("p".to_owned(), Value::Raw(mldsa.to_vec())),
        ]);
        Ok(to_bytes(&container))
    }
}

/// Verifies a certificate container against the root keys a contact already
/// holds.
///
/// Both signatures must verify. One of two is not a weaker certificate, it is
/// a certificate a quantum adversary could have written.
///
/// # Errors
///
/// [`Error::Malformed`], [`Error::WrongIdentity`], [`Error::BadSignature`].
pub fn verify_certificate(
    container: &[u8],
    root_ed25519: &[u8],
    root_mldsa: &[u8],
) -> Result<DeviceCertificate, Error> {
    let (body, expected_identity) =
        open_container(container, root_ed25519, root_mldsa, CERTIFICATE_LABEL)?;
    if integer(&body, "v")? != i64::from(IDENTITY_VERSION) {
        return Err(Error::Malformed);
    }
    if raw(&body, "id")? != expected_identity.as_bytes() {
        return Err(Error::WrongIdentity);
    }
    let epoch = integer(&body, "epoch")?;
    let from_ms = integer(&body, "from")?;

    Ok(DeviceCertificate {
        identity_id: expected_identity,
        device_signing_pub: exact(raw(&body, "dev")?)?,
        dh_static_pub: exact(raw(&body, "dh")?)?,
        kem_static_pub: exact(raw(&body, "kem")?)?,
        epoch: u64::try_from(epoch).map_err(|_| Error::Malformed)?,
        from_ms: u64::try_from(from_ms).map_err(|_| Error::Malformed)?,
    })
}

/// Opens a signed container: both signatures over the bytes inside, then the
/// bytes parsed.
///
/// Verify before parsing. What has not been authenticated is an attacker's
/// data structure, and parsing it first puts the parser in front.
pub(crate) fn open_container(
    container: &[u8],
    root_ed25519: &[u8],
    root_mldsa: &[u8],
    label: &[u8],
) -> Result<(Vec<(String, Value)>, IdentityId), Error> {
    // Length-checks the root keys on the way, before anything is verified
    // against them.
    let expected_identity = IdentityId::derive(root_ed25519, root_mldsa)?;

    let fields = dictionary(container)?;
    let signed = raw(&fields, "c")?;
    let to_sign = hash(&[label, signed]);
    verify_ed25519(root_ed25519, &to_sign, raw(&fields, "e")?)?;
    verify_mldsa(root_mldsa, &to_sign, raw(&fields, "p")?)?;

    Ok((dictionary(signed)?, expected_identity))
}

/// Parses canonical BDF into a dictionary. Non-canonical input is refused,
/// because these bytes are hashed (`spec/10-encoding.md` §2.3).
pub(crate) fn dictionary(bytes: &[u8]) -> Result<Vec<(String, Value)>, Error> {
    match from_bytes_canonical(bytes) {
        Ok(Value::Dict(entries)) => Ok(entries),
        _ => Err(Error::Malformed),
    }
}

pub(crate) fn raw<'a>(fields: &'a [(String, Value)], key: &str) -> Result<&'a [u8], Error> {
    match fields.iter().find(|(name, _)| name == key) {
        Some((_, Value::Raw(bytes))) => Ok(bytes),
        _ => Err(Error::Malformed),
    }
}

pub(crate) fn integer(fields: &[(String, Value)], key: &str) -> Result<i64, Error> {
    match fields.iter().find(|(name, _)| name == key) {
        Some((_, Value::Int(number))) => Ok(*number),
        _ => Err(Error::Malformed),
    }
}

pub(crate) fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    <[u8; N]>::try_from(bytes).map_err(|_| Error::Malformed)
}

fn verify_ed25519(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    let public = EdVerifyingKey::from_bytes(&exact(public)?).map_err(|_| Error::BadSignature)?;
    let signature = EdSignature::from_bytes(&exact(signature)?);
    public
        .verify(message, &signature)
        .map_err(|_| Error::BadSignature)
}

fn verify_mldsa(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    let encoded_key =
        EncodedVerifyingKey::<MlDsa65>::try_from(public).map_err(|_| Error::BadSignature)?;
    let key = PqVerifyingKey::<MlDsa65>::decode(&encoded_key);

    let encoded_signature =
        EncodedSignature::<MlDsa65>::try_from(signature).map_err(|_| Error::BadSignature)?;
    let signature =
        PqSignature::<MlDsa65>::decode(&encoded_signature).ok_or(Error::BadSignature)?;

    if key.verify_with_context(message, MLDSA_CONTEXT, &signature) {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}
