use std::io::Write;

use ecdsa::Signature;
use elliptic_curve::{
    sec1::{EncodedPoint, FromEncodedPoint},
    AffinePoint,
};
use nom::Parser;
use p521::NistP521;
use ring::signature::{Ed25519KeyPair, KeyPair, VerificationAlgorithm, ED25519};
use signature::Verifier;
use smicro_macros::{
    create_wrapper_enum_implementing_trait, declare_crypto_arg, declare_deserializable_struct,
    gen_serialize_impl,
};
use smicro_types::deserialize::DeserializePacket;
use smicro_types::serialize::SerializePacket;
use smicro_types::sftp::deserialize::{parse_slice, parse_utf8_slice};
use smicro_types::ssh::types::{PositiveBigNum, SharedSSHSlice};

use crate::{
    crypto::{CryptoAlg, CryptoAlgName, KeyWrapper},
    error::{Error, KeyLoadingError},
};

use super::CryptoAlgWithKey;

const ECDSA_SHA2_NISTPR521_CURVE_NAME: &'static str = "nistp521";
const ED25519_SIZE_BYTES: usize = 32;
const NISTP521_KEY_SIZE_BYTES: usize = 66;

#[create_wrapper_enum_implementing_trait(name = SignerIdentifierWrapper, serializable = true, deserializable = true)]
#[implementors(EcdsaSha2Nistp521, Ed25519)]
pub trait SignerIdentifier {
    fn curve_name(&self) -> Option<&'static str>;

    fn deserialize_buf_to_key<'a>(&self, buf: &'a [u8])
        -> Result<(&'a [u8], SignerWrapper), Error>;

    fn signature_is_valid(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error>;
}

#[derive(Clone, Debug)]
#[declare_crypto_arg("ecdsa-sha2-nistp521")]
#[declare_deserializable_struct]
#[gen_serialize_impl]
pub struct EcdsaSha2Nistp521 {}

impl CryptoAlg for EcdsaSha2Nistp521 {
    fn new() -> Self {
        Self {}
    }
}

impl SignerIdentifier for EcdsaSha2Nistp521 {
    fn curve_name(&self) -> Option<&'static str> {
        Some(ECDSA_SHA2_NISTPR521_CURVE_NAME)
    }

    fn deserialize_buf_to_key<'a>(
        &self,
        buf: &'a [u8],
    ) -> Result<(&'a [u8], SignerWrapper), Error> {
        let (next_data, point_data) = parse_slice(buf)?;
        let (next_data, secret_key_data) = parse_slice(next_data)?;

        Ok((
            next_data,
            SignerWrapper::KeyWrapperEcdsaSha2Nistp521Signer(KeyWrapper::new(&[
                point_data,
                secret_key_data,
            ])?),
        ))
    }

    fn signature_is_valid(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        let (_, key) = KeyEcdsa::deserialize(key)?;
        let signer = <ecdsa::VerifyingKey<NistP521>>::from_sec1_bytes(key.key.0)
            .map_err(|_| Error::InvalidPublicKey)?;

        let (_, sig) = SignatureWithName::deserialize(signature)?;
        let (_, raw_ecdsa_sig) = EcdsaSignature::deserialize(sig.key.0)?;

        let expand_bignum =
            |bignum: PositiveBigNum| -> Result<p521::Scalar, elliptic_curve::Error> {
                let mut out = [0; NISTP521_KEY_SIZE_BYTES];

                let slice = if bignum.0.len() < NISTP521_KEY_SIZE_BYTES {
                    out[NISTP521_KEY_SIZE_BYTES - bignum.0.len()..].copy_from_slice(bignum.0);
                    &out
                } else {
                    bignum.0
                };

                p521::Scalar::from_slice(slice)
            };

        let r = expand_bignum(raw_ecdsa_sig.r)?;
        let s = expand_bignum(raw_ecdsa_sig.s)?;

        let ecdsa_sig = <ecdsa::Signature<NistP521>>::from_scalars(&r, &s)
            .map_err(|_| Error::InvalidSignature)?;

        Ok(signer.verify(message, &ecdsa_sig).is_ok())
    }
}

#[derive(Clone, Debug)]
#[declare_crypto_arg("ssh-ed25519")]
#[declare_deserializable_struct]
#[gen_serialize_impl]
pub struct Ed25519 {}

impl CryptoAlg for Ed25519 {
    fn new() -> Self {
        Self {}
    }
}

impl SignerIdentifier for Ed25519 {
    fn curve_name(&self) -> Option<&'static str> {
        None
    }

    fn deserialize_buf_to_key<'a>(
        &self,
        buf: &'a [u8],
    ) -> Result<(&'a [u8], SignerWrapper), Error> {
        let (next_data, public_key_data) = parse_slice(buf)?;
        let (next_data, secret_key_data) = parse_slice(next_data)?;

        Ok((
            next_data,
            SignerWrapper::KeyWrapperEd25519Signer(KeyWrapper::new(&[
                public_key_data,
                secret_key_data,
            ])?),
        ))
    }

    fn signature_is_valid(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        let (_, key) = Ed25519Key::deserialize(key)?;
        let (_, sig) = SignatureWithName::deserialize(signature)?;

        Ok(ED25519
            .verify(key.key.0.into(), message.into(), sig.key.0.into())
            .is_ok())
    }
}

#[create_wrapper_enum_implementing_trait(name = SignerWrapper, serializable = true, deserializable = true)]
#[implementors(KeyWrapper::<EcdsaSha2Nistp521Signer>, KeyWrapper::<Ed25519Signer>)]
pub trait Signer {
    fn key_name(&self) -> &'static str;
    fn curve_name(&self) -> Option<&'static str>;

    fn integer_size_bytes(&self) -> usize;

    fn sign(&self, data_to_sign: &[u8], output: &mut dyn Write) -> Result<(), Error>;

    fn serialize_key(&self) -> Result<Vec<u8>, Error>;
}

#[declare_crypto_arg("ecdsa-sha2-nistp521")]
pub struct EcdsaSha2Nistp521Signer(ecdsa::SigningKey<NistP521>);

impl CryptoAlgWithKey for EcdsaSha2Nistp521Signer {
    fn new(keys: &[&[u8]]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let point_data = keys[0];
        let secret_key_data = keys[1];
        let encoded_point = <EncodedPoint<NistP521>>::from_bytes(point_data)
            .map_err(|_| KeyLoadingError::InvalidEncodedPoint)?;
        if encoded_point.is_identity() {
            return Err(KeyLoadingError::GotIdentityPoint)?;
        }
        let maybe_affine_point = <AffinePoint<NistP521>>::from_encoded_point(&encoded_point);
        let affine_point = <Option<AffinePoint<NistP521>>>::from(maybe_affine_point)
            .ok_or(KeyLoadingError::NotAnAffinePoint)?;

        let secret_key = p521::SecretKey::from_slice(secret_key_data)
            .map_err(|_| KeyLoadingError::NotASecretKey)?;

        let signing_key = <ecdsa::SigningKey<NistP521>>::from(&secret_key);

        // ensure the automatically-generated verifying key match the public key provided as input
        if signing_key.verifying_key().as_affine() != &affine_point {
            return Err(KeyLoadingError::VerifyingKeyMismatch)?;
        }

        Ok(Self(signing_key))
    }
}

impl Signer for EcdsaSha2Nistp521Signer {
    fn key_name(&self) -> &'static str {
        EcdsaSha2Nistp521::NAME
    }

    fn curve_name(&self) -> Option<&'static str> {
        Some(ECDSA_SHA2_NISTPR521_CURVE_NAME)
    }

    fn integer_size_bytes(&self) -> usize {
        NISTP521_KEY_SIZE_BYTES
    }

    fn sign(&self, data_to_sign: &[u8], mut output: &mut dyn Write) -> Result<(), Error> {
        let data = (&self.0 as &dyn signature::Signer<Signature<NistP521>>)
            .try_sign(data_to_sign)
            .map_err(|_| Error::SigningError)?
            .to_bytes();

        let r = PositiveBigNum(&data[0..self.integer_size_bytes()]);
        let s = PositiveBigNum(&data[self.integer_size_bytes()..]);

        EcdsaSignature { r, s }.serialize(&mut output)?;

        Ok(())
    }

    fn serialize_key(&self) -> Result<Vec<u8>, Error> {
        let mut k_server = Vec::new();
        KeyEcdsa {
            name: self.key_name(),
            curve_name: ECDSA_SHA2_NISTPR521_CURVE_NAME,
            key: PositiveBigNum(self.0.verifying_key().to_encoded_point(false).as_bytes()),
        }
        .serialize(&mut k_server)?;

        Ok(k_server)
    }
}

#[declare_crypto_arg("ssh-ed25519")]
pub struct Ed25519Signer(Ed25519KeyPair);

impl CryptoAlgWithKey for Ed25519Signer {
    fn new(keys: &[&[u8]]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let public_key_data = keys[0];
        let secret_key_data = keys[1];

        // secret_key_data contains the 32 bytes prefix and then a copy of the public key
        // Extract the private key
        let private_key_seed = &secret_key_data[..ED25519_SIZE_BYTES];
        let key_pair = Ed25519KeyPair::from_seed_and_public_key(private_key_seed, public_key_data)
            .map_err(|_| Error::KeyLoadingError(KeyLoadingError::NotASecretKey))?;

        Ok(Ed25519Signer(key_pair))
    }
}

impl Signer for Ed25519Signer {
    fn key_name(&self) -> &'static str {
        Ed25519::NAME
    }

    fn curve_name(&self) -> Option<&'static str> {
        None
    }

    fn integer_size_bytes(&self) -> usize {
        ED25519_SIZE_BYTES
    }

    fn sign(&self, data_to_sign: &[u8], output: &mut dyn Write) -> Result<(), Error> {
        let signature = self.0.sign(data_to_sign);

        Ok(signature.as_ref().serialize(output)?)
    }

    fn serialize_key(&self) -> Result<Vec<u8>, Error> {
        let mut k_server = Vec::new();
        Ed25519Key {
            name: self.key_name(),
            key: SharedSSHSlice(self.0.public_key().as_ref()),
        }
        .serialize(&mut k_server)?;

        Ok(k_server)
    }
}

impl<T: Signer> Signer for KeyWrapper<T> {
    fn key_name(&self) -> &'static str {
        self.inner.key_name()
    }

    fn curve_name(&self) -> Option<&'static str> {
        self.inner.curve_name()
    }

    fn integer_size_bytes(&self) -> usize {
        self.inner.integer_size_bytes()
    }

    fn sign(&self, data_to_sign: &[u8], output: &mut dyn Write) -> Result<(), Error> {
        self.inner.sign(data_to_sign, output)
    }

    fn serialize_key(&self) -> Result<Vec<u8>, Error> {
        self.inner.serialize_key()
    }
}

#[gen_serialize_impl]
#[declare_deserializable_struct]
pub struct KeyEcdsa<'a> {
    #[field(parser = parse_utf8_slice)]
    name: &'a str,
    #[field(parser = parse_utf8_slice)]
    curve_name: &'a str,
    #[field(parser = parse_slice.map(|x| PositiveBigNum(x)))]
    key: PositiveBigNum<'a>,
}

#[gen_serialize_impl]
#[declare_deserializable_struct]
pub struct Ed25519Key<'a> {
    #[field(parser = parse_utf8_slice)]
    name: &'a str,
    key: SharedSSHSlice<'a, u8>,
}

#[gen_serialize_impl]
#[declare_deserializable_struct]
pub struct SignatureWithName<'a> {
    #[field(parser = parse_utf8_slice)]
    name: &'a str,
    #[field(parser = parse_slice.map(SharedSSHSlice))]
    key: SharedSSHSlice<'a, u8>,
}

#[gen_serialize_impl]
#[declare_deserializable_struct]
struct EcdsaSignature<'a> {
    #[field(parser = parse_slice.map(PositiveBigNum))]
    r: PositiveBigNum<'a>,
    #[field(parser = parse_slice.map(PositiveBigNum))]
    s: PositiveBigNum<'a>,
}
