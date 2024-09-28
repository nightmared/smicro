use std::io::Write;

use ecdsa::Signature;
use elliptic_curve::{
    point::AffineCoordinates,
    sec1::{EncodedPoint, FromEncodedPoint},
    AffinePoint,
};
use nom::Parser;
use p521::NistP521;
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
    crypto::{CryptoAlg, CryptoAlgName},
    error::{Error, KeyLoadingError},
};

const ECDSA_SHA2_NISTPR521_CURVE_NAME: &'static str = "nistp521";
const NISTP521_KEY_SIZE_BYTES: usize = 66;

#[create_wrapper_enum_implementing_trait(name = SignerIdentifierWrapper, implementors = [EcdsaSha2Nistp521])]
pub trait SignerIdentifier {
    fn curve_name(&self) -> &'static str;

    fn deserialize_buf_to_key<'a>(
        &self,
        buf: &'a [u8],
    ) -> Result<(&'a [u8], SignerWrapper), KeyLoadingError>;

    fn signature_is_valid(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error>;
}

#[declare_crypto_arg("ecdsa-sha2-nistp521")]
pub struct EcdsaSha2Nistp521 {}

impl CryptoAlg for EcdsaSha2Nistp521 {
    fn new() -> Self {
        Self {}
    }
}

impl SignerIdentifier for EcdsaSha2Nistp521 {
    fn curve_name(&self) -> &'static str {
        ECDSA_SHA2_NISTPR521_CURVE_NAME
    }

    fn deserialize_buf_to_key<'a>(
        &self,
        buf: &'a [u8],
    ) -> Result<(&'a [u8], SignerWrapper), KeyLoadingError> {
        let (next_data, point_data) = parse_slice(buf)?;

        let encoded_point = <EncodedPoint<NistP521>>::from_bytes(point_data)
            .map_err(|_| KeyLoadingError::InvalidEncodedPoint)?;
        if encoded_point.is_identity() {
            return Err(KeyLoadingError::GotIdentityPoint);
        }
        let maybe_affine_point = <AffinePoint<NistP521>>::from_encoded_point(&encoded_point);
        let affine_point = <Option<AffinePoint<NistP521>>>::from(maybe_affine_point)
            .ok_or(KeyLoadingError::NotAnAffinePoint)?;

        let (next_data, secret_key_data) = parse_slice(next_data)?;
        let secret_key = p521::SecretKey::from_slice(secret_key_data)
            .map_err(|_| KeyLoadingError::NotASecretKey)?;

        let signing_key = <ecdsa::SigningKey<NistP521>>::from(&secret_key);

        // ensure the automatically-generated verifying key match the public key provided as input
        if signing_key.verifying_key().as_affine() != &affine_point {
            return Err(KeyLoadingError::VerifyingKeyMismatch);
        }

        Ok((
            next_data,
            SignerWrapper::EcdsaSha2Nistp521Signer(EcdsaSha2Nistp521Signer(signing_key)),
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

#[create_wrapper_enum_implementing_trait(name = SignerWrapper, implementors = [EcdsaSha2Nistp521Signer])]
pub trait Signer {
    fn key_name(&self) -> &'static str;
    fn curve_name(&self) -> &'static str;

    fn integer_size_bytes(&self) -> usize;

    fn sign(&self, data_to_sign: &[u8], output: &mut dyn Write) -> Result<(), Error>;

    fn public_sec1_part(&self) -> Vec<u8>;

    fn public_key_x(&self) -> Vec<u8>;
}

#[declare_crypto_arg("ecdsa-sha2-nistp521")]
pub struct EcdsaSha2Nistp521Signer(ecdsa::SigningKey<NistP521>);

impl Signer for EcdsaSha2Nistp521Signer {
    fn key_name(&self) -> &'static str {
        EcdsaSha2Nistp521::NAME
    }

    fn curve_name(&self) -> &'static str {
        ECDSA_SHA2_NISTPR521_CURVE_NAME
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

    fn public_sec1_part(&self) -> Vec<u8> {
        self.0
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    fn public_key_x(&self) -> Vec<u8> {
        self.0.verifying_key().as_affine().x().to_vec()
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
