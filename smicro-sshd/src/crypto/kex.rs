use std::ops::Mul;

use digest::Digest;
use elliptic_curve::{
    ecdh::EphemeralSecret as EcEphemeralSecret, scalar::FromUintUnchecked, Curve,
    PublicKey as EcPublicKey,
};
use nom::AsBytes;
use p521::NistP521;
use sha2::Sha512;

use smicro_macros::{
    create_wrapper_enum_implementing_trait, declare_crypto_arg, declare_deserializable_struct,
    gen_serialize_impl,
};
use smicro_types::ssh::types::{SSHSlice, SharedSSHSlice};
use smicro_types::{deserialize::DeserializePacket, serialize::SerializePacket};

use crate::{
    crypto::{
        compute_exchange_hash, derive_encryption_key,
        sign::{SignatureWithName, Signer},
        CryptoAlg,
    },
    error::Error,
    messages::{MessageKexEcdhInit, MessageKexEcdhReply},
    session::KexReceived,
    state::State,
};

#[derive(Clone, Debug)]
pub struct KexNegotiatedKeys {
    pub iv_c2s: Vec<u8>,
    pub iv_s2c: Vec<u8>,
    pub encryption_key_c2s: Vec<u8>,
    pub encryption_key_s2c: Vec<u8>,
    pub integrity_key_c2s: Vec<u8>,
    pub integrity_key_s2c: Vec<u8>,
}

#[create_wrapper_enum_implementing_trait(name = KEXWrapper, serializable = true, deserializable = true)]
#[implementors(EcdhSha2Nistp521)]
pub trait KEX {
    fn perform_key_exchange(
        &self,
        state: &mut State,
        ecdh_init: &MessageKexEcdhInit,
        received_kex_msg: &KexReceived,
    ) -> Result<(MessageKexEcdhReply, KexNegotiatedKeys), Error>;
}

#[derive(Clone, Debug)]
#[declare_crypto_arg("ecdh-sha2-nistp521")]
#[declare_deserializable_struct]
#[gen_serialize_impl]
pub struct EcdhSha2Nistp521 {}

impl CryptoAlg for EcdhSha2Nistp521 {
    fn new() -> Self {
        Self {}
    }
}

impl KEX for EcdhSha2Nistp521 {
    fn perform_key_exchange(
        &self,
        state: &mut State,
        ecdh_init: &MessageKexEcdhInit,
        received_kex_msg: &KexReceived,
    ) -> Result<(MessageKexEcdhReply, KexNegotiatedKeys), Error> {
        let crypto_algs = received_kex_msg.new_crypto_algs.clone();

        // Compute the shared secret
        let peer_pubkey: EcPublicKey<p521::NistP521> =
            EcPublicKey::from_sec1_bytes(&ecdh_init.q_client)?;

        // Elliptic Curve Public Key Validation Primitive (see https://www.secg.org/sec1-v2.pdf)
        // `from_sec1_bytes` checks for us that the point is not "at infinity" and that the
        // point lie on the curve

        // Ensure that the order of the curve is respected
        if peer_pubkey
            .as_affine()
            .mul(p521::Scalar::from_uint_unchecked(NistP521::ORDER))
            != p521::ProjectivePoint::IDENTITY
        {
            return Err(Error::InvalidPointForEcdh);
        }

        let my_secret = EcEphemeralSecret::random(&mut state.receiver.rng);
        let shared_secret = my_secret.diffie_hellman(&peer_pubkey);
        let my_pubkey = my_secret.public_key();

        // Retrieve the host key
        let match_host_key = || {
            for host_key in state.host_keys.iter() {
                if host_key.name() == crypto_algs.host_key_alg.name() {
                    return Some(host_key);
                }
            }
            None
        };
        let matching_host_key =
            match_host_key().ok_or(Error::NoGoodHostKeyFound(crypto_algs.host_key_alg.name()))?;
        let key_name = matching_host_key.name();

        // Print the server host key to a byte string
        let k_server = SSHSlice(matching_host_key.serialize_key()?);

        let q_server = SSHSlice(my_pubkey.to_sec1_bytes().to_vec());

        let exchange_hash = compute_exchange_hash(
            state,
            &mut <Sha512 as Digest>::new(),
            &k_server,
            &q_server,
            &shared_secret,
            ecdh_init,
            &received_kex_msg.my_kex_message,
            &received_kex_msg.peer_kex_message,
        )?;

        // the session identifier is unique for the connection, do not reset it if it is already set
        if state.session_identifier.is_none() {
            state.session_identifier = Some(exchange_hash.clone());
        }
        let session_id = state.session_identifier.as_ref().unwrap();

        let mut signature = Vec::new();
        matching_host_key.sign(exchange_hash.as_bytes(), &mut signature)?;

        let mut kex_signature = Vec::new();
        SignatureWithName {
            name: key_name,
            key: SharedSSHSlice(&signature),
        }
        .serialize(&mut kex_signature)?;
        let kex_signature = SSHSlice(kex_signature);

        let res = MessageKexEcdhReply {
            k_server,
            q_server,
            signature: kex_signature,
        };

        let derive_key = |c: u8| -> Result<Vec<u8>, Error> {
            derive_encryption_key(
                &mut <Sha512 as Digest>::new(),
                &shared_secret,
                &exchange_hash,
                c,
                session_id,
                crypto_algs.key_max_length,
            )
        };

        let iv_c2s = derive_key(b'A')?;
        let iv_s2c = derive_key(b'B')?;
        let encryption_key_c2s = derive_key(b'C')?;
        let encryption_key_s2c = derive_key(b'D')?;
        let integrity_key_c2s = derive_key(b'E')?;
        let integrity_key_s2c = derive_key(b'F')?;

        let negotiated_keys = KexNegotiatedKeys {
            iv_c2s,
            iv_s2c,
            encryption_key_c2s,
            encryption_key_s2c,
            integrity_key_c2s,
            integrity_key_s2c,
        };

        Ok((res, negotiated_keys))
    }
}
