use std::net::TcpStream;
use std::ops::Mul;

use digest::Digest;
use elliptic_curve::{
    ecdh::EphemeralSecret as EcEphemeralSecret, scalar::FromUintUnchecked, Curve,
    PublicKey as EcPublicKey,
};
use nom::AsBytes;
use p521::NistP521;
use sha2::Sha512;
use smicro_types::serialize::SerializePacket;
use smicro_types::ssh::types::{PositiveBigNum, SSHSlice, SharedSSHSlice};

use crate::session::KexReplySent;
use crate::session::SessionStates;
use crate::{
    crypto::{
        compute_exchange_hash, derive_encryption_key,
        sign::{KeyEcdsa, SignatureWithName},
        CryptoAlg,
    },
    error::Error,
    messages::{MessageKexEcdhInit, MessageKexEcdhReply, MessageKeyExchangeInit},
    state::State,
    write_message,
};

pub trait KEX {
    fn perform_key_exchange(
        &self,
        state: &mut State,
        stream: &mut TcpStream,
        ecdh_init: &MessageKexEcdhInit,
        my_kex_message: &MessageKeyExchangeInit,
        peer_kex_message: &MessageKeyExchangeInit,
    ) -> Result<SessionStates, Error>;
}

pub trait KEXIdentifier: CryptoAlg + KEX {
    const NAME: &'static str;
}

#[derive(Clone)]
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
        stream: &mut TcpStream,
        ecdh_init: &MessageKexEcdhInit,
        my_kex_message: &MessageKeyExchangeInit,
        peer_kex_message: &MessageKeyExchangeInit,
    ) -> Result<SessionStates, Error> {
        let crypto_algs = state
            .crypto_algs
            .as_ref()
            .ok_or(Error::MissingCryptoAlgs)?
            .clone();

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

        let my_secret = EcEphemeralSecret::random(&mut state.rng);
        let shared_secret = my_secret.diffie_hellman(&peer_pubkey);
        let my_pubkey = my_secret.public_key();

        // Retrieve the host key
        let match_host_key = || {
            for host_key in state.host_keys {
                if host_key.key_name() == crypto_algs.host_key_name() {
                    return Some(host_key);
                }
            }
            None
        };
        let matching_host_key =
            match_host_key().ok_or(Error::NoGoodHostKeyFound(crypto_algs.host_key_name()))?;
        let key_name = matching_host_key.key_name();

        // Print the server host key to a byte string
        let mut k_server = Vec::new();
        KeyEcdsa {
            name: key_name,
            curve_name: matching_host_key.curve_name(),
            key: PositiveBigNum(matching_host_key.public_sec1_part().as_bytes()),
        }
        .serialize(&mut k_server)?;
        let k_server = SSHSlice(k_server);

        let q_server = SSHSlice(my_pubkey.to_sec1_bytes().to_vec());

        let exchange_hash = compute_exchange_hash(
            state,
            &mut <Sha512 as Digest>::new(),
            &k_server,
            &q_server,
            &shared_secret,
            ecdh_init,
            my_kex_message,
            peer_kex_message,
        )?;

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

        write_message(state, stream, &res)?;

        let derive_key = |c: u8| -> Result<Vec<u8>, Error> {
            derive_encryption_key(
                &mut <Sha512 as Digest>::new(),
                &shared_secret,
                &exchange_hash,
                c,
                &exchange_hash,
                crypto_algs.key_max_length(),
            )
        };

        let iv_c2s = derive_key(b'A')?;
        let iv_s2c = derive_key(b'B')?;
        let encryption_key_c2s = derive_key(b'C')?;
        let encryption_key_s2c = derive_key(b'D')?;
        let integrity_key_c2s = derive_key(b'E')?;
        let integrity_key_s2c = derive_key(b'F')?;

        state.session_identifier = Some(exchange_hash);

        Ok(SessionStates::KexReplySent(KexReplySent {
            iv_c2s,
            iv_s2c,
            encryption_key_c2s,
            encryption_key_s2c,
            integrity_key_c2s,
            integrity_key_s2c,
        }))
    }
}

impl KEXIdentifier for EcdhSha2Nistp521 {
    const NAME: &'static str = "ecdh-sha2-nistp521";
}
