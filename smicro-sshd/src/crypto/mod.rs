use std::fmt::Debug;
use std::io::Write;

use elliptic_curve::ecdh::SharedSecret;
use nom::AsBytes;
use smicro_types::serialize::SerializePacket;
use smicro_types::ssh::types::{MessageType, PositiveBigNum, SSHSlice, SharedSSHSlice};

use crate::messages::{MessageKexEcdhInit, MessageKeyExchangeInit};
use crate::{error::Error, state::State};

pub(crate) mod cipher;
pub(crate) mod kex;
pub(crate) mod mac;
pub(crate) mod sign;

use cipher::{CipherAllocator, CipherIdentifier};
use kex::{KEXIdentifier, KEX};
use mac::{MACAllocator, MACIdentifier};
use sign::SignerIdentifier;

pub trait CryptoAlg {
    fn new() -> Self
    where
        Self: Sized;
}

struct HashAdaptor<'a>(&'a mut dyn digest::DynDigest);

impl<'a> Write for HashAdaptor<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn compute_exchange_hash<C: elliptic_curve::Curve>(
    state: &State,
    hash: &mut dyn digest::DynDigest,
    k_server: &SSHSlice<u8>,
    q_server: &SSHSlice<u8>,
    shared_secret: &SharedSecret<C>,
    ecdh_init: &MessageKexEcdhInit,
    my_kex_message: &MessageKeyExchangeInit,
    peer_kex_message: &MessageKeyExchangeInit,
) -> Result<Vec<u8>, Error> {
    let mut hash = HashAdaptor(hash);

    // Hash the identification strings
    SharedSSHSlice(
        &state
            .peer_identifier_string
            .as_ref()
            .expect("The client identifier string should have been set by now"),
    )
    .serialize(&mut hash)?;
    state.my_identifier_string.serialize(&mut hash)?;

    // Hash the SSH_MSG_KEXINIT messages
    let mut serialize_kex_msg = |kex_msg: &MessageKeyExchangeInit| -> Result<(), Error> {
        let mut tmp_buf = Vec::new();
        kex_msg.serialize(&mut tmp_buf)?;

        ((tmp_buf.len() + 1) as u32).serialize(&mut hash)?;
        (&[MessageType::KexInit as u8] as &[u8]).serialize(&mut hash)?;
        tmp_buf.serialize(&mut hash)?;
        Ok(())
    };
    serialize_kex_msg(peer_kex_message)?;
    serialize_kex_msg(my_kex_message)?;

    // Hash our public host key
    k_server.serialize(&mut hash)?;

    // Hash the ephemeral public keys
    SharedSSHSlice(ecdh_init.q_client).serialize(&mut hash)?;
    q_server.serialize(&mut hash)?;

    // Finally, hash the shared secret
    PositiveBigNum(shared_secret.raw_secret_bytes().as_bytes()).serialize(&mut hash)?;

    let mut result = vec![0; hash.0.output_size()];
    hash.0.finalize_into_reset(&mut result).unwrap();

    Ok(result)
}

fn derive_encryption_key<C: elliptic_curve::Curve>(
    hash: &mut dyn digest::DynDigest,
    shared_secret: &SharedSecret<C>,
    exchange_hash_digest: &[u8],
    char_index: u8,
    session_id: &[u8],
    needed_bits: usize,
) -> Result<Vec<u8>, Error> {
    let mut hash = HashAdaptor(hash);

    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut total_len_bits = 0;
    while total_len_bits < needed_bits {
        PositiveBigNum(shared_secret.raw_secret_bytes().as_slice()).serialize(&mut hash)?;
        exchange_hash_digest.serialize(&mut hash)?;
        if total_len_bits == 0 {
            hash.0.update(&[char_index]);
            session_id.serialize(&mut hash)?;
        } else {
            for key in &keys {
                hash.0.update(key);
            }
        }

        let mut key = vec![0; hash.0.output_size()];
        hash.0.finalize_into_reset(&mut key).unwrap();
        total_len_bits += key.len() * 8;
        keys.push(key);
    }

    let new_key_size = keys.len() * hash.0.output_size();
    let resulting_key = keys
        .into_iter()
        .fold(Vec::with_capacity(new_key_size), |mut acc, new| {
            acc.extend(&new);
            acc.truncate(needed_bits.div_ceil(8));
            acc
        });

    Ok(resulting_key)
}

pub trait ICryptoAlgs: Debug {
    fn kex(&self) -> &dyn KEX;

    fn host_key_name(&self) -> &'static str;

    fn key_max_length(&self) -> usize;

    fn client_cipher(&self) -> &dyn CipherAllocator;

    fn server_cipher(&self) -> &dyn CipherAllocator;

    fn client_mac(&self) -> &dyn MACAllocator;

    fn server_mac(&self) -> &dyn MACAllocator;
}

pub struct CryptoAlgs<
    Kex: KEXIdentifier,
    HostKey: SignerIdentifier,
    C2SCipher: CipherIdentifier,
    S2CCipher: CipherIdentifier,
    C2SMac: MACIdentifier,
    S2CMac: MACIdentifier,
> {
    pub kex: Kex,
    pub host_key_alg: HostKey,
    pub client_to_server_cipher: C2SCipher,
    pub server_to_client_cipher: S2CCipher,
    pub client_to_server_mac: C2SMac,
    pub server_to_client_mac: S2CMac,
    pub key_max_length: usize,
}

impl<
        Kex: KEXIdentifier,
        HostKey: SignerIdentifier,
        C2SCipher: CipherIdentifier,
        S2CCipher: CipherIdentifier,
        C2SMac: MACIdentifier,
        S2CMac: MACIdentifier,
    > ICryptoAlgs for CryptoAlgs<Kex, HostKey, C2SCipher, S2CCipher, C2SMac, S2CMac>
{
    fn kex(&self) -> &dyn KEX {
        &self.kex
    }

    fn host_key_name(&self) -> &'static str {
        self.host_key_alg.name()
    }

    fn key_max_length(&self) -> usize {
        self.key_max_length
    }

    fn client_cipher(&self) -> &dyn CipherAllocator {
        &self.client_to_server_cipher
    }

    fn server_cipher(&self) -> &dyn CipherAllocator {
        &self.server_to_client_cipher
    }

    fn client_mac(&self) -> &dyn MACAllocator {
        &self.client_to_server_mac
    }

    fn server_mac(&self) -> &dyn MACAllocator {
        &self.server_to_client_mac
    }
}

impl<
        Kex: KEXIdentifier,
        HostKey: SignerIdentifier,
        C2SCipher: CipherIdentifier,
        S2CCipher: CipherIdentifier,
        C2SMac: MACIdentifier,
        S2CMac: MACIdentifier,
    > Debug for CryptoAlgs<Kex, HostKey, C2SCipher, S2CCipher, C2SMac, S2CMac>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoAlgs")
            .field("kex", &Kex::NAME)
            .field("host_key_alg", &HostKey::NAME)
            .field("client_to_server_cipher", &C2SCipher::NAME)
            .field("client_to_server_mac", &C2SMac::NAME)
            .field("server_to_client_cipher", &S2CCipher::NAME)
            .field("server_to_client_mac", &S2CMac::NAME)
            .finish()
    }
}
