use std::any::type_name;
use std::fmt::Debug;
use std::io::Write;

use elliptic_curve::ecdh::SharedSecret;
use nom::{AsBytes, Parser};

use smicro_macros::{declare_deserializable_struct, gen_serialize_impl};
use smicro_types::ssh::types::{
    MessageType, PositiveBigNum, SSHSlice, SharedSSHSlice, SlowSSHSlice,
};
use smicro_types::{deserialize::DeserializePacket, serialize::SerializePacket};

use crate::messages::{MessageKexEcdhInit, MessageKeyExchangeInit};
use crate::state::IDENTIFIER_STRING;
use crate::{error::Error, state::State};

pub(crate) mod cipher;
pub(crate) mod kex;
pub(crate) mod keys;
pub(crate) mod mac;
pub(crate) mod sign;

use cipher::CipherAllocatorWrapper;
use kex::KEXWrapper;
use mac::MACAllocatorWrapper;
use sign::SignerIdentifierWrapper;

pub trait CryptoAlgName {
    const NAME: &'static str;

    fn name(&self) -> &'static str;
}

pub trait CryptoAlg {
    fn new() -> Self
    where
        Self: Sized;
}

pub trait CryptoAlgWithKey {
    fn new(keys: &[&[u8]]) -> Result<Self, Error>
    where
        Self: Sized;
}

struct HashAdaptor<'a>(&'a mut dyn digest::DynDigest);

impl Write for HashAdaptor<'_> {
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
        state
            .peer_identifier_string
            .as_ref()
            .expect("The client identifier string should have been set by now"),
    )
    .serialize(&mut hash)?;
    IDENTIFIER_STRING.serialize(&mut hash)?;

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

#[declare_deserializable_struct]
#[gen_serialize_impl]
#[derive(Clone)]
pub struct CryptoAlgs {
    pub kex: KEXWrapper,
    pub host_key_alg: SignerIdentifierWrapper,
    pub client_to_server_cipher: CipherAllocatorWrapper,
    pub server_to_client_cipher: CipherAllocatorWrapper,
    pub client_to_server_mac: MACAllocatorWrapper,
    pub server_to_client_mac: MACAllocatorWrapper,
    #[field(parser = nom::number::streaming::be_u64.map(|x| x as usize))]
    pub key_max_length: usize,
}

impl Debug for CryptoAlgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoAlgs")
            .field("kex", &self.kex.name())
            .field("host_key_alg", &self.host_key_alg.name())
            .field(
                "client_to_server_cipher",
                &self.client_to_server_cipher.name(),
            )
            .field("client_to_server_mac", &self.client_to_server_mac.name())
            .field(
                "server_to_client_cipher",
                &self.server_to_client_cipher.name(),
            )
            .field("server_to_client_mac", &self.server_to_client_mac.name())
            .finish()
    }
}

pub struct KeyWrapper<T> {
    keys: SlowSSHSlice<SlowSSHSlice<u8>>,
    pub inner: T,
}

impl<T> Debug for KeyWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyWrapper")
            .field("inner", &type_name::<T>())
            .finish()
    }
}

impl<T: CryptoAlgWithKey> Clone for KeyWrapper<T> {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            inner: T::new(
                &self
                    .keys
                    .0
                    .iter()
                    .map(|x| x.0.as_ref())
                    .collect::<Vec<&[u8]>>(),
            )
            .expect("Couldn't clone a key from itself!?"),
        }
    }
}

impl<'a, T: CryptoAlgWithKey> DeserializePacket<'a> for KeyWrapper<T> {
    fn deserialize(
        input: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self, smicro_types::error::ParsingError> {
        let (next_data, keys) = SlowSSHSlice::deserialize(input)?;
        let inner = T::new(
            &keys
                .0
                .iter()
                .map(|x: &SlowSSHSlice<u8>| x.0.as_ref())
                .collect::<Vec<&[u8]>>(),
        )
        .expect("Couldn't recreate a key from its serialized representation!?");
        Ok((next_data, Self { keys, inner }))
    }
}

impl<T> SerializePacket for KeyWrapper<T> {
    fn get_size(&self) -> usize {
        self.keys.get_size()
    }

    fn serialize<W: Write>(&self, output: W) -> Result<(), std::io::Error> {
        self.keys.serialize(output)
    }
}

impl<T: CryptoAlgName> CryptoAlgName for KeyWrapper<T> {
    const NAME: &str = <T as CryptoAlgName>::NAME;

    fn name(&self) -> &'static str {
        self.inner.name()
    }
}

impl<T: CryptoAlgWithKey + Sized> CryptoAlgWithKey for KeyWrapper<T> {
    fn new(keys: &[&[u8]]) -> Result<Self, Error> {
        let inner = T::new(keys)?;
        Ok(Self {
            keys: SlowSSHSlice(keys.iter().map(|x| SlowSSHSlice(x.to_vec())).collect()),
            inner,
        })
    }
}
