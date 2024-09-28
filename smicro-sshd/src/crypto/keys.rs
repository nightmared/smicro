use std::fs::File;
use std::io::Read;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use log::{debug, info, trace};
use nom::{
    bytes::complete::{tag, take_till1, take_while},
    character::complete::line_ending,
    combinator::{peek, rest},
    multi::{many_till, separated_list0},
    number::complete::be_u32,
    sequence::{delimited, preceded, terminated, tuple},
    AsChar, Parser,
};

use smicro_macros::declare_deserializable_struct;
use smicro_types::deserialize::DeserializePacket;
use smicro_types::sftp::deserialize::{parse_slice, parse_utf8_string};

use crate::crypto::sign::SignerIdentifier;
use crate::error::KeyLoadingError;
use crate::messages::negotiate_alg_signing_algorithms;

use super::sign::SignerWrapper;

#[declare_deserializable_struct]
pub struct OpenSSHKeySerialized<'a> {
    #[field(parser = parse_utf8_string)]
    ciphername: String,
    #[field(parser = parse_utf8_string)]
    kdfname: String,
    #[field(parser = parse_slice)]
    kdfoptions: &'a [u8],
    #[field(parser = be_u32)]
    key_number: u32,
    #[field(parser = rest)]
    key_data: &'a [u8],
}

pub fn load_hostkey(hostkey_file: &Path) -> Result<SignerWrapper, KeyLoadingError> {
    let mut f = File::open(hostkey_file)?;
    let mut file_content = Vec::with_capacity(4096);
    f.read_to_end(&mut file_content)?;

    let mut key_parser = delimited(
        tag("-----BEGIN OPENSSH PRIVATE KEY-----\n"),
        many_till(
            terminated(take_till1(|c| c == b'\n' || c == b'\r'), line_ending),
            peek(tag(b"-")),
        )
        .map(|(delimited_list, _)| delimited_list),
        tag("-----END OPENSSH PRIVATE KEY-----"),
    )
    .map(|v| {
        let mut res = Vec::with_capacity(file_content.len());
        for substr in v {
            res.extend_from_slice(substr);
        }
        res
    });

    let key_base64encoded = key_parser.parse(file_content.as_slice())?.1;
    let key_openssh_raw = STANDARD.decode(key_base64encoded)?;

    let key_openssh_raw_data =
        preceded(tag("openssh-key-v1\0"), rest)(key_openssh_raw.as_slice())?.1;

    let key_openssh_raw_serialized = OpenSSHKeySerialized::deserialize(key_openssh_raw_data)?.1;

    let nb_keys = key_openssh_raw_serialized.key_number as usize;

    if nb_keys != 1 {
        return Err(KeyLoadingError::InvalidNumberOfKeys);
    }

    if key_openssh_raw_serialized.kdfname != "none"
        || key_openssh_raw_serialized.ciphername != "none"
        || key_openssh_raw_serialized.kdfoptions != []
    {
        return Err(KeyLoadingError::PassphraseProtectedKeyUnsupported);
    }

    let next_data = key_openssh_raw_serialized.key_data;
    let (next_data, _public_key) = parse_slice(next_data)?;

    let (_, next_data) = parse_slice(next_data)?;
    let (next_data, checkint1) = be_u32(next_data)?;
    let (next_data, checkint2) = be_u32(next_data)?;

    if checkint1 != checkint2 {
        return Err(KeyLoadingError::InvalidIntegersCheck);
    }

    let (next_data, private_key_type) = parse_utf8_string(next_data)?;
    let signing_algo = negotiate_alg_signing_algorithms(&[&private_key_type])
        .map_err(|_| KeyLoadingError::UnsupportedSigningAlgorithm)?;

    let (next_data, curve_name) = parse_utf8_string(next_data)?;
    // check that the EC curve name matches the key type
    if curve_name != signing_algo.curve_name() {
        return Err(KeyLoadingError::EcdsaCurveMismatch);
    }

    let (next_data, signing_key) = signing_algo.deserialize_buf_to_key(next_data)?;

    let (mut next_data, comment) = parse_utf8_string(next_data)?;
    info!("Read key '{}' of type '{}'", comment, private_key_type);

    // ensure a proper padding
    let mut pad_pos = 1;
    while next_data != [] {
        if next_data[0] != pad_pos {
            return Err(KeyLoadingError::InvalidBlockPadding);
        }

        pad_pos += 1;
        next_data = &next_data[1..];
    }

    Ok(signing_key)
}

#[derive(Debug)]
pub struct AuthorizedKeyOption {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug)]
pub struct AuthorizedKey {
    pub key_type: Vec<u8>,
    pub key_data: Vec<u8>,
    pub options: Vec<AuthorizedKeyOption>,
}

pub fn load_public_key_list(allowed_keys: &Path) -> Result<Vec<AuthorizedKey>, KeyLoadingError> {
    let mut f = File::open(&allowed_keys)?;
    let mut file_content = Vec::with_capacity(4096);
    f.read_to_end(&mut file_content)?;

    let mut results = Vec::new();

    let mut next_data = file_content.as_slice();
    while next_data.len() > 0 {
        let (remain, entry) = terminated(take_while(|c| c != b'\n'), tag("\n"))(next_data)?;
        next_data = remain;

        // let's ignore key options for now, by finding the first unquoted whitespace character
        let space = || tag::<&[u8], &[u8], _>(b" ").or(tag(b"\t"));
        let keytype_parser = || {
            terminated(
                take_while(|c: u8| c.is_alphanum() || c == b'-' || c == b'.' || c == b'@'),
                space(),
            )
        };
        let pubkey_parser = || {
            terminated(
                // base64
                take_while(|c: u8| {
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                        .contains(&c)
                }),
                space(),
            )
        };
        let comment = rest;
        let key_parser = || {
            tuple((keytype_parser(), pubkey_parser(), comment)).map(|(key_type, key_data, _)| {
                STANDARD.decode(key_data).map(|key_data| AuthorizedKey {
                    key_type: key_type.to_vec(),
                    key_data,
                    options: Vec::new(),
                })
            })
        };

        let opt_key = take_while(|c: u8| c.is_alphanum() || c == b'-');
        let opt_value = delimited(tag("\""), take_while(|c: u8| c != b'"'), tag("\""));
        let opt_parser = tuple((&opt_key, tag("="), opt_value))
            .map(|(name, _, value): (&[u8], _, &[u8])| {
                if let (Ok(name), Ok(value)) = (
                    String::from_utf8(name.to_vec()),
                    String::from_utf8(value.to_vec()),
                ) {
                    Some(AuthorizedKeyOption {
                        name,
                        value: Some(value),
                    })
                } else {
                    None
                }
            })
            .or((&opt_key)
                .map(Vec::from)
                .map(String::from_utf8)
                .map(|name| {
                    if let Ok(name) = name {
                        Some(AuthorizedKeyOption { name, value: None })
                    } else {
                        None
                    }
                }));
        let opts_parser = terminated(separated_list0(tag(","), opt_parser), space());

        let mut parser =
            key_parser().or(tuple((opts_parser, key_parser())).map(|(options, key)| {
                key.map(|mut key| {
                    for opt in options {
                        if let Some(opt) = opt {
                            key.options.push(opt);
                        }
                    }
                    key
                })
            }));
        let parsed: Result<_, nom::Err<nom::error::Error<_>>> = parser.parse(entry);
        if let Ok((_, Ok(parsed))) = parsed {
            trace!("Parsed public key object: {:?}", parsed);
            results.push(parsed);
        } else {
            debug!("Invalid public key entry {:?}", entry);
        }
    }

    Ok(results)
}
