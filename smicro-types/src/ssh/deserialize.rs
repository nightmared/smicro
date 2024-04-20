use nom::{
    bytes::complete::{tag, take, take_while1},
    combinator::{all_consuming, map},
    multi::separated_list0,
    number::complete::{be_u32, be_u8},
    AsChar, IResult,
};

use crate::error::ParsingError;

use super::types::{MessageType, NameList};

pub fn parse_message_type(input: &[u8]) -> IResult<&[u8], MessageType, ParsingError> {
    let (next, potential_cmd) = be_u8(input)?;

    Ok((
        next,
        MessageType::try_from(potential_cmd)
            .map_err(ParsingError::from)
            .map_err(nom::Err::Failure)?,
    ))
}

pub fn parse_name_list(input: &[u8]) -> IResult<&[u8], NameList, ParsingError> {
    let (next, length) = be_u32(input)?;
    let (next, data) = take(length)(next)?;

    let (_, entry_list) = all_consuming(separated_list0(
        tag(b","),
        take_while1(|c: u8| c.is_ascii() && c != b','),
    ))(data)?;

    let mut entries = Vec::with_capacity(entry_list.len());
    for entry in entry_list {
        entries.push(
            std::str::from_utf8(entry)
                .map_err(|e| nom::Err::Failure(ParsingError::from(e)))?
                .to_string(),
        );
    }

    Ok((next, NameList { entries }))
}

pub fn parse_boolean(input: &[u8]) -> IResult<&[u8], bool, ParsingError> {
    let (next, val) = be_u8(input)?;
    Ok((next, val != 0))
}

// see https://github.com/rust-bakery/nom/issues/1517
pub fn streaming_const_take<const N: usize>(i: &[u8]) -> IResult<&[u8], [u8; N], ParsingError> {
    // Safety: fine because `take` already check that we took N bytes
    map(nom::bytes::streaming::take(N), |bytes: &[u8]| {
        let mut res = [0; N];
        res.copy_from_slice(bytes);
        res
    })(i)
}
// see https://github.com/rust-bakery/nom/issues/1517
pub fn const_take<const N: usize>(i: &[u8]) -> IResult<&[u8], [u8; N], ParsingError> {
    // Safety: fine because `take` already check that we took N bytes
    map(take(N), |bytes: &[u8]| {
        let mut res = [0; N];
        res.copy_from_slice(bytes);
        res
    })(i)
}
