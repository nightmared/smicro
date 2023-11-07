use nom::{
    bytes::complete::take, number::complete::be_u32, number::complete::be_u64, sequence::tuple,
    IResult, Parser,
};

use crate::{
    command::{command_deserialize, CommandType, CommandWrapper},
    error::ParsingError,
    types::{Attrs, AttrsFlags, OpenModes},
};

pub trait DeserializeSftp: Sized {
    fn deserialize(input: &[u8]) -> IResult<&[u8], Self, ParsingError<&[u8]>>;
}

pub fn parse_open_modes(input: &[u8]) -> IResult<&[u8], u32, ParsingError<&[u8]>> {
    let (next_data, modes) = be_u32(input)?;

    if modes
        & !(OpenModes::Read as u32
            | OpenModes::Write as u32
            | OpenModes::Append as u32
            | OpenModes::Create as u32
            | OpenModes::Truncate as u32
            | OpenModes::Exclusive as u32)
        != 0
    {
        return Err(nom::Err::Failure(ParsingError::InvalidOpenModes(modes)));
    }

    Ok((next_data, modes))
}

pub fn parse_attrs_flags(input: &[u8]) -> IResult<&[u8], u32, ParsingError<&[u8]>> {
    let (next_data, flags) = be_u32(input)?;

    if flags
        & !(AttrsFlags::Size as u32
            | AttrsFlags::UidAndGid as u32
            | AttrsFlags::Permissions as u32
            | AttrsFlags::Time as u32)
        != 0
    {
        return Err(nom::Err::Failure(ParsingError::InvalidAttrsFlags(flags)));
    }

    Ok((next_data, flags))
}

pub fn parse_attrs(input: &[u8]) -> IResult<&[u8], Attrs, ParsingError<&[u8]>> {
    let (mut next_data, flags) = parse_attrs_flags(input)?;

    let mut size = None;
    if flags & AttrsFlags::Size as u32 != 0 {
        (next_data, size) = be_u64.map(Some).parse(next_data)?;
    }

    let mut uid = None;
    let mut gid = None;
    if flags & AttrsFlags::UidAndGid as u32 != 0 {
        (next_data, uid) = be_u32.map(Some).parse(next_data)?;
        (next_data, gid) = be_u32.map(Some).parse(next_data)?;
    }

    let mut permissions = None;
    if flags & AttrsFlags::Permissions as u32 != 0 {
        (next_data, permissions) = be_u32.map(Some).parse(next_data)?;
    }

    let mut atime = None;
    let mut mtime = None;
    if flags & AttrsFlags::Time as u32 != 0 {
        (next_data, atime) = be_u32.map(Some).parse(next_data)?;
        (next_data, mtime) = be_u32.map(Some).parse(next_data)?;
    }

    let attrs = Attrs {
        attribute_flags: flags,
        size,
        uid,
        gid,
        permissions,
        atime,
        mtime,
    };

    Ok((next_data, attrs))
}

#[derive(Debug)]
pub struct PacketHeader<Ty> {
    pub length: u32,
    pub ty: Ty,
    pub request_id: Option<u32>,
}

#[derive(Debug)]
pub struct Packet<PktTy, Data> {
    pub hdr: PacketHeader<PktTy>,
    pub data: Data,
}

fn parse_command_type(input: &[u8]) -> IResult<&[u8], CommandType, ParsingError<&[u8]>> {
    let (next, potential_cmd) = nom::number::streaming::u8(input)?;
    Ok((
        next,
        CommandType::try_from(potential_cmd)
            .map_err(ParsingError::from)
            .map_err(nom::Err::Failure)?,
    ))
}

pub fn parse_version(input: &[u8]) -> IResult<&[u8], u32, ParsingError<&[u8]>> {
    let (next_data, version) = be_u32(input)?;
    // only accept clients that implement version renegociation
    if version != 3 {
        return Err(nom::Err::Failure(ParsingError::InvalidVersionNumber(
            version,
        )));
    }

    Ok((next_data, version))
}

fn parse_command_header(
    input: &[u8],
) -> IResult<&[u8], PacketHeader<CommandType>, ParsingError<&[u8]>> {
    let (mut next_data, (length, ty)) =
        tuple((nom::number::streaming::be_u32, parse_command_type))(input)?;

    let mut request_id = None;
    if ty != CommandType::Init {
        (next_data, request_id) = nom::number::streaming::be_u32.map(Some).parse(next_data)?;
    }

    Ok((
        next_data,
        PacketHeader {
            length,
            ty,
            request_id,
        },
    ))
}

pub fn parse_string(input: &[u8]) -> IResult<&[u8], Vec<u8>, ParsingError<&[u8]>> {
    let (next_data, length) = be_u32(input)?;

    let (next_data, data) = take(length)(next_data)?;

    Ok((next_data, data.to_vec()))
}

pub fn parse_utf8_string(input: &[u8]) -> IResult<&[u8], String, ParsingError<&[u8]>> {
    let (next_data, bytes) = parse_string(input)?;

    let string = String::from_utf8(bytes)
        .map_err(ParsingError::from)
        .map_err(nom::Err::Failure)?;

    Ok((next_data, string))
}

pub fn parse_command(
    input: &[u8],
) -> IResult<&[u8], Packet<CommandType, CommandWrapper>, ParsingError<&[u8]>> {
    let (_, hdr) = parse_command_header(input)?;
    if input.len() < hdr.length as usize + 4 {
        return Err(nom::Err::Incomplete(nom::Needed::Unknown));
    }
    let command_data = if hdr.request_id.is_some() {
        &input[9..hdr.length as usize + 4]
    } else {
        &input[5..hdr.length as usize + 4]
    };
    let next_data = &input[hdr.length as usize + 4..];
    Ok((next_data, command_deserialize(hdr, command_data)?))
}
