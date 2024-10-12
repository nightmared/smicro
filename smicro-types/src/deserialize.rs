use nom::{
    bytes::streaming::take,
    number::streaming::{be_u32, be_u8},
    IResult,
};

use crate::{
    error::ParsingError,
    ssh::types::{SharedSSHSlice, SlowSSHSlice},
};

pub trait DeserializePacket<'a>: Sized {
    fn deserialize(input: &'a [u8]) -> IResult<&'a [u8], Self, ParsingError>;
}

impl<'a, T: DeserializePacket<'a>> DeserializePacket<'a> for Option<T> {
    fn deserialize(input: &'a [u8]) -> IResult<&'a [u8], Self, ParsingError> {
        log::trace!("Deserializing {}", std::any::type_name::<Self>());
        let (next_data, present) = take(1usize)(input)?;
        match present[0] {
            0 => Ok((next_data, None)),
            1 => T::deserialize(next_data).map(|(next_data, v)| (next_data, Some(v))),
            _ => Err(nom::Err::Failure(ParsingError::InvalidOptionDiscriminator)),
        }
    }
}

impl<'a, T: DeserializePacket<'a>> DeserializePacket<'a> for SlowSSHSlice<T> {
    fn deserialize(input: &'a [u8]) -> IResult<&'a [u8], Self, ParsingError> {
        log::trace!("Deserializing {}", std::any::type_name::<Self>());
        let (mut input, number_elements) = be_u32(input)?;

        let mut result = Vec::with_capacity(number_elements as usize);

        for _ in 0..number_elements {
            let (next_data, data) = T::deserialize(input)?;
            result.push(data);
            input = next_data;
        }

        Ok((input, SlowSSHSlice(result)))
    }
}

impl<'a> DeserializePacket<'a> for SharedSSHSlice<'a, u8> {
    fn deserialize(input: &'a [u8]) -> IResult<&'a [u8], Self, ParsingError> {
        let (next_data, length) = be_u32(input)?;

        let (next_data, data) = take(length)(next_data)?;

        Ok((next_data, SharedSSHSlice(data)))
    }
}

impl<'a> DeserializePacket<'a> for u8 {
    fn deserialize(input: &'a [u8]) -> IResult<&'a [u8], Self, ParsingError> {
        be_u8(input)
    }
}
