use nom::IResult;

use crate::error::ParsingError;

pub trait DeserializePacket<'a>: Sized {
    fn deserialize(input: &'a [u8]) -> IResult<&'a [u8], Self, ParsingError>;
}
