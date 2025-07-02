use rlnc::RLNCError;

#[derive(Debug, PartialEq)]
pub enum ShelbyError {
    CatchAllError,
}

impl std::fmt::Display for ShelbyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            _ => write!(f, "something went wrong !"),
        }
    }
}

pub fn rlnc_error_mapper(_: RLNCError) -> ShelbyError {
    ShelbyError::CatchAllError
}

pub fn bincode_error_mapper(_: bincode::error::EncodeError) -> ShelbyError {
    ShelbyError::CatchAllError
}
