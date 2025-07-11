#[derive(Debug, PartialEq)]
pub enum DecdsError {
    FailedToReadProofCarryingChunk(String),
}

impl std::fmt::Display for DecdsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecdsError::FailedToReadProofCarryingChunk(err) => write!(f, "{}", err),
        }
    }
}
