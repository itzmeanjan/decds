#[derive(Debug, PartialEq)]
pub enum DecdsCLIError {
    FailedToReadProofCarryingChunk(String),
}

impl std::fmt::Display for DecdsCLIError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecdsCLIError::FailedToReadProofCarryingChunk(err) => write!(f, "{}", err),
        }
    }
}
