#[derive(Debug, PartialEq)]
pub enum DecdsCLIError {
    FailedToReadProofCarryingChunk(String),
    FailedToSendBlobDataToBlobBuilder(String),
}

impl std::fmt::Display for DecdsCLIError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecdsCLIError::FailedToReadProofCarryingChunk(err) => write!(f, "{}", err),
            DecdsCLIError::FailedToSendBlobDataToBlobBuilder(err) => write!(f, "{}", err),
        }
    }
}
