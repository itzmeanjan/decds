use crate::{chunkset::ChunkSet, consts};

#[derive(Debug, PartialEq)]
pub enum DECDSError {
    EmptyDataForBlob,
    InvalidStartBound,
    InvalidEndBound(usize),

    BlobHeaderSerializationFailed(String),
    BlobHeaderDeserializationFailed(String),

    ProofCarryingChunkSerializationFailed(String),
    ProofCarryingChunkDeserializationFailed(String),

    ChunksetReadyToRepair(usize),
    ChunksetNotYetReadyToRepair(usize),
    ChunksetAlreadyRepaired(usize),
    ChunksetRepairingFailed(usize, String),

    InvalidErasureCodedShareId(usize),
    InvalidChunksetId(usize, usize),
    InvalidChunksetSize(usize),
    InvalidChunkMetadata(usize),
    InvalidProofInChunk(usize),
    ChunkDecodingFailed(usize, String),

    NoLeafNodesToBuildMerkleTreeOn,
    InvalidLeafNodeIndex(usize, usize),
}

impl std::fmt::Display for DECDSError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DECDSError::EmptyDataForBlob => write!(f, "empty data for blob"),
            DECDSError::InvalidStartBound => write!(f, "invalid start bound"),
            DECDSError::InvalidEndBound(end) => write!(f, "invalid end bound: {}", end),

            DECDSError::BlobHeaderSerializationFailed(err) => write!(f, "failed to serialize blob header: {}", err),
            DECDSError::BlobHeaderDeserializationFailed(err) => write!(f, "failed to deserialize blob header: {}", err),

            DECDSError::ProofCarryingChunkSerializationFailed(err) => write!(f, "failed to serialize proof carrying chunk: {}", err),
            DECDSError::ProofCarryingChunkDeserializationFailed(err) => write!(f, "failed to deserialize proof carrying chunk: {}", err),

            DECDSError::ChunksetReadyToRepair(id) => write!(f, "chunkset {} is ready to repair", id),
            DECDSError::ChunksetNotYetReadyToRepair(id) => write!(f, "chunkset {} is not ready to repair", id),
            DECDSError::ChunksetAlreadyRepaired(id) => write!(f, "chunkset {} is already repaired", id),
            DECDSError::ChunksetRepairingFailed(id, err) => write!(f, "chunkset {} repairing failed: {}", id, err),

            DECDSError::InvalidErasureCodedShareId(id) => write!(
                f,
                "invalid erasure coded share id: {} (num_shares: {})",
                id,
                consts::DECDS_NUM_ERASURE_CODED_SHARES
            ),
            DECDSError::InvalidChunksetId(id, num_chunksets) => write!(f, "invalid chunkset id: {} (num_chunksets: {})", id, num_chunksets),
            DECDSError::InvalidChunksetSize(size) => write!(f, "invalid chunkset size: {}B, expected: {}B", size, ChunkSet::SIZE),
            DECDSError::InvalidChunkMetadata(chunkset_id) => write!(f, "invalid chunk for chunkset {}", chunkset_id),
            DECDSError::InvalidProofInChunk(chunkset_id) => write!(f, "invalid proof carrying chunk for chunkset {}", chunkset_id),
            DECDSError::ChunkDecodingFailed(chunkset_id, err) => write!(f, "decoding chunk for chunkset {} failed: {}", chunkset_id, err),

            DECDSError::NoLeafNodesToBuildMerkleTreeOn => write!(f, "no leaf nodes to build merkle tree on"),
            DECDSError::InvalidLeafNodeIndex(leaf_index, num_leaves) => write!(f, "invalid leaf node index: {} (num_leaves: {})", leaf_index, num_leaves),
        }
    }
}
