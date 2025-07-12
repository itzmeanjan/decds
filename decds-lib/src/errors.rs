use crate::{chunkset::ChunkSet, consts};

#[derive(Debug, PartialEq)]
pub enum DecdsError {
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

impl std::fmt::Display for DecdsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecdsError::EmptyDataForBlob => write!(f, "empty data for blob"),
            DecdsError::InvalidStartBound => write!(f, "invalid start bound"),
            DecdsError::InvalidEndBound(end) => write!(f, "invalid end bound: {}", end),

            DecdsError::BlobHeaderSerializationFailed(err) => write!(f, "failed to serialize blob header: {}", err),
            DecdsError::BlobHeaderDeserializationFailed(err) => write!(f, "failed to deserialize blob header: {}", err),

            DecdsError::ProofCarryingChunkSerializationFailed(err) => write!(f, "failed to serialize proof carrying chunk: {}", err),
            DecdsError::ProofCarryingChunkDeserializationFailed(err) => write!(f, "failed to deserialize proof carrying chunk: {}", err),

            DecdsError::ChunksetReadyToRepair(id) => write!(f, "chunkset {} is ready to repair", id),
            DecdsError::ChunksetNotYetReadyToRepair(id) => write!(f, "chunkset {} is not ready to repair", id),
            DecdsError::ChunksetAlreadyRepaired(id) => write!(f, "chunkset {} is already repaired", id),
            DecdsError::ChunksetRepairingFailed(id, err) => write!(f, "chunkset {} repairing failed: {}", id, err),

            DecdsError::InvalidErasureCodedShareId(id) => write!(
                f,
                "invalid erasure coded share id: {} (num_shares: {})",
                id,
                consts::DECDS_NUM_ERASURE_CODED_SHARES
            ),
            DecdsError::InvalidChunksetId(id, num_chunksets) => write!(f, "invalid chunkset id: {} (num_chunksets: {})", id, num_chunksets),
            DecdsError::InvalidChunksetSize(size) => write!(f, "invalid chunkset size: {}B, expected: {}B", size, ChunkSet::SIZE),
            DecdsError::InvalidChunkMetadata(chunkset_id) => write!(f, "invalid chunk for chunkset {}", chunkset_id),
            DecdsError::InvalidProofInChunk(chunkset_id) => write!(f, "invalid proof carrying chunk for chunkset {}", chunkset_id),
            DecdsError::ChunkDecodingFailed(chunkset_id, err) => write!(f, "decoding chunk for chunkset {} failed: {}", chunkset_id, err),

            DecdsError::NoLeafNodesToBuildMerkleTreeOn => write!(f, "no leaf nodes to build merkle tree on"),
            DecdsError::InvalidLeafNodeIndex(leaf_index, num_leaves) => write!(f, "invalid leaf node index: {} (num_leaves: {})", leaf_index, num_leaves),
        }
    }
}
