use crate::{chunkset::ChunkSet, consts};

#[derive(Debug, PartialEq)]
pub enum DecdsError {
    /// Returned when trying to create a blob with empty data.
    EmptyDataForBlob,
    /// Returned when a byte range operation has an invalid start bound.
    InvalidStartBound,
    /// Returned when a byte range operation has an invalid end bound. Contains the invalid end value.
    InvalidEndBound(usize),

    /// Returned when `BlobHeader` serialization fails. Contains the error message from the underlying serialization library.
    BlobHeaderSerializationFailed(String),
    /// Returned when `BlobHeader` deserialization fails. Contains the error message from the underlying deserialization library.
    BlobHeaderDeserializationFailed(String),

    /// Returned when `ProofCarryingChunk` serialization fails. Contains the error message from the underlying serialization library.
    ProofCarryingChunkSerializationFailed(String),
    /// Returned when `ProofCarryingChunk` deserialization fails. Contains the error message from the underlying deserialization library.
    ProofCarryingChunkDeserializationFailed(String),

    /// Returned when attempting to add a chunk to a `RepairingChunkSet` that is already ready for repair. Contains the chunkset ID.
    ChunksetReadyToRepair(usize),
    /// Returned when attempting to repair a `RepairingChunkSet` that is not yet ready. Contains the chunkset ID.
    ChunksetNotYetReadyToRepair(usize),
    /// Returned when attempting to add a chunk to a `RepairingChunkSet` that has already been repaired. Contains the chunkset ID.
    ChunksetAlreadyRepaired(usize),
    /// Returned when `RepairingChunkSet` fails to repair its data. Contains the chunkset ID and an error message.
    ChunksetRepairingFailed(usize, String),

    /// Returned when an invalid erasure-coded share ID is provided. Contains the invalid share ID.
    InvalidErasureCodedShareId(usize),
    /// Returned when an invalid chunkset ID is provided. Contains the invalid chunkset ID and the total number of chunksets.
    InvalidChunksetId(usize, usize),
    /// Returned when creating a `ChunkSet` with data of an invalid size. Contains the provided size.
    InvalidChunksetSize(usize),
    /// Returned when a chunk contains metadata (e.g., chunkset ID) that does not match the expected context. Contains the chunkset ID.
    InvalidChunkMetadata(usize),
    /// Returned when a `ProofCarryingChunk` fails its Merkle proof validation. Contains the chunkset ID.
    InvalidProofInChunk(usize),
    /// Returned when decoding a chunk fails during the repair process. Contains the chunkset ID and an error message.
    ChunkDecodingFailed(usize, String),

    /// Returned when attempting to build a Merkle tree with no leaf nodes.
    NoLeafNodesToBuildMerkleTreeOn,
    /// Returned when a Merkle tree operation specifies an invalid leaf node index. Contains the invalid index and the total number of leaves.
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
