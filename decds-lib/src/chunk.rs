use crate::{chunkset::ChunkSet, consts::DECDS_BINCODE_CONFIG, errors::DecdsError, merkle_tree::MerkleTree};
use serde::{Deserialize, Serialize};

/// Represents a fixed-size (1MB = 2^20 bytes) data chunk within a chunkset.
/// It contains metadata about its origin and the erasure-coded data.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub(crate) struct Chunk {
    chunkset_id: usize,
    chunk_id: usize,
    offset: usize,
    erasure_coded_data: Vec<u8>,
}

impl Chunk {
    pub const SIZE: usize = 1usize << 20;

    /// Creates a new `Chunk` instance.
    ///
    /// # Arguments
    ///
    /// * `chunkset_id` - The ID of the chunkset this chunk belongs to.
    /// * `chunk_id` - The global ID of this chunk.
    /// * `offset` - The starting byte offset of the chunkset within the original blob data.
    /// * `erasure_coded_data` - The erasure-coded data payload of the chunk.
    ///
    /// # Returns
    ///
    /// Returns a new `Chunk` instance.
    pub fn new(chunkset_id: usize, chunk_id: usize, offset: usize, erasure_coded_data: Vec<u8>) -> Self {
        Chunk {
            chunkset_id,
            chunk_id,
            offset,
            erasure_coded_data,
        }
    }

    /// Computes the BLAKE3 digest of the chunk, based on its metadata and erasure-coded data.
    ///
    /// # Returns
    ///
    /// A `blake3::Hash` representing the digest of the chunk.
    pub fn digest(&self) -> blake3::Hash {
        blake3::Hasher::new()
            .update(&self.chunkset_id.to_le_bytes())
            .update(&self.chunk_id.to_le_bytes())
            .update(&self.erasure_coded_data)
            .finalize()
    }
}

/// Represents a `Chunk` augmented with a Merkle proof of its inclusion in the original blob.
/// This structure is used for verifiable data retrieval.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ProofCarryingChunk {
    chunk: Chunk,
    proof: Vec<blake3::Hash>,
}

impl ProofCarryingChunk {
    /// Creates a new `ProofCarryingChunk` instance.
    ///
    /// # Arguments
    ///
    /// * `chunk` - The underlying `Chunk` data.
    /// * `proof` - A `Vec<blake3::Hash>` representing the Merkle proof for this chunk within its chunkset.
    ///
    /// # Panics
    ///
    /// Panics if the `proof.len()` does not match `ChunkSet::PROOF_SIZE`.
    pub(crate) fn new(chunk: Chunk, proof: Vec<blake3::Hash>) -> Self {
        assert_eq!(proof.len(), ChunkSet::PROOF_SIZE);
        Self { chunk, proof }
    }

    /// Validates the inclusion of this chunk in the overall blob using the provided blob root commitment.
    ///
    /// This method verifies the Merkle proof against the blob's root commitment,
    /// assuming the proof contains the necessary elements to ascend to the blob root.
    ///
    /// # Arguments
    ///
    /// * `blob_commitment` - The `blake3::Hash` of the root of the Merkle tree for the entire blob.
    ///
    /// # Returns
    ///
    /// Returns `true` if the chunk's inclusion proof in the blob is valid, `false` otherwise.
    pub fn validate_inclusion_in_blob(&self, blob_commitment: blake3::Hash) -> bool {
        let leaf_index = self.chunk.chunk_id;
        let leaf_node = self.chunk.digest();

        MerkleTree::verify_proof(leaf_index, leaf_node, &self.proof, blob_commitment)
    }

    /// Validates the inclusion of this chunk within its specific chunkset using the provided chunkset root commitment.
    ///
    /// This method checks the Merkle proof against the chunkset's root commitment.
    ///
    /// # Arguments
    ///
    /// * `chunkset_commitment` - The `blake3::Hash` of the root of the Merkle tree for the chunkset this chunk belongs to.
    ///
    /// # Returns
    ///
    /// Returns `true` if the chunk's inclusion proof in its chunkset is valid, `false` otherwise.
    pub fn validate_inclusion_in_chunkset(&self, chunkset_commitment: blake3::Hash) -> bool {
        let leaf_index = self.chunk.chunk_id % ChunkSet::NUM_ERASURE_CODED_CHUNKS;
        let leaf_node = self.chunk.digest();

        MerkleTree::verify_proof(leaf_index, leaf_node, &self.proof[..ChunkSet::PROOF_SIZE], chunkset_commitment)
    }

    /// Returns the ID of the chunkset this chunk belongs to.
    ///
    /// # Returns
    ///
    /// The `usize` ID of the chunkset.
    pub fn get_chunkset_id(&self) -> usize {
        self.chunk.chunkset_id
    }

    /// Returns a reference to the erasure-coded data contained within the chunk.
    ///
    /// # Returns
    ///
    /// A slice `&[u8]` containing the erasure-coded data.
    pub fn get_erasure_coded_data(&self) -> &[u8] {
        self.chunk.erasure_coded_data.as_ref()
    }

    /// Returns the byte range (start, end) that this chunk covers within the original blob data.
    ///
    /// # Returns
    ///
    /// A tuple `(usize, usize)` representing the start and end byte offsets.
    pub fn get_blob_byte_range(&self) -> (usize, usize) {
        (self.chunk.offset, self.chunk.offset + ChunkSet::SIZE)
    }

    /// Appends additional Merkle proof hashes to the existing proof, typically for blob-level inclusion.
    ///
    /// This is used to extend a chunkset-level proof to a blob-level proof.
    ///
    /// # Arguments
    ///
    /// * `blob_proof` - A slice of `blake3::Hash` representing the proof to append.
    pub(crate) fn append_proof_to_blob_root(&mut self, blob_proof: &[blake3::Hash]) {
        self.proof.extend_from_slice(blob_proof);
    }

    /// Serializes the `ProofCarryingChunk` into a vector of bytes using `bincode`.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(Vec<u8>)` containing the serialized bytes if successful.
    /// - `Err(DecdsError::ProofCarryingChunkSerializationFailed)` if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecdsError> {
        bincode::serde::encode_to_vec(self, DECDS_BINCODE_CONFIG).map_err(|err| DecdsError::ProofCarryingChunkSerializationFailed(err.to_string()))
    }

    /// Deserializes a `ProofCarryingChunk` from a byte slice using `bincode`.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The byte slice from which to deserialize the chunk.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok((Self, usize))` containing the deserialized `ProofCarryingChunk` and the number of bytes read if successful.
    /// - `Err(DecdsError::ProofCarryingChunkDeserializationFailed)` if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), DecdsError> {
        bincode::serde::decode_from_slice::<ProofCarryingChunk, bincode::config::Configuration>(bytes, DECDS_BINCODE_CONFIG)
            .map_err(|err| DecdsError::ProofCarryingChunkDeserializationFailed(err.to_string()))
    }
}
