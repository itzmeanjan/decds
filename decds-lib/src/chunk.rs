use crate::{chunkset::ChunkSet, consts::DECDS_BINCODE_CONFIG, errors::DecdsError, merkle_tree::MerkleTree};
use serde::{Deserialize, Serialize};

/// Represents a fixed-size (1MB = 2^20 bytes) data chunk within a chunkset in erasure-coded form.
/// It contains metadata about its origin and the RLNC erasure-coded data.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub(crate) struct Chunk {
    chunkset_id: usize,
    chunk_id: usize,
    erasure_coded_data: Vec<u8>,
}

impl Chunk {
    pub const BYTE_LENGTH: usize = 1usize << 20;

    /// Creates a new `Chunk` instance.
    ///
    /// # Arguments
    ///
    /// * `chunkset_id` - The ID of the chunkset this chunk belongs to.
    /// * `chunk_id` - The global ID of this chunk.
    /// * `erasure_coded_data` - The RLNC erasure-coded data payload of the chunk.
    ///
    /// # Returns
    ///
    /// Returns a new `Chunk` instance.
    pub fn new(chunkset_id: usize, chunk_id: usize, erasure_coded_data: Vec<u8>) -> Self {
        Chunk {
            chunkset_id,
            chunk_id,
            erasure_coded_data,
        }
    }

    /// Computes the BLAKE3 digest of the byte serialized representation of this chunk.
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
/// This structure is used for verifiable data retrieval and reconstruction.
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
    /// * `proof` - A `Vec<blake3::Hash>` representing the Merkle inclusion proof for this chunk within its chunkset.
    ///
    /// # Assumes
    ///
    /// That `proof.len()` equals to `ChunkSet::PROOF_SIZE`.
    pub(crate) fn new(chunk: Chunk, proof: Vec<blake3::Hash>) -> Self {
        Self { chunk, proof }
    }

    /// Validates the inclusion of this chunk in the overall blob using the provided blob root commitment.
    ///
    /// This method verifies the Merkle proof against the blob's root commitment,
    /// assuming the proof contains the necessary sibling nodes to ascend to the blob root.
    ///
    /// Meaning `Self::append_proof_to_blob_root()` needs to be called after `Self::new()` to extend
    /// the Merkle inclusion proof to the blob root level - only then one can validate inclusion of this
    /// chunk in the blob.
    ///
    /// # Arguments
    ///
    /// * `blob_commitment` - The `blake3::Hash` of the root of the Merkle tree for the entire blob.
    ///
    /// # Returns
    ///
    /// Returns `true` if the chunk's inclusion proof in the blob is valid, `false` otherwise.
    pub fn validate_inclusion_in_blob(&self, blob_commitment: blake3::Hash) -> bool {
        MerkleTree::verify_proof(self.get_global_chunk_id(), self.chunk.digest(), &self.proof, blob_commitment)
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
        MerkleTree::verify_proof(
            self.get_local_chunk_id(),
            self.chunk.digest(),
            &self.proof[..ChunkSet::PROOF_SIZE],
            chunkset_commitment,
        )
    }

    /// Returns the ID of the chunkset this chunk belongs to.
    pub fn get_chunkset_id(&self) -> usize {
        self.chunk.chunkset_id
    }

    /// Returns the global ID of the chunk.
    pub fn get_global_chunk_id(&self) -> usize {
        self.chunk.chunk_id
    }

    /// Returns the local ID of the chunk.
    pub fn get_local_chunk_id(&self) -> usize {
        self.chunk.chunk_id % ChunkSet::NUM_ERASURE_CODED_CHUNKS
    }

    /// Returns a reference to the erasure-coded data contained within the chunk.
    pub fn get_erasure_coded_data(&self) -> &[u8] {
        self.chunk.erasure_coded_data.as_ref()
    }

    /// Appends additional Merkle proof hashes to the existing proof, proving blob-level inclusion.
    ///
    /// This is used to extend a chunkset-level proof to a blob-level proof. You are supposed to call this
    /// function after `Self::new` is used to contruct a new proof-carrying chunk, which originally holds a
    /// proof of inclusion in the corresponding chunkset.
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

#[cfg(test)]
mod tests {
    use super::*;
    use blake3;
    use rand::Rng;

    #[test]
    fn test_chunk_digest() {
        let chunkset_id = 1;
        let chunk_id = 5;
        let erasure_coded_data = vec![1, 2, 3, 4, 5];

        let chunk = Chunk::new(chunkset_id, chunk_id, erasure_coded_data.clone());
        let computed_digest = chunk.digest();

        // Manually compute the expected digest
        let expected_digest = blake3::Hasher::new()
            .update(&chunkset_id.to_le_bytes())
            .update(&chunk_id.to_le_bytes())
            .update(&erasure_coded_data)
            .finalize();

        assert_eq!(computed_digest, expected_digest);

        // Test with different data to ensure digest changes
        let chunk2 = Chunk::new(chunkset_id, chunk_id, vec![6, 7, 8]);
        assert_ne!(chunk2.digest(), expected_digest);
    }

    #[test]
    fn test_proof_carrying_chunk_serialization_deserialization() {
        let mut rng = rand::rng();

        let chunkset_id = 0;
        let chunk_id = 5;
        let erasure_coded_data: Vec<u8> = (0..Chunk::BYTE_LENGTH).map(|_| rng.random()).collect();

        // Generate a proof with a length consistent with ChunkSet::PROOF_SIZE
        let proof_data = (0..ChunkSet::PROOF_SIZE)
            .map(|_| {
                let random_bytes: [u8; 32] = rng.random();
                blake3::Hash::from_bytes(random_bytes)
            })
            .collect::<Vec<blake3::Hash>>();

        let original_chunk = Chunk::new(chunkset_id, chunk_id, erasure_coded_data);
        let original_pcc = ProofCarryingChunk::new(original_chunk.clone(), proof_data.clone());

        // Test serialization
        let serialized_pcc_bytes = original_pcc.to_bytes().expect("Serialization failed");

        // Test deserialization
        let (deserialized_pcc, bytes_read) = ProofCarryingChunk::from_bytes(&serialized_pcc_bytes).expect("Deserialization failed");

        assert_eq!(original_pcc, deserialized_pcc);
        assert_eq!(serialized_pcc_bytes.len(), bytes_read);

        // Test deserialization with lesser bytes
        assert!(ProofCarryingChunk::from_bytes(&serialized_pcc_bytes[..(serialized_pcc_bytes.len() / 2)]).is_err());
    }
}
