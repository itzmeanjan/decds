use crate::{chunkset::ChunkSet, consts::DECDS_BINCODE_CONFIG, errors::DECDSError, merkle_tree::MerkleTree};
use serde::{Deserialize, Serialize};

/// Fixed size = 1MB = 2^20 bytes
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct Chunk {
    chunkset_id: usize,
    chunk_id: usize,
    offset: usize,
    erasure_coded_data: Vec<u8>,
    chunkset_digest: blake3::Hash,
}

impl Chunk {
    pub const SIZE: usize = 1usize << 20;

    pub fn new(chunkset_id: usize, chunk_id: usize, offset: usize, erasure_coded_data: Vec<u8>, chunkset_digest: blake3::Hash) -> Self {
        Chunk {
            chunkset_id,
            chunk_id,
            offset,
            erasure_coded_data,
            chunkset_digest,
        }
    }

    pub fn digest(&self) -> blake3::Hash {
        blake3::Hasher::new()
            .update(&self.chunk_id.to_le_bytes())
            .update(&self.erasure_coded_data)
            .update(self.chunkset_digest.as_bytes())
            .finalize()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProofCarryingChunk {
    chunk: Chunk,
    proof: Vec<blake3::Hash>,
}

impl ProofCarryingChunk {
    pub(crate) fn new(chunk: Chunk, proof: Vec<blake3::Hash>) -> Self {
        assert_eq!(proof.len(), ChunkSet::PROOF_SIZE);
        Self { chunk, proof }
    }

    pub fn validate_inclusion_in_blob(&self, blob_commitment: blake3::Hash) -> bool {
        let leaf_index = self.chunk.chunk_id;
        let leaf_node = self.chunk.digest();

        MerkleTree::verify_proof(leaf_index, leaf_node, &self.proof, blob_commitment)
    }

    pub fn validate_inclusion_in_chunkset(&self, chunkset_commitment: blake3::Hash) -> bool {
        let leaf_index = self.chunk.chunk_id % ChunkSet::NUM_ERASURE_CODED_CHUNKS;
        let leaf_node = self.chunk.digest();

        MerkleTree::verify_proof(leaf_index, leaf_node, &self.proof[..ChunkSet::PROOF_SIZE], chunkset_commitment)
    }

    pub fn get_chunkset_id(&self) -> usize {
        self.chunk.chunkset_id
    }

    pub fn get_erasure_coded_data(&self) -> &[u8] {
        self.chunk.erasure_coded_data.as_ref()
    }

    pub fn get_blob_byte_range(&self) -> (usize, usize) {
        (self.chunk.offset, self.chunk.offset + ChunkSet::SIZE)
    }

    pub(crate) fn append_proof_to_blob_root(&mut self, blob_proof: &[blake3::Hash]) {
        self.proof.extend_from_slice(blob_proof);
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DECDSError> {
        bincode::serde::encode_to_vec(self, DECDS_BINCODE_CONFIG).map_err(|err| DECDSError::ProofCarryingChunkSerializationFailed(err.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), DECDSError> {
        bincode::serde::decode_from_slice::<ProofCarryingChunk, bincode::config::Configuration>(bytes, DECDS_BINCODE_CONFIG)
            .map_err(|err| DECDSError::ProofCarryingChunkDeserializationFailed(err.to_string()))
    }
}
