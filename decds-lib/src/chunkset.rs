use crate::{
    chunk::{self, Chunk},
    consts::DECDS_NUM_ERASURE_CODED_SHARES,
    errors::DecdsError,
    merkle_tree::MerkleTree,
};

/// Represents a set of erasure-coded chunks, along with its Merkle root commitment.
/// This structure is used for encoding a fixed size (10MB = 10 * 2^20 bytes) portion of the original blob data
/// into `NUM_ERASURE_CODED_CHUNKS` (= 16) erasure-coded verifiable chunks.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ChunkSet {
    commitment: blake3::Hash,
    chunks: Vec<chunk::ProofCarryingChunk>,
}

impl ChunkSet {
    /// The fixed size of a `ChunkSet` in bytes (10MB).
    pub const SIZE: usize = 10 * Chunk::SIZE;

    /// The number of original data chunks within a `ChunkSet` before erasure coding.
    pub const NUM_ORIGINAL_CHUNKS: usize = 10;

    /// The total number of erasure-coded chunks generated from a `ChunkSet`.
    pub const NUM_ERASURE_CODED_CHUNKS: usize = DECDS_NUM_ERASURE_CODED_SHARES;

    /// The number of BLAKE3 digests required for a Merkle proof within a `ChunkSet`.
    pub const PROOF_SIZE: usize = usize::ilog2(Self::NUM_ERASURE_CODED_CHUNKS) as usize;

    /// Creates a new `ChunkSet` by taking a fixed sized block of data, splits into 10 equal sized chunks,
    /// RLNC encoding them into 16 erasure-coded chunks, and building a Merkle tree over these chunks.
    ///
    /// # Arguments
    ///
    /// * `offset` - The starting byte offset of this chunkset within the original blob data.
    /// * `chunkset_id` - The unique identifier for this chunkset.
    /// * `data` - The raw data (10MB) to be encoded into chunks for this chunkset.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(ChunkSet)` containing the newly created `ChunkSet` if successful.
    /// - `Err(DecdsError::InvalidChunksetSize)` if the `data` length does not match `ChunkSet::SIZE`.
    pub fn new(offset: usize, chunkset_id: usize, data: Vec<u8>) -> Result<ChunkSet, DecdsError> {
        if data.len() != Self::SIZE {
            return Err(DecdsError::InvalidChunksetSize(data.len()));
        }

        let mut rng = rand::rng();
        let encoder = unsafe { rlnc::full::encoder::Encoder::new(data, Self::NUM_ORIGINAL_CHUNKS).unwrap_unchecked() };

        let chunks = (0..Self::NUM_ERASURE_CODED_CHUNKS)
            .map(|i| {
                let chunk_id = chunkset_id * Self::NUM_ERASURE_CODED_CHUNKS + i;
                let erasure_coded_data = encoder.code(&mut rng);

                chunk::Chunk::new(chunkset_id, chunk_id, offset, erasure_coded_data)
            })
            .collect::<Vec<Chunk>>();

        let merkle_leaves = chunks.iter().map(|chunk| chunk.digest()).collect::<Vec<blake3::Hash>>();
        let merkle_tree = unsafe { MerkleTree::new(merkle_leaves).unwrap_unchecked() };

        let commitment = merkle_tree.get_root_commitment();

        let proof_carrying_chunks = chunks
            .into_iter()
            .enumerate()
            .map(|(leaf_idx, chunk)| chunk::ProofCarryingChunk::new(chunk, unsafe { merkle_tree.generate_proof(leaf_idx).unwrap_unchecked() }))
            .collect::<Vec<chunk::ProofCarryingChunk>>();

        Ok(ChunkSet {
            commitment,
            chunks: proof_carrying_chunks,
        })
    }

    /// Returns the Merkle root commitment of this `ChunkSet`.
    ///
    /// # Returns
    ///
    /// A `blake3::Hash` representing the root commitment.
    pub fn get_root_commitment(&self) -> blake3::Hash {
        self.commitment
    }

    /// Retrieves a specific `ProofCarryingChunk` from the `ChunkSet` by its local chunk ID.
    ///
    /// # Arguments
    ///
    /// * `chunk_id` - The local ID (`>= 0 && < Self::NUM_ERASURE_CODED_CHUNKS`) of the chunk to retrieve within this chunkset.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(&chunk::ProofCarryingChunk)` containing a reference to the chunk if found.
    /// - `Err(DecdsError::InvalidErasureCodedShareId)` if `chunk_id` is out of bounds for this chunkset.
    pub fn get_chunk(&self, chunk_id: usize) -> Result<&chunk::ProofCarryingChunk, DecdsError> {
        self.chunks.get(chunk_id).ok_or(DecdsError::InvalidErasureCodedShareId(chunk_id))
    }

    /// Appends a Merkle proof for blob inclusion to all `ProofCarryingChunk`s within this `ChunkSet`.
    /// This extends the chunkset-level proof to a blob-level proof for each chunk.
    ///
    /// # Arguments
    ///
    /// * `blob_proof` - A slice of `blake3::Hash` representing the Merkle path from the chunkset's
    ///   root commitment to the blob's root commitment.
    pub fn append_blob_inclusion_proof(&mut self, blob_proof: &[blake3::Hash]) {
        if !blob_proof.is_empty() {
            self.chunks.iter_mut().for_each(|chunk| chunk.append_proof_to_blob_root(blob_proof));
        }
    }
}

/// A structure designed to reconstruct the original data of a `ChunkSet`
/// by collecting erasure-coded chunks, verifying their integrity, and performing RLNC decoding.
pub struct RepairingChunkSet {
    chunkset_id: usize,
    commitment: blake3::Hash,
    decoder: rlnc::full::decoder::Decoder,
}

impl RepairingChunkSet {
    /// The padded byte length for individual chunks used in RLNC decoding.
    /// It ensures that the total chunkset size is a multiple of `NUM_ORIGINAL_CHUNKS`,
    /// after appending a single byte end-of-data marker.
    const PADDED_CHUNK_BYTE_LEN: usize = (ChunkSet::SIZE + 1).div_ceil(ChunkSet::NUM_ORIGINAL_CHUNKS);

    /// Creates a new `RepairingChunkSet` instance.
    ///
    /// # Arguments
    ///
    /// * `chunkset_id` - The ID of the chunkset being repaired.
    /// * `commitment` - The expected Merkle root commitment of the chunkset, used for chunk validation.
    ///
    /// # Returns
    ///
    /// A new `RepairingChunkSet` instance.
    pub fn new(chunkset_id: usize, commitment: blake3::Hash) -> Self {
        RepairingChunkSet {
            chunkset_id,
            commitment,
            decoder: unsafe { rlnc::full::decoder::Decoder::new(Self::PADDED_CHUNK_BYTE_LEN, ChunkSet::NUM_ORIGINAL_CHUNKS).unwrap_unchecked() },
        }
    }

    /// Adds a `ProofCarryingChunk` to the `RepairingChunkSet` after validating its Merkle proof.
    /// The chunk's inclusion proof in its chunkset is verified against the `commitment` stored in `RepairingChunkSet`.
    ///
    /// # Arguments
    ///
    /// * `chunk` - The `ProofCarryingChunk` to add.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(())` if the chunk is successfully added and validated.
    /// - `Err(DecdsError::InvalidProofInChunk)` if the chunk's inclusion proof is invalid for this chunkset.
    /// - `Err(DecdsError::InvalidChunkMetadata)` if the chunk's `chunkset_id` does not match this `RepairingChunkSet`.
    /// - `Err(DecdsError::ChunkDecodingFailed)` if the underlying RLNC decoding operation fails.
    pub fn add_chunk(&mut self, chunk: &chunk::ProofCarryingChunk) -> Result<(), DecdsError> {
        if chunk.validate_inclusion_in_chunkset(self.commitment) {
            self.add_chunk_unvalidated(chunk)
        } else {
            Err(DecdsError::InvalidProofInChunk(chunk.get_chunkset_id()))
        }
    }

    /// Adds a `ProofCarryingChunk` to the `RepairingChunkSet` without validating its Merkle proof.
    /// This method is intended for internal use when proof validation has already occurred.
    ///
    /// # Arguments
    ///
    /// * `chunk` - The `ProofCarryingChunk` to add.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(())` if the chunk is successfully added.
    /// - `Err(DecdsError::InvalidChunkMetadata)` if the chunk's `chunkset_id` does not match this `RepairingChunkSet`.
    /// - `Err(DecdsError::ChunkDecodingFailed)` if the underlying RLNC decoding operation fails.
    pub fn add_chunk_unvalidated(&mut self, chunk: &chunk::ProofCarryingChunk) -> Result<(), DecdsError> {
        if self.chunkset_id != chunk.get_chunkset_id() {
            return Err(DecdsError::InvalidChunkMetadata(chunk.get_chunkset_id()));
        }

        self.decoder
            .decode(chunk.get_erasure_coded_data())
            .map_err(|err| DecdsError::ChunkDecodingFailed(chunk.get_chunkset_id(), err.to_string()))
    }

    /// Checks if enough useful chunks have been collected to repair the original data for this chunkset.
    ///
    /// # Returns
    ///
    /// `true` if the chunkset is ready to be repaired, `false` otherwise.
    pub fn is_ready_to_repair(&self) -> bool {
        self.decoder.is_already_decoded()
    }

    /// Repairs the original data of the chunkset if enough chunks have been collected.
    /// This consumes the `RepairingChunkSet` as the decoding process is final.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(Vec<u8>)` containing the repaired original data if successful.
    /// - `Err(DecdsError::ChunksetNotYetReadyToRepair)` if not enough chunks have been added yet.
    /// - `Err(DecdsError::ChunksetRepairingFailed)` if an error occurs during the RLNC decoding process.
    pub fn repair(self) -> Result<Vec<u8>, DecdsError> {
        if self.is_ready_to_repair() {
            self.decoder
                .get_decoded_data()
                .map_err(|err| DecdsError::ChunksetRepairingFailed(self.chunkset_id, format!("RLNC Decoding error: {}", err)))
        } else {
            Err(DecdsError::ChunksetNotYetReadyToRepair(self.chunkset_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        chunk::ProofCarryingChunk,
        chunkset::{ChunkSet, RepairingChunkSet},
    };
    use rand::{Rng, seq::SliceRandom};

    #[test]
    fn prop_test_erasure_coding_chunks_work() {
        const NUM_TEST_ITERATIONS: usize = 10;
        let mut rng = rand::rng();

        (0..NUM_TEST_ITERATIONS).for_each(|_| {
            let data = (0..ChunkSet::SIZE).map(|_| rng.random()).collect::<Vec<u8>>();
            let chunkset = ChunkSet::new(0, 0, data).expect("Must be able to build erasure-coded ChunkSet");

            for i in 0..ChunkSet::NUM_ERASURE_CODED_CHUNKS {
                assert!(
                    chunkset
                        .get_chunk(i)
                        .expect("Must be able to lookup chunk by id")
                        .validate_inclusion_in_chunkset(chunkset.get_root_commitment())
                );
            }
        });
    }

    #[test]
    fn prop_test_repairing_erasure_coded_chunks_work() {
        const NUM_TEST_ITERATIONS: usize = 10;
        let mut rng = rand::rng();

        (0..NUM_TEST_ITERATIONS).for_each(|_| {
            let data = (0..ChunkSet::SIZE).map(|_| rng.random()).collect::<Vec<u8>>();
            let data_copy = data.clone();

            let chunkset = ChunkSet::new(0, 0, data).expect("Must be able to build erasure-coded ChunkSet");
            let mut repairing_chunkset = RepairingChunkSet::new(0, chunkset.get_root_commitment());

            let mut chunks = (0..ChunkSet::NUM_ERASURE_CODED_CHUNKS)
                .map(|i| chunkset.get_chunk(i).expect("Must be able to lookup chunk by id"))
                .collect::<Vec<&ProofCarryingChunk>>();
            chunks.shuffle(&mut rng);

            let mut chunk_idx = 0;
            while !repairing_chunkset.is_ready_to_repair() {
                repairing_chunkset.add_chunk(chunks[chunk_idx]).unwrap();
                chunk_idx += 1;
            }

            let repaired_data = repairing_chunkset.repair().expect("Data must be reconstructed by this point!");
            assert_eq!(data_copy, repaired_data);
        });
    }
}
