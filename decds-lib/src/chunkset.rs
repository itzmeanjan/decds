use crate::{
    chunk::{self, Chunk},
    consts::DECDS_NUM_ERASURE_CODED_SHARES,
    errors::DecdsError,
    merkle_tree::MerkleTree,
};

/// Represents a fixed set (= 16) of erasure-coded chunks, along with its Merkle root commitment.
/// This structure is used for encoding a fixed size (10MB = 10 * 2^20 bytes) portion of the original
/// blob data into `NUM_ERASURE_CODED_CHUNKS` (= 16) erasure-coded verifiable chunks, each carrying
/// a merkle proof of inclusion in both this chunkset and the blob.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ChunkSet {
    commitment: blake3::Hash,
    chunks: Vec<chunk::ProofCarryingChunk>,
}

impl ChunkSet {
    pub const NUM_ORIGINAL_CHUNKS: usize = 10;
    pub const BYTE_LENGTH: usize = Self::NUM_ORIGINAL_CHUNKS * Chunk::BYTE_LENGTH;
    pub const NUM_ERASURE_CODED_CHUNKS: usize = DECDS_NUM_ERASURE_CODED_SHARES;
    pub const PROOF_SIZE: usize = usize::ilog2(Self::NUM_ERASURE_CODED_CHUNKS) as usize;

    /// Creates a new `ChunkSet` by taking a fixed sized block of data, splits into 10 equal sized chunks,
    /// each of 1MB, RLNC encoding them into 16 erasure-coded chunks, and building a Merkle tree over these chunks.
    ///
    /// # Arguments
    ///
    /// * `chunkset_id` - The unique identifier for this chunkset.
    /// * `data` - The raw data (10MB) to be erasure-coded into chunks for this chunkset.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(ChunkSet)` containing the newly created `ChunkSet` if successful.
    /// - `Err(DecdsError::InvalidChunksetSize)` if the `data` length does not match `ChunkSet::BYTE_LENGTH`.
    pub fn new(chunkset_id: usize, data: Vec<u8>) -> Result<ChunkSet, DecdsError> {
        if data.len() != Self::BYTE_LENGTH {
            return Err(DecdsError::InvalidChunksetSize(data.len()));
        }

        let mut rng = rand::rng();
        let encoder = unsafe { rlnc::full::encoder::Encoder::new(data, Self::NUM_ORIGINAL_CHUNKS).unwrap_unchecked() };

        let chunks = (0..Self::NUM_ERASURE_CODED_CHUNKS)
            .map(|i| {
                let chunk_id = chunkset_id * Self::NUM_ERASURE_CODED_CHUNKS + i;
                let erasure_coded_data = encoder.code(&mut rng);

                chunk::Chunk::new(chunkset_id, chunk_id, erasure_coded_data)
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

    /// Appends a Merkle proof for the blob inclusion to all `ProofCarryingChunk`s within this `ChunkSet`.
    /// This extends the chunkset-level proof to a blob-level proof for each chunk.
    ///
    /// # Arguments
    ///
    /// * `blob_proof` - A slice of `blake3::Hash` representing the Merkle path from the chunkset's
    ///   root commitment to the blob's root commitment.
    pub(crate) fn append_blob_inclusion_proof(&mut self, blob_proof: &[blake3::Hash]) {
        if !blob_proof.is_empty() {
            self.chunks.iter_mut().for_each(|chunk| chunk.append_proof_to_blob_root(blob_proof));
        }
    }
}

/// A structure designed to help incrementally reconstruct the original data of a `ChunkSet`
/// by collecting enough erasure-coded chunks, verifying their integrity, and performing RLNC decoding.
pub struct RepairingChunkSet {
    chunkset_id: usize,
    commitment: blake3::Hash,
    decoder: rlnc::full::decoder::Decoder,
}

impl RepairingChunkSet {
    /// The padded byte length of individual chunks used in RLNC encoding.
    /// It ensures that the total chunkset size is a multiple of `NUM_ORIGINAL_CHUNKS`,
    /// after appending a single byte end-of-data marker.
    const PADDED_CHUNK_BYTE_LEN: usize = (ChunkSet::BYTE_LENGTH + 1).div_ceil(ChunkSet::NUM_ORIGINAL_CHUNKS);

    /// Creates a new `RepairingChunkSet` instance.
    ///
    /// # Arguments
    ///
    /// * `chunkset_id` - The ID of the chunkset being repaired.
    /// * `commitment` - The expected Merkle root commitment of the chunkset, used for validating chunk inclusion in chunkset.
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
    /// The chunk's inclusion proof in this chunkset is verified against the `commitment` stored in `RepairingChunkSet`.
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
    /// This method is intended for use when proof validation has already occurred.
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
    /// - `Err(DecdsError::ChunksetReadyToRepair)` if the chunkset is ready to repair, no more chunks are required. Just call `repair`.
    /// - `Err(DecdsError::ChunkDecodingFailed)` if the underlying RLNC decoding operation fails.
    pub fn add_chunk_unvalidated(&mut self, chunk: &chunk::ProofCarryingChunk) -> Result<(), DecdsError> {
        if self.chunkset_id != chunk.get_chunkset_id() {
            return Err(DecdsError::InvalidChunkMetadata(chunk.get_chunkset_id()));
        }
        if self.is_ready_to_repair() {
            return Err(DecdsError::ChunksetReadyToRepair(self.chunkset_id));
        }

        self.decoder
            .decode(chunk.get_erasure_coded_data())
            .map_err(|err| DecdsError::ChunkDecodingFailed(chunk.get_chunkset_id(), err.to_string()))
    }

    /// Checks if enough useful erasure-coded chunks have been collected to repair the original data for this chunkset.
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
        DecdsError,
        chunk::ProofCarryingChunk,
        chunkset::{ChunkSet, RepairingChunkSet},
        merkle_tree::tests::flip_a_bit,
    };
    use rand::{Rng, seq::SliceRandom};

    fn flip_a_single_bit_in_proof_carrying_chunk<R: Rng + ?Sized>(mut chunk_bytes: Vec<u8>, rng: &mut R) -> Vec<u8> {
        if chunk_bytes.is_empty() {
            return chunk_bytes;
        }

        let random_byte_index = rng.random_range(0..chunk_bytes.len());
        let random_bit_index = rng.random_range(0..u8::BITS) as usize;

        chunk_bytes[random_byte_index] = flip_a_bit(chunk_bytes[random_byte_index], random_bit_index);
        chunk_bytes
    }

    #[test]
    fn prop_test_erasure_coding_chunks_and_validating_proofs_work() {
        const NUM_TEST_ITERATIONS: usize = 10;
        let mut rng = rand::rng();

        (0..NUM_TEST_ITERATIONS).for_each(|_| {
            let data = (0..ChunkSet::BYTE_LENGTH).map(|_| rng.random()).collect::<Vec<u8>>();
            let chunkset = ChunkSet::new(0, data).expect("Must be able to build erasure-coded ChunkSet");

            for i in 0..ChunkSet::NUM_ERASURE_CODED_CHUNKS {
                let chunk = chunkset.get_chunk(i).expect("Must be able to lookup chunk by id");
                assert!(chunk.validate_inclusion_in_chunkset(chunkset.get_root_commitment()));

                let chunk_bytes = chunk.to_bytes().expect("Must be able to serialize proof-carrying chunk as bytes");
                let bit_flipped_chunk_bytes = flip_a_single_bit_in_proof_carrying_chunk(chunk_bytes, &mut rng);

                match ProofCarryingChunk::from_bytes(&bit_flipped_chunk_bytes) {
                    Ok((bit_flipped_chunk, _)) => assert!(!bit_flipped_chunk.validate_inclusion_in_chunkset(chunkset.get_root_commitment())),
                    Err(e) => assert!(e.to_string().starts_with("failed to deserialize proof carrying chunk: ")),
                }
            }
        });
    }

    #[test]
    fn prop_test_repairing_erasure_coded_chunks_work() {
        const NUM_TEST_ITERATIONS: usize = 10;
        let mut rng = rand::rng();

        (0..NUM_TEST_ITERATIONS).for_each(|_| {
            let data = (0..ChunkSet::BYTE_LENGTH).map(|_| rng.random()).collect::<Vec<u8>>();
            let data_copy = data.clone();

            let chunkset = ChunkSet::new(0, data).expect("Must be able to build erasure-coded ChunkSet");
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

    #[test]
    fn test_chunkset_new_invalid_size() {
        let data_too_small = vec![0u8; ChunkSet::BYTE_LENGTH - 1];
        let data_too_large = vec![0u8; ChunkSet::BYTE_LENGTH + 1];

        assert_eq!(
            ChunkSet::new(0, data_too_small),
            Err(DecdsError::InvalidChunksetSize(ChunkSet::BYTE_LENGTH - 1))
        );
        assert_eq!(
            ChunkSet::new(0, data_too_large),
            Err(DecdsError::InvalidChunksetSize(ChunkSet::BYTE_LENGTH + 1))
        );
    }

    #[test]
    fn test_chunkset_get_chunk_out_of_bounds() {
        let mut rng = rand::rng();

        let data = (0..ChunkSet::BYTE_LENGTH).map(|_| rng.random()).collect::<Vec<u8>>();
        let chunkset = ChunkSet::new(0, data).expect("Must be able to build erasure-coded ChunkSet");

        assert_eq!(
            chunkset.get_chunk(ChunkSet::NUM_ERASURE_CODED_CHUNKS),
            Err(DecdsError::InvalidErasureCodedShareId(ChunkSet::NUM_ERASURE_CODED_CHUNKS))
        );
        assert_eq!(
            chunkset.get_chunk(ChunkSet::NUM_ERASURE_CODED_CHUNKS + 100),
            Err(DecdsError::InvalidErasureCodedShareId(ChunkSet::NUM_ERASURE_CODED_CHUNKS + 100))
        );
    }

    #[test]
    fn test_repairing_chunkset_add_chunk_after_ready_to_repair() {
        let mut rng = rand::rng();

        let data = (0..ChunkSet::BYTE_LENGTH).map(|_| rng.random()).collect::<Vec<u8>>();
        let chunkset = ChunkSet::new(0, data.clone()).expect("Must be able to build erasure-coded ChunkSet");
        let mut repairing_chunkset = RepairingChunkSet::new(0, chunkset.get_root_commitment());

        let mut chunk_idx = 0;
        while !repairing_chunkset.is_ready_to_repair() {
            let chunk = chunkset.get_chunk(chunk_idx).expect("Must be able to lookup chunk by id");
            repairing_chunkset.add_chunk(chunk).expect("Must be able to add valid chunk");

            chunk_idx += 1;
        }

        while chunk_idx < ChunkSet::NUM_ERASURE_CODED_CHUNKS {
            let chunk = chunkset.get_chunk(chunk_idx).expect("Must be able to lookup chunk by id");
            assert_eq!(repairing_chunkset.add_chunk(chunk), Err(DecdsError::ChunksetReadyToRepair(0)));

            chunk_idx += 1;
        }

        let repaired_chunkset = repairing_chunkset.repair().expect("Must be able to repair chunkset");
        assert_eq!(repaired_chunkset, data);
    }

    #[test]
    fn test_repairing_chunkset_repair_not_ready() {
        let mut rng = rand::rng();

        let data = (0..ChunkSet::BYTE_LENGTH).map(|_| rng.random()).collect::<Vec<u8>>();
        let chunkset = ChunkSet::new(0, data).expect("Must be able to build erasure-coded ChunkSet");
        let mut repairing_chunkset = RepairingChunkSet::new(0, chunkset.get_root_commitment());

        // Add fewer than NUM_ORIGINAL_CHUNKS chunks
        for i in 0..(ChunkSet::NUM_ORIGINAL_CHUNKS - 1) {
            repairing_chunkset.add_chunk(chunkset.get_chunk(i).unwrap()).unwrap();
        }

        assert!(!repairing_chunkset.is_ready_to_repair());
        assert_eq!(repairing_chunkset.repair(), Err(DecdsError::ChunksetNotYetReadyToRepair(0)));
    }
}
