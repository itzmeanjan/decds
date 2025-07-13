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
        merkle_tree::{MerkleTree, tests::flip_a_bit},
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
    fn test_chunkset_append_blob_inclusion_proof_unit() {
        let mut rng = rand::rng();

        // 1. Create a base ChunkSet
        let data_for_chunkset = (0..ChunkSet::BYTE_LENGTH).map(|_| rng.random()).collect::<Vec<u8>>();
        let mut chunkset_1 = ChunkSet::new(1, data_for_chunkset.clone()).expect("Must be able to build erasure-coded ChunkSet");
        let chunkset_1_commitment = chunkset_1.get_root_commitment();

        // 2. Create mock blob-level Merkle tree leaves (chunkset roots)
        // This mock tree will have chunkset_1_commitment at index 1
        let mock_blob_leaves = vec![
            blake3::hash(b"dummy_chunkset_root_0"), // Leaf 0
            chunkset_1_commitment,                  // Leaf 1 (our chunkset_1's commitment)
            blake3::hash(b"dummy_chunkset_root_2"), // Leaf 2
            blake3::hash(b"dummy_chunkset_root_3"), // Leaf 3
        ];

        // 3. Build a mock blob MerkleTree
        let mock_blob_merkle_tree = MerkleTree::new(mock_blob_leaves).expect("Must be able to build mock blob Merkle Tree");
        let mock_blob_root_commitment = mock_blob_merkle_tree.get_root_commitment();

        // 4. Generate the blob_proof for chunkset_1_commitment at its index (1)
        let blob_proof_for_chunkset_1 = mock_blob_merkle_tree.generate_proof(1).expect("Must be able to generate blob proof");

        // Take a chunk for validation BEFORE appending the blob proof
        let chunk_before_append = chunkset_1.get_chunk(0).unwrap().clone();
        // It should NOT validate against the blob root commitment yet because it doesn't have the blob proof
        assert!(!chunk_before_append.validate_inclusion_in_blob(mock_blob_root_commitment));

        // 5. Call the method under test: append_blob_inclusion_proof
        chunkset_1.append_blob_inclusion_proof(&blob_proof_for_chunkset_1);

        // 6. Verify the outcome using a chunk from the modified chunkset
        let chunk_after_append = chunkset_1.get_chunk(0).unwrap();

        // 7. Assert that validate_inclusion_in_blob now returns true
        assert!(chunk_after_append.validate_inclusion_in_blob(mock_blob_root_commitment));

        // Test with an empty blob_proof (should not change anything, i.e., validation still works)
        chunkset_1.append_blob_inclusion_proof(&[]);
        let chunk_after_empty_append = chunkset_1.get_chunk(0).unwrap();
        assert!(chunk_after_empty_append.validate_inclusion_in_blob(mock_blob_root_commitment));

        // Negative test: Tamper the proof and verify it fails
        let mut tampered_blob_proof = blob_proof_for_chunkset_1.clone();
        if !tampered_blob_proof.is_empty() {
            // Flip a bit in the first hash of the proof to tamper it
            let random_byte_index = rng.random_range(0..blake3::OUT_LEN);
            let random_bit_index = rng.random_range(0..u8::BITS) as usize;

            let mut bytes = [0u8; blake3::OUT_LEN];
            bytes.copy_from_slice(tampered_blob_proof[0].as_bytes());
            bytes[random_byte_index] = flip_a_bit(bytes[random_byte_index], random_bit_index);

            tampered_blob_proof[0] = blake3::Hash::from_bytes(bytes);
        }

        let mut chunkset_1 = ChunkSet::new(1, data_for_chunkset).expect("Must be able to build erasure-coded ChunkSet");
        chunkset_1.append_blob_inclusion_proof(&tampered_blob_proof);

        let tampered_chunk = chunkset_1.get_chunk(0).unwrap();
        assert!(!tampered_chunk.validate_inclusion_in_blob(mock_blob_root_commitment));
    }

    #[test]
    fn test_repairing_chunkset_new() {
        let mut rng = rand::rng();

        let data = (0..ChunkSet::BYTE_LENGTH).map(|_| rng.random()).collect::<Vec<u8>>();
        let chunkset = ChunkSet::new(0, data).expect("Must be able to build erasure-coded ChunkSet");
        let commitment = chunkset.get_root_commitment();
        let chunkset_id = 0;

        let repairing_chunkset = RepairingChunkSet::new(chunkset_id, commitment);

        assert_eq!(repairing_chunkset.chunkset_id, chunkset_id);
        assert_eq!(repairing_chunkset.commitment, commitment);
        assert!(!repairing_chunkset.is_ready_to_repair());
    }

    #[test]
    fn test_repairing_chunkset_add_chunk_invalid_proof_in_chunk() {
        let mut rng = rand::rng();

        let data = (0..ChunkSet::BYTE_LENGTH).map(|_| rng.random()).collect::<Vec<u8>>();
        let chunkset = ChunkSet::new(0, data).expect("Must be able to build erasure-coded ChunkSet");

        // Create a repairing chunkset with a *different* commitment
        let tampered_commitment = blake3::hash(b"tampered_commitment");
        let mut repairing_chunkset = RepairingChunkSet::new(0, tampered_commitment);

        // Get a valid chunk from the original chunkset
        let valid_chunk = chunkset.get_chunk(0).unwrap();

        // Adding this valid chunk to a repairing_chunkset with a tampered commitment should fail
        assert_eq!(
            repairing_chunkset.add_chunk(valid_chunk).unwrap_err(),
            DecdsError::InvalidProofInChunk(valid_chunk.get_chunkset_id())
        );
    }

    #[test]
    fn test_repairing_chunkset_add_chunk_unvalidated_invalid_chunk_metadata() {
        let mut rng = rand::rng();

        let data = (0..ChunkSet::BYTE_LENGTH).map(|_| rng.random()).collect::<Vec<u8>>();
        let chunkset = ChunkSet::new(0, data).expect("Must be able to build erasure-coded ChunkSet");

        let chunk_from_chunkset_0 = chunkset.get_chunk(0).unwrap();

        // Create a repairing chunkset for a different ID (e.g., ID 1 instead of 0)
        let mut repairing_chunkset = RepairingChunkSet::new(1, chunkset.get_root_commitment());

        // Attempt to add a chunk that belongs to chunkset_id 0 to a repairing_chunkset for chunkset_id 1
        assert_eq!(
            repairing_chunkset.add_chunk_unvalidated(chunk_from_chunkset_0).unwrap_err(),
            DecdsError::InvalidChunkMetadata(chunk_from_chunkset_0.get_chunkset_id())
        );
    }

    #[test]
    fn test_repairing_chunkset_repair_when_not_ready() {
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
}
