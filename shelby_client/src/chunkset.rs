use crate::{
    chunk,
    errors::{ShelbyError, rlnc_error_mapper},
    merkle_tree::MerkleTree,
};

#[derive(Clone)]
/// Fixed size = 10MB = 10 * 2^20 bytes
pub struct ChunkSet {
    offset: usize,
    chunkset_id: usize,
    commitment: blake3::Hash,
    digest: blake3::Hash,
    chunks: Vec<chunk::ProofCarryingChunk>,
}

impl ChunkSet {
    pub const SIZE: usize = 10 * (1usize << 20); // 10MB
    pub const NUM_ORIGINAL_CHUNKS: usize = 10;
    pub const NUM_ERASURE_CODED_CHUNKS: usize = 16;
    pub const PROOF_SIZE: usize = usize::ilog2(Self::NUM_ERASURE_CODED_CHUNKS) as usize; // These many 32 bytes BLAKE3 digests

    pub fn new(offset: usize, chunkset_id: usize, data: Vec<u8>) -> Result<ChunkSet, ShelbyError> {
        assert_eq!(data.len(), Self::SIZE);

        let chunkset_digest = blake3::hash(&data);

        let mut rng = rand::rng();
        let encoder = rlnc::full::encoder::Encoder::new(data, Self::NUM_ORIGINAL_CHUNKS).map_err(rlnc_error_mapper)?;

        let mut chunks = Vec::with_capacity(Self::NUM_ERASURE_CODED_CHUNKS);
        for i in 0..Self::NUM_ERASURE_CODED_CHUNKS {
            let chunk_id = chunkset_id * Self::NUM_ERASURE_CODED_CHUNKS + i;
            let coded_piece = encoder.code(&mut rng);

            let chunk = chunk::Chunk::new(chunk_id, offset, coded_piece, chunkset_digest);
            chunks.push(chunk);
        }

        let merkle_leaves = chunks.iter().map(|chunk| chunk.digest()).collect::<Vec<blake3::Hash>>();
        let merkle_tree = MerkleTree::new(merkle_leaves).ok_or(ShelbyError::CatchAllError)?;

        let commitment = merkle_tree.get_root_commitment();

        let proof_carrying_chunks = chunks
            .into_iter()
            .enumerate()
            .map(|(leaf_idx, chunk)| {
                let proof = unsafe { merkle_tree.generate_proof(leaf_idx).unwrap_unchecked() };
                chunk::ProofCarryingChunk::new(chunk, proof)
            })
            .collect::<Vec<chunk::ProofCarryingChunk>>();

        Ok(ChunkSet {
            offset,
            chunkset_id,
            commitment,
            digest: chunkset_digest,
            chunks: proof_carrying_chunks,
        })
    }

    pub fn get_root_commitment(&self) -> blake3::Hash {
        self.commitment
    }

    pub fn get_chunkset_digest(&self) -> blake3::Hash {
        self.digest
    }

    pub fn get_chunkset_id(&self) -> usize {
        self.chunkset_id
    }

    pub fn get_chunk_id_range(&self) -> (usize, usize) {
        let chunk_id_from = self.chunkset_id * Self::NUM_ERASURE_CODED_CHUNKS;
        let chunk_id_to = chunk_id_from + Self::NUM_ERASURE_CODED_CHUNKS;

        (chunk_id_from, chunk_id_to)
    }

    pub fn get_blob_byte_range(&self) -> (usize, usize) {
        (self.offset, self.offset + ChunkSet::SIZE)
    }

    pub fn get_chunk(&self, chunk_id: usize) -> Result<&chunk::ProofCarryingChunk, ShelbyError> {
        if chunk_id > Self::NUM_ERASURE_CODED_CHUNKS {
            Err(ShelbyError::CatchAllError)
        } else {
            Ok(&self.chunks[chunk_id])
        }
    }

    pub(crate) fn append_blob_inclusion_proof(&mut self, blob_proof: &[blake3::Hash]) {
        if !blob_proof.is_empty() {
            self.chunks.iter_mut().for_each(|chunk| chunk.append_proof_to_blob_root(blob_proof));
        }
    }
}

pub struct RepairingChunkSet {
    commitment: blake3::Hash,
    decoder: rlnc::full::decoder::Decoder,
}

impl RepairingChunkSet {
    const PADDED_CHUNK_BYTE_LEN: usize = (ChunkSet::SIZE + 1).div_ceil(ChunkSet::NUM_ORIGINAL_CHUNKS);

    pub fn new(commitment: blake3::Hash) -> Self {
        let decoder = unsafe { rlnc::full::decoder::Decoder::new(Self::PADDED_CHUNK_BYTE_LEN, ChunkSet::NUM_ORIGINAL_CHUNKS).unwrap_unchecked() };
        RepairingChunkSet { commitment, decoder }
    }

    pub fn add_chunk(&mut self, chunk: &chunk::ProofCarryingChunk) -> Result<(), ShelbyError> {
        let is_valid = chunk.validate_inclusion_in_chunkset(self.commitment);
        if !is_valid {
            return Err(ShelbyError::CatchAllError);
        }

        self.decoder.decode(chunk.get_erasure_coded_data()).map_err(rlnc_error_mapper)
    }

    pub fn is_ready_to_repair(&self) -> bool {
        self.decoder.is_already_decoded()
    }

    pub fn repair(self) -> Result<Vec<u8>, ShelbyError> {
        self.decoder.get_decoded_data().map_err(rlnc_error_mapper)
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
            let mut repairing_chunkset = RepairingChunkSet::new(chunkset.get_root_commitment());

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
