use crate::{
    chunk,
    chunkset::{self, ChunkSet},
    errors::ShelbyError,
    merkle_tree::MerkleTree,
};
use blake3;

/// Arbitrary size
pub struct Blob {
    length: usize,
    commitment: blake3::Hash,
    digest: blake3::Hash,
    chunksets: Vec<chunkset::ChunkSet>,
}

impl Blob {
    pub fn new(mut data: Vec<u8>) -> Result<Self, ShelbyError> {
        if data.is_empty() {
            return Err(ShelbyError::CatchAllError);
        }

        let blob_digest = blake3::hash(&data);
        let blob_length = data.len();

        let num_chunksets = blob_length.div_ceil(chunkset::ChunkSet::SIZE);
        let zero_padded_blob_len = num_chunksets * chunkset::ChunkSet::SIZE;
        data.resize(zero_padded_blob_len, 0);

        let mut offset = 0;
        let mut chunksets = Vec::with_capacity(num_chunksets);

        while offset < zero_padded_blob_len {
            let till = offset + chunkset::ChunkSet::SIZE;
            let chunkset_id = offset / chunkset::ChunkSet::SIZE;

            let chunkset = chunkset::ChunkSet::new(offset, chunkset_id, data[offset..till].to_vec())?;
            chunksets.push(chunkset);

            offset += chunkset::ChunkSet::SIZE;
        }

        let merkle_leaves = chunksets.iter().map(|chunkset| chunkset.get_root_commitment()).collect::<Vec<blake3::Hash>>();
        let merkle_tree = MerkleTree::new(merkle_leaves).ok_or(ShelbyError::CatchAllError)?;
        let commitment = merkle_tree.get_root_commitment();

        chunksets.iter_mut().enumerate().for_each(|(chunkset_idx, chunkset)| {
            let blob_proof = unsafe { merkle_tree.generate_proof(chunkset_idx).unwrap_unchecked() };
            chunkset.append_blob_inclusion_proof(&blob_proof);
        });

        Ok(Blob {
            length: blob_length,
            commitment,
            digest: blob_digest,
            chunksets,
        })
    }

    pub fn get_root_commitment(&self) -> blake3::Hash {
        self.commitment
    }

    pub fn get_blob_digest(&self) -> blake3::Hash {
        self.digest
    }

    pub fn get_blob_size(&self) -> usize {
        self.length
    }

    pub fn get_num_chunksets(&self) -> usize {
        self.length.div_ceil(chunkset::ChunkSet::SIZE)
    }

    pub fn get_num_chunks(&self) -> usize {
        self.get_num_chunksets() * chunkset::ChunkSet::NUM_ERASURE_CODED_CHUNKS
    }

    pub fn get_chunkset(&self, chunkset_id: usize) -> Result<&chunkset::ChunkSet, ShelbyError> {
        let num_chunksets = self.length.div_ceil(chunkset::ChunkSet::SIZE);

        if chunkset_id > num_chunksets {
            Err(ShelbyError::CatchAllError)
        } else {
            Ok(&self.chunksets[chunkset_id])
        }
    }

    pub fn get_chunk(&self, chunk_id: usize) -> Result<&chunk::ProofCarryingChunk, ShelbyError> {
        if chunk_id > self.get_num_chunks() {
            Err(ShelbyError::CatchAllError)
        } else {
            let chunkset_id = chunk_id / ChunkSet::NUM_ERASURE_CODED_CHUNKS;
            let local_chunk_id = chunk_id % ChunkSet::NUM_ERASURE_CODED_CHUNKS;

            self.chunksets[chunkset_id].get_chunk(local_chunk_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{blob::Blob, chunk::ProofCarryingChunk, chunkset::ChunkSet};
    use rand::Rng;

    #[test]
    fn prop_test_blob_preparation_and_commitment_works() {
        const NUM_TEST_ITERATIONS: usize = 10;

        const MIN_BLOB_DATA_BYTE_LEN: usize = 1usize;
        const MAX_BLOB_DATA_BYTE_LEN: usize = 1usize << 30;

        let mut rng = rand::rng();

        (0..NUM_TEST_ITERATIONS).for_each(|_| {
            let blob_byte_len = rng.random_range(MIN_BLOB_DATA_BYTE_LEN..=MAX_BLOB_DATA_BYTE_LEN);
            let blob_data = (0..blob_byte_len).map(|_| rng.random()).collect::<Vec<u8>>();

            let blob = Blob::new(blob_data).expect("Must be able to prepare blob");
            let num_chunks = blob.get_num_chunks();
            let blob_commitment = blob.get_root_commitment();

            (0..num_chunks).for_each(|chunk_id| {
                let chunkset_id = chunk_id / ChunkSet::NUM_ERASURE_CODED_CHUNKS;

                let chunkset = blob.get_chunkset(chunkset_id).expect("Must be able to lookup chunkset from blob API");
                let chunk = blob.get_chunk(chunk_id).expect("Must be able to lookup chunk from blob API");

                assert!(chunk.validate_inclusion_in_blob(blob_commitment));
                assert!(chunk.validate_inclusion_in_chunkset(chunkset.get_root_commitment()));

                let chunk_as_bytes = chunk.to_bytes().expect("Must be able to encode proof-carrying chunk");
                let decoded_chunk = ProofCarryingChunk::from_bytes(&chunk_as_bytes, blob_commitment).expect("Must be able to decode proof-carrying chunk");

                assert!(decoded_chunk.validate_inclusion_in_blob(blob_commitment));
                assert!(decoded_chunk.validate_inclusion_in_chunkset(chunkset.get_root_commitment()));
            });
        });
    }
}
