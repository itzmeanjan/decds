use crate::{
    RepairingChunkSet,
    chunk::{self, ProofCarryingChunk},
    chunkset::{self, ChunkSet},
    consts::DECDS_BINCODE_CONFIG,
    errors::{ShelbyError, bincode_error_mapper},
    merkle_tree::MerkleTree,
};
use blake3;
use rand::seq::IteratorRandom;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ops::RangeBounds};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlobHeader {
    byte_length: usize,
    root_commitment: blake3::Hash,
    digest: blake3::Hash,
    num_chunksets: usize,
    chunkset_root_commitments: Vec<blake3::Hash>,
}

impl BlobHeader {
    pub fn get_root_commitment(&self) -> blake3::Hash {
        self.root_commitment
    }

    pub fn get_blob_digest(&self) -> blake3::Hash {
        self.digest
    }

    pub fn get_blob_size(&self) -> usize {
        self.byte_length
    }

    pub fn get_num_chunksets(&self) -> usize {
        self.num_chunksets
    }

    pub fn get_num_chunks(&self) -> usize {
        self.get_num_chunksets() * chunkset::ChunkSet::NUM_ERASURE_CODED_CHUNKS
    }

    pub fn get_chunkset_commitment(&self, chunkset_id: usize) -> Result<blake3::Hash, ShelbyError> {
        if chunkset_id < self.get_num_chunksets() {
            Ok(self.chunkset_root_commitments[chunkset_id])
        } else {
            Err(ShelbyError::CatchAllError)
        }
    }

    pub fn get_byte_range_for_chunkset(&self, chunkset_id: usize) -> Result<(usize, usize), ShelbyError> {
        if chunkset_id < self.get_num_chunksets() {
            let from = chunkset_id * ChunkSet::SIZE;
            let to = from + ChunkSet::SIZE;

            Ok((from, to))
        } else {
            Err(ShelbyError::CatchAllError)
        }
    }

    pub fn get_chunkset_ids_for_byte_range(&self, byte_range: impl RangeBounds<usize>) -> Result<Vec<usize>, ShelbyError> {
        let start = match byte_range.start_bound() {
            std::ops::Bound::Unbounded => 0,
            std::ops::Bound::Included(&x) => x,
            _ => return Err(ShelbyError::CatchAllError),
        };

        let end = match byte_range.end_bound() {
            std::ops::Bound::Included(&x) => x,
            std::ops::Bound::Excluded(&x) => {
                if x == 0 {
                    return Err(ShelbyError::CatchAllError);
                }

                x - 1
            }
            _ => return Err(ShelbyError::CatchAllError),
        };

        let start_chunkset_id = start / ChunkSet::SIZE;
        let end_chunkset_id = end / ChunkSet::SIZE;

        if end_chunkset_id >= self.get_num_chunksets() {
            return Err(ShelbyError::CatchAllError);
        }

        Ok((start_chunkset_id..=end_chunkset_id).collect())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ShelbyError> {
        bincode::serde::encode_to_vec(self, DECDS_BINCODE_CONFIG).map_err(bincode_error_mapper)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ShelbyError> {
        match bincode::serde::decode_from_slice::<BlobHeader, bincode::config::Configuration>(bytes, DECDS_BINCODE_CONFIG) {
            Ok((header, n)) => {
                if bytes.len() != n {
                    return Err(ShelbyError::CatchAllError);
                }
                if header.num_chunksets != header.chunkset_root_commitments.len() {
                    return Err(ShelbyError::CatchAllError);
                }

                Ok(header)
            }
            Err(_) => Err(ShelbyError::CatchAllError),
        }
    }

    pub fn validate_chunk(&self, chunk: &chunk::ProofCarryingChunk) -> bool {
        chunk.validate_inclusion_in_blob(self.root_commitment)
            && (chunk.get_chunkset_id() < self.num_chunksets)
            && chunk.validate_inclusion_in_chunkset(self.chunkset_root_commitments[chunk.get_chunkset_id()])
    }
}

pub struct Blob {
    header: BlobHeader,
    body: Vec<chunkset::ChunkSet>,
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

        let mut chunksets = (0..num_chunksets)
            .into_par_iter()
            .map(|chunkset_id| {
                let offset = chunkset_id * chunkset::ChunkSet::SIZE;
                let till = offset + chunkset::ChunkSet::SIZE;

                unsafe { chunkset::ChunkSet::new(offset, chunkset_id, data[offset..till].to_vec()).unwrap_unchecked() }
            })
            .collect::<Vec<chunkset::ChunkSet>>();

        let merkle_leaves = chunksets.iter().map(|chunkset| chunkset.get_root_commitment()).collect::<Vec<blake3::Hash>>();
        let merkle_tree = MerkleTree::new(merkle_leaves).ok_or(ShelbyError::CatchAllError)?;
        let commitment = merkle_tree.get_root_commitment();

        chunksets.par_iter_mut().enumerate().for_each(|(chunkset_idx, chunkset)| {
            let blob_proof = unsafe { merkle_tree.generate_proof(chunkset_idx).unwrap_unchecked() };
            chunkset.append_blob_inclusion_proof(&blob_proof);
        });

        Ok(Blob {
            header: BlobHeader {
                byte_length: blob_length,
                root_commitment: commitment,
                digest: blob_digest,
                num_chunksets: num_chunksets,
                chunkset_root_commitments: chunksets.iter().map(|chunkset| chunkset.get_root_commitment()).collect(),
            },
            body: chunksets,
        })
    }

    pub fn get_blob_header(&self) -> &BlobHeader {
        &self.header
    }

    pub fn get_share(&self) -> Vec<ProofCarryingChunk> {
        let mut rng = rand::rng();

        (0..self.header.num_chunksets)
            .flat_map(|chunkset_id| {
                let chunkset = &self.body[chunkset_id];

                (0..ChunkSet::NUM_ERASURE_CODED_CHUNKS)
                    .choose_multiple(&mut rng, ChunkSet::NUM_ORIGINAL_CHUNKS + 1)
                    .iter()
                    .map(|&chunk_id| unsafe { chunkset.get_chunk(chunk_id).unwrap_unchecked().clone() })
                    .collect::<Vec<ProofCarryingChunk>>()
            })
            .collect::<Vec<ProofCarryingChunk>>()
    }
}

pub struct RepairingBlob {
    header: BlobHeader,
    body: HashMap<usize, Option<chunkset::RepairingChunkSet>>,
}

impl RepairingBlob {
    pub fn new(header: BlobHeader) -> Self {
        RepairingBlob {
            body: HashMap::from_iter((0..header.get_num_chunksets()).map(|chunkset_id| {
                (
                    chunkset_id,
                    Some(RepairingChunkSet::new(chunkset_id, header.get_chunkset_commitment(chunkset_id).unwrap())),
                )
            })),
            header: header,
        }
    }

    pub fn add_chunk(&mut self, chunk: &chunk::ProofCarryingChunk) -> Result<(), ShelbyError> {
        let chunkset_id = chunk.get_chunkset_id();

        match self.body.get_mut(&chunkset_id).ok_or(ShelbyError::CatchAllError)? {
            Some(chunkset) => {
                if self.header.validate_chunk(chunk) {
                    if !chunkset.is_ready_to_repair() {
                        chunkset.add_chunk_unvalidated(chunk)
                    } else {
                        Err(ShelbyError::CatchAllError)
                    }
                } else {
                    Err(ShelbyError::CatchAllError)
                }
            }
            None => Err(ShelbyError::CatchAllError),
        }
    }

    pub fn is_chunkset_ready_to_repair(&self, chunkset_id: usize) -> bool {
        if chunkset_id >= self.header.get_num_chunksets() {
            false
        } else if let Some(chunkset) = &self.body[&chunkset_id] {
            chunkset.is_ready_to_repair()
        } else {
            false
        }
    }

    pub fn is_chunkset_already_repaired(&self, chunkset_id: usize) -> bool {
        if chunkset_id >= self.header.get_num_chunksets() {
            false
        } else {
            self.body[&chunkset_id].is_none()
        }
    }

    pub fn get_repaired_chunkset(&mut self, chunkset_id: usize) -> Result<Vec<u8>, ShelbyError> {
        if self.is_chunkset_ready_to_repair(chunkset_id) {
            let chunkset = unsafe { self.body.remove(&chunkset_id).ok_or(ShelbyError::CatchAllError)?.unwrap_unchecked() };
            self.body.insert(chunkset_id, None);

            chunkset.repair()
        } else {
            Err(ShelbyError::CatchAllError)
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
            // let num_chunks = blob.get_num_chunks();
            // let blob_commitment = blob.get_root_commitment();

            // (0..num_chunks).for_each(|chunk_id| {
            //     let chunkset_id = chunk_id / ChunkSet::NUM_ERASURE_CODED_CHUNKS;

            //     let chunkset = blob.get_chunkset(chunkset_id).expect("Must be able to lookup chunkset from blob API");
            //     let chunk = blob.get_chunk(chunk_id).expect("Must be able to lookup chunk from blob API");

            //     assert!(chunk.validate_inclusion_in_blob(blob_commitment));
            //     assert!(chunk.validate_inclusion_in_chunkset(chunkset.get_root_commitment()));

            //     let chunk_as_bytes = chunk.to_bytes().expect("Must be able to encode proof-carrying chunk");
            //     let decoded_chunk = ProofCarryingChunk::from_bytes(&chunk_as_bytes, blob_commitment).expect("Must be able to decode proof-carrying chunk");

            //     assert!(decoded_chunk.validate_inclusion_in_blob(blob_commitment));
            //     assert!(decoded_chunk.validate_inclusion_in_chunkset(chunkset.get_root_commitment()));
            // });
        });
    }
}
