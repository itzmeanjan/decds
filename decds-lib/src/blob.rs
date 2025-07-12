use crate::{
    RepairingChunkSet,
    chunk::{self, ProofCarryingChunk},
    chunkset::{self, ChunkSet},
    consts::{DECDS_BINCODE_CONFIG, DECDS_NUM_ERASURE_CODED_SHARES},
    errors::DECDSError,
    merkle_tree::MerkleTree,
};
use blake3;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ops::RangeBounds, usize};

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

    pub fn get_chunkset_size(&self, chunkset_id: usize) -> Result<usize, DECDSError> {
        if chunkset_id < self.get_num_chunksets() {
            let from = chunkset_id * ChunkSet::SIZE;
            let to = (from + ChunkSet::SIZE).min(self.get_blob_size());
            let effective_len = to - from;

            Ok(effective_len)
        } else {
            Err(DECDSError::InvalidChunksetId(chunkset_id, self.get_num_chunksets()))
        }
    }

    pub fn get_num_chunks(&self) -> usize {
        self.get_num_chunksets() * chunkset::ChunkSet::NUM_ERASURE_CODED_CHUNKS
    }

    pub fn get_chunkset_commitment(&self, chunkset_id: usize) -> Result<blake3::Hash, DECDSError> {
        if chunkset_id < self.get_num_chunksets() {
            Ok(self.chunkset_root_commitments[chunkset_id])
        } else {
            Err(DECDSError::InvalidChunksetId(chunkset_id, self.get_num_chunksets()))
        }
    }

    pub fn get_byte_range_for_chunkset(&self, chunkset_id: usize) -> Result<(usize, usize), DECDSError> {
        if chunkset_id < self.get_num_chunksets() {
            let from = chunkset_id * ChunkSet::SIZE;
            let to = from + ChunkSet::SIZE;

            Ok((from, to))
        } else {
            Err(DECDSError::InvalidChunksetId(chunkset_id, self.get_num_chunksets()))
        }
    }

    pub fn get_chunkset_ids_for_byte_range(&self, byte_range: impl RangeBounds<usize>) -> Result<Vec<usize>, DECDSError> {
        let start = match byte_range.start_bound() {
            std::ops::Bound::Unbounded => 0,
            std::ops::Bound::Included(&x) => x,
            _ => return Err(DECDSError::InvalidStartBound),
        };

        let end = match byte_range.end_bound() {
            std::ops::Bound::Included(&x) => x,
            std::ops::Bound::Excluded(&x) => {
                if x == 0 {
                    return Err(DECDSError::InvalidEndBound(x));
                }

                x - 1
            }
            _ => return Err(DECDSError::InvalidEndBound(usize::MAX)),
        };

        let start_chunkset_id = start / ChunkSet::SIZE;
        let end_chunkset_id = end / ChunkSet::SIZE;

        if end_chunkset_id >= self.get_num_chunksets() {
            return Err(DECDSError::InvalidChunksetId(end_chunkset_id, self.get_num_chunksets()));
        }

        Ok((start_chunkset_id..=end_chunkset_id).collect())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DECDSError> {
        bincode::serde::encode_to_vec(self, DECDS_BINCODE_CONFIG).map_err(|err| DECDSError::BlobHeaderSerializationFailed(err.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), DECDSError> {
        match bincode::serde::decode_from_slice::<BlobHeader, bincode::config::Configuration>(bytes, DECDS_BINCODE_CONFIG) {
            Ok((header, n)) => {
                if header.num_chunksets != header.chunkset_root_commitments.len() {
                    return Err(DECDSError::BlobHeaderDeserializationFailed(
                        "number of chunksets and root commitments do not match".to_string(),
                    ));
                }

                Ok((header, n))
            }
            Err(err) => Err(DECDSError::BlobHeaderDeserializationFailed(err.to_string())),
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
    pub fn new(mut data: Vec<u8>) -> Result<Self, DECDSError> {
        if data.is_empty() {
            return Err(DECDSError::EmptyDataForBlob);
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
        let merkle_tree = MerkleTree::new(merkle_leaves)?;
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

    pub fn get_share(&self, share_id: usize) -> Result<Vec<ProofCarryingChunk>, DECDSError> {
        if share_id >= DECDS_NUM_ERASURE_CODED_SHARES {
            return Err(DECDSError::InvalidErasureCodedShareId(share_id));
        }

        Ok((0..self.header.num_chunksets)
            .map(|chunkset_id| unsafe {
                let chunkset = &self.body[chunkset_id];
                chunkset.get_chunk(share_id).unwrap_unchecked().clone()
            })
            .collect::<Vec<ProofCarryingChunk>>())
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
                    Some(RepairingChunkSet::new(chunkset_id, unsafe {
                        header.get_chunkset_commitment(chunkset_id).unwrap_unchecked()
                    })),
                )
            })),
            header: header,
        }
    }

    pub fn add_chunk(&mut self, chunk: &chunk::ProofCarryingChunk) -> Result<(), DECDSError> {
        let chunkset_id = chunk.get_chunkset_id();

        match self
            .body
            .get_mut(&chunkset_id)
            .ok_or(DECDSError::InvalidChunksetId(chunkset_id, self.header.get_num_chunksets()))?
        {
            Some(chunkset) => {
                if self.header.validate_chunk(chunk) {
                    if !chunkset.is_ready_to_repair() {
                        chunkset.add_chunk_unvalidated(chunk)
                    } else {
                        Err(DECDSError::ChunksetReadyToRepair(chunkset_id))
                    }
                } else {
                    Err(DECDSError::InvalidProofInChunk(chunkset_id))
                }
            }
            None => Err(DECDSError::ChunksetAlreadyRepaired(chunkset_id)),
        }
    }

    pub fn is_chunkset_ready_to_repair(&self, chunkset_id: usize) -> Result<bool, DECDSError> {
        Ok(self
            .body
            .get(&chunkset_id)
            .ok_or(DECDSError::InvalidChunksetId(chunkset_id, self.header.get_num_chunksets()))?
            .as_ref()
            .is_some_and(|x| x.is_ready_to_repair()))
    }

    pub fn is_chunkset_already_repaired(&self, chunkset_id: usize) -> Result<bool, DECDSError> {
        Ok(self
            .body
            .get(&chunkset_id)
            .ok_or(DECDSError::InvalidChunksetId(chunkset_id, self.header.get_num_chunksets()))?
            .is_none())
    }

    pub fn get_repaired_chunkset(&mut self, chunkset_id: usize) -> Result<Vec<u8>, DECDSError> {
        self.is_chunkset_already_repaired(chunkset_id).and_then(|yes| {
            if yes {
                Err(DECDSError::ChunksetAlreadyRepaired(chunkset_id))
            } else {
                self.is_chunkset_ready_to_repair(chunkset_id).and_then(|yes| unsafe {
                    if yes {
                        self.body
                            .insert(chunkset_id, None)
                            .unwrap_unchecked()
                            .unwrap_unchecked()
                            .repair()
                            .map(|mut repaired| {
                                repaired.truncate(self.header.get_chunkset_size(chunkset_id).unwrap_unchecked());
                                repaired
                            })
                    } else {
                        Err(DECDSError::ChunksetNotYetReadyToRepair(chunkset_id))
                    }
                })
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{blob::Blob, consts};
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
            let blob_header = blob.get_blob_header();

            assert!(
                (0..consts::DECDS_NUM_ERASURE_CODED_SHARES)
                    .flat_map(|share_id| blob.get_share(share_id).expect("Must be able to get erasure coded shares"))
                    .all(|share| blob_header.validate_chunk(&share))
            );
        });
    }
}
