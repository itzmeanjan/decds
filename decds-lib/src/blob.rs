use crate::{
    RepairingChunkSet,
    chunk::{self, ProofCarryingChunk},
    chunkset::{self, ChunkSet},
    consts::{DECDS_BINCODE_CONFIG, DECDS_NUM_ERASURE_CODED_SHARES},
    errors::DecdsError,
    merkle_tree::MerkleTree,
};
use blake3;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ops::RangeBounds, usize};

/// Represents the header of a `Blob`, containing essential metadata about the blob's
/// structure and cryptographic commitments. This is essentially what is used during
/// validity checking and repairing of erasure-coded chunks.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlobHeader {
    byte_length: usize,
    num_chunksets: usize,
    digest: blake3::Hash,
    root_commitment: blake3::Hash,
    chunkset_root_commitments: Vec<blake3::Hash>,
}

impl BlobHeader {
    /// Returns the original byte length of the blob data before padding.
    pub fn get_blob_size(&self) -> usize {
        self.byte_length
    }

    /// Returns the total number of chunksets that comprise the blob.
    pub fn get_num_chunksets(&self) -> usize {
        self.num_chunksets
    }

    /// Returns the total number of erasure-coded chunks across all chunksets in the blob.
    pub fn get_num_chunks(&self) -> usize {
        self.get_num_chunksets() * chunkset::ChunkSet::NUM_ERASURE_CODED_CHUNKS
    }

    /// Returns the BLAKE3 digest of the original, unpadded blob data.
    pub fn get_blob_digest(&self) -> blake3::Hash {
        self.digest
    }

    /// Returns the Merkle root commitment of the entire blob.
    ///
    /// This commitment is derived from the Merkle tree of all chunksets in the blob.
    pub fn get_root_commitment(&self) -> blake3::Hash {
        self.root_commitment
    }

    /// Returns the Merkle root commitment of a specific chunkset within the blob.
    ///
    /// # Arguments
    ///
    /// * `chunkset_id` - The ID of the chunkset whose commitment is to be retrieved.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(blake3::Hash)` containing the root commitment of the specified chunkset if successful.
    /// - `Err(DecdsError::InvalidChunksetId)` if `chunkset_id` is out of bounds.
    pub fn get_chunkset_commitment(&self, chunkset_id: usize) -> Result<blake3::Hash, DecdsError> {
        self.chunkset_root_commitments
            .get(chunkset_id)
            .and_then(|&v| Some(v))
            .ok_or(DecdsError::InvalidChunksetId(chunkset_id, self.get_num_chunksets()))
    }

    /// Calculates the effective byte length of a specific chunkset within the blob.
    /// This accounts for the last chunkset potentially being smaller than `ChunkSet::BYTE_LENGTH`.
    ///
    /// # Arguments
    ///
    /// * `chunkset_id` - The ID of the chunkset whose size is to be determined.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(usize)` containing the effective byte length of the chunkset if successful.
    /// - `Err(DecdsError::InvalidChunksetId)` if `chunkset_id` is out of bounds.
    pub fn get_chunkset_size(&self, chunkset_id: usize) -> Result<usize, DecdsError> {
        if chunkset_id < self.get_num_chunksets() {
            let from = chunkset_id * ChunkSet::BYTE_LENGTH;
            let to = (from + ChunkSet::BYTE_LENGTH).min(self.get_blob_size());
            let effective_len = to - from;

            Ok(effective_len)
        } else {
            Err(DecdsError::InvalidChunksetId(chunkset_id, self.get_num_chunksets()))
        }
    }

    /// Returns the full byte range `[start, end)` of a specific chunkset as it would appear
    /// in the zero-padded blob data.
    ///
    /// # Arguments
    ///
    /// * `chunkset_id` - The ID of the chunkset whose byte range is to be retrieved.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok((usize, usize))` containing a tuple `[start_byte_idx, end_byte_idx)` if successful.
    /// - `Err(DecdsError::InvalidChunksetId)` if `chunkset_id` is out of bounds.
    pub fn get_byte_range_for_chunkset(&self, chunkset_id: usize) -> Result<(usize, usize), DecdsError> {
        if chunkset_id < self.get_num_chunksets() {
            let from = chunkset_id * ChunkSet::BYTE_LENGTH;
            let to = (from + ChunkSet::BYTE_LENGTH).min(self.get_blob_size());

            Ok((from, to))
        } else {
            Err(DecdsError::InvalidChunksetId(chunkset_id, self.get_num_chunksets()))
        }
    }

    /// Determines the IDs of all chunksets that overlap with a given byte range within the blob.
    ///
    /// # Arguments
    ///
    /// * `byte_range` - A range `impl RangeBounds<usize>` specifying the byte range.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(Vec<usize>)` containing a vector of chunkset IDs if successful.
    /// - `Err(DecdsError::InvalidStartBound)` if the start bound of the range is not valid.
    /// - `Err(DecdsError::InvalidEndBound)` if the end bound of the range is not valid (e.g., 0 for an `Excluded` bound or `usize::MAX`).
    /// - `Err(DecdsError::InvalidChunksetId)` if the calculated `end_chunkset_id` is out of bounds.
    pub fn get_chunkset_ids_for_byte_range(&self, byte_range: impl RangeBounds<usize>) -> Result<Vec<usize>, DecdsError> {
        let start = match byte_range.start_bound() {
            std::ops::Bound::Unbounded => 0,
            std::ops::Bound::Included(&x) => x,
            _ => return Err(DecdsError::InvalidStartBound),
        };

        let end = match byte_range.end_bound() {
            std::ops::Bound::Included(&x) => x,
            std::ops::Bound::Excluded(&x) => {
                if x == 0 {
                    return Err(DecdsError::InvalidEndBound(x));
                }

                x - 1
            }
            _ => return Err(DecdsError::InvalidEndBound(usize::MAX)),
        };

        let start_chunkset_id = start / ChunkSet::BYTE_LENGTH;
        let end_chunkset_id = end / ChunkSet::BYTE_LENGTH;

        if end_chunkset_id >= self.get_num_chunksets() {
            return Err(DecdsError::InvalidChunksetId(end_chunkset_id, self.get_num_chunksets()));
        }

        Ok((start_chunkset_id..=end_chunkset_id).collect())
    }

    /// Serializes the `BlobHeader` into a vector of bytes using `bincode`.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(Vec<u8>)` containing the serialized bytes if successful.
    /// - `Err(DecdsError::BlobHeaderSerializationFailed)` if `bincode` serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecdsError> {
        bincode::serde::encode_to_vec(self, DECDS_BINCODE_CONFIG).map_err(|err| DecdsError::BlobHeaderSerializationFailed(err.to_string()))
    }

    /// Deserializes a `BlobHeader` from a byte slice using `bincode`.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The byte slice from which to deserialize the header.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok((Self, usize))` containing the deserialized `BlobHeader` and the number of bytes read if successful.
    /// - `Err(DecdsError::BlobHeaderDeserializationFailed)` if `bincode` deserialization fails, or if the number
    ///   of chunksets in the header does not match the number of root commitments.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), DecdsError> {
        match bincode::serde::decode_from_slice::<BlobHeader, bincode::config::Configuration>(bytes, DECDS_BINCODE_CONFIG) {
            Ok((header, n)) => {
                if header.num_chunksets != header.chunkset_root_commitments.len() {
                    return Err(DecdsError::BlobHeaderDeserializationFailed(
                        "number of chunksets and root commitments do not match".to_string(),
                    ));
                }

                Ok((header, n))
            }
            Err(err) => Err(DecdsError::BlobHeaderDeserializationFailed(err.to_string())),
        }
    }

    /// Validates a `ProofCarryingChunk` against the `BlobHeader`'s commitments.
    ///
    /// This checks if the chunk is correctly included in the blob (via blob root commitment)
    /// and its respective chunkset (via chunkset root commitment).
    ///
    /// # Arguments
    ///
    /// * `chunk` - A reference to the `ProofCarryingChunk` to validate.
    ///
    /// # Returns
    ///
    /// Returns `true` if the chunk is valid and its proofs are consistent with the blob header, `false` otherwise.
    pub fn validate_chunk(&self, chunk: &chunk::ProofCarryingChunk) -> bool {
        chunk.validate_inclusion_in_blob(self.root_commitment)
            && (chunk.get_chunkset_id() < self.num_chunksets)
            && chunk.validate_inclusion_in_chunkset(self.chunkset_root_commitments[chunk.get_chunkset_id()])
    }
}

/// Represents a complete, erasure-coded blob of data, consisting of a `BlobHeader` and a collection of `ChunkSet`s,
/// each of which are holding 16 erasure-coded proof-of-inclusion carrying chunks.
pub struct Blob {
    header: BlobHeader,
    body: Vec<chunkset::ChunkSet>,
}

impl Blob {
    /// Creates a new `Blob` from raw byte data.
    ///
    /// This involves:
    /// 1. Calculating the blob's digest and padding its length to a multiple of `ChunkSet::BYTE_LENGTH`.
    /// 2. Dividing the data into `ChunkSet`s and erasure-coding them individually.
    /// 3. Building a Merkle tree over the chunksets' root commitments to create the blob's root commitment.
    /// 4. Appending blob-level Merkle proofs to each chunk within the chunksets.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw `Vec<u8>` representing the blob's content.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(Self)` containing the newly created `Blob` if successful.
    /// - `Err(DecdsError::EmptyDataForBlob)` if the input `data` is empty.
    /// - Other `DecdsError` types may be returned from underlying `ChunkSet::new` or `MerkleTree::new` calls.
    pub fn new(mut data: Vec<u8>) -> Result<Self, DecdsError> {
        if data.is_empty() {
            return Err(DecdsError::EmptyDataForBlob);
        }

        let blob_digest = blake3::hash(&data);
        let blob_length = data.len();

        let num_chunksets = blob_length.div_ceil(chunkset::ChunkSet::BYTE_LENGTH);
        let zero_padded_blob_len = num_chunksets * chunkset::ChunkSet::BYTE_LENGTH;
        data.resize(zero_padded_blob_len, 0);

        let mut chunksets = (0..num_chunksets)
            .into_par_iter()
            .map(|chunkset_id| {
                let offset = chunkset_id * chunkset::ChunkSet::BYTE_LENGTH;
                let till = offset + chunkset::ChunkSet::BYTE_LENGTH;

                unsafe { chunkset::ChunkSet::new(chunkset_id, data[offset..till].to_vec()).unwrap_unchecked() }
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
                num_chunksets,
                digest: blob_digest,
                root_commitment: commitment,
                chunkset_root_commitments: chunksets.iter().map(|chunkset| chunkset.get_root_commitment()).collect(),
            },
            body: chunksets,
        })
    }

    /// Returns a reference to the `BlobHeader` of this blob.
    pub fn get_blob_header(&self) -> &BlobHeader {
        &self.header
    }

    /// Retrieves a specific "share" (a collection of erasure-coded chunks, one from each chunkset)
    /// based on the `share_id`.
    ///
    /// Each share represents a vertical slice through the blob's chunksets.
    ///
    /// # Arguments
    ///
    /// * `share_id` - The ID of the share to retrieve (`0` to `DECDS_NUM_ERASURE_CODED_SHARES - 1`).
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(Vec<ProofCarryingChunk>)` containing a vector of proof-carrying chunks for the requested share.
    /// - `Err(DecdsError::InvalidErasureCodedShareId)` if `share_id` is out of bounds.
    pub fn get_share(&self, share_id: usize) -> Result<Vec<ProofCarryingChunk>, DecdsError> {
        if share_id >= DECDS_NUM_ERASURE_CODED_SHARES {
            return Err(DecdsError::InvalidErasureCodedShareId(share_id));
        }

        Ok((0..self.header.num_chunksets)
            .map(|chunkset_id| unsafe {
                let chunkset = &self.body[chunkset_id];
                chunkset.get_chunk(share_id).unwrap_unchecked().clone()
            })
            .collect::<Vec<ProofCarryingChunk>>())
    }
}

/// Represents a blob that is in the process of being incrementally repaired or reconstructed
/// from received `ProofCarryingChunk`s.
pub struct RepairingBlob {
    header: BlobHeader,
    body: HashMap<usize, Option<chunkset::RepairingChunkSet>>,
}

impl RepairingBlob {
    /// Creates a new `RepairingBlob` instance from a `BlobHeader`.
    ///
    /// This initializes an empty `RepairingChunkSet` for each chunkset indicated in the header,
    /// ready to receive chunks for repair.
    ///
    /// # Arguments
    ///
    /// * `header` - The `BlobHeader` of the blob to be repaired. This header provides the necessary
    ///   metadata, including chunkset commitments, for the repair process.
    ///
    /// # Returns
    ///
    /// A new `RepairingBlob` instance, prepared to accept chunks for reconstruction.
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

    /// Adds a `ProofCarryingChunk` to the appropriate `RepairingChunkSet` within the blob.
    ///
    /// This method first validates the chunk's inclusion using the blob header, then attempts
    /// to add it to the relevant chunkset's decoder.
    ///
    /// # Arguments
    ///
    /// * `chunk` - A reference to the `ProofCarryingChunk` to add.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(())` if the chunk is successfully added.
    /// - `Err(DecdsError::InvalidChunksetId)` if the chunk's `chunkset_id` does not exist in this blob.
    /// - `Err(DecdsError::ChunksetAlreadyRepaired)` if the target chunkset has already been repaired.
    /// - `Err(DecdsError::InvalidProofInChunk)` if the chunk's proof of inclusion in the blob or chunkset is invalid.
    /// - `Err(DecdsError::ChunksetReadyToRepair)` if the chunkset is already ready to repair (and thus cannot accept more chunks).
    /// - Other `DecdsError` types may be returned from `RepairingChunkSet::add_chunk_unvalidated`.
    pub fn add_chunk(&mut self, chunk: &chunk::ProofCarryingChunk) -> Result<(), DecdsError> {
        let chunkset_id = chunk.get_chunkset_id();

        match self
            .body
            .get_mut(&chunkset_id)
            .ok_or(DecdsError::InvalidChunksetId(chunkset_id, self.header.get_num_chunksets()))?
        {
            Some(chunkset) => {
                if self.header.validate_chunk(chunk) {
                    if !chunkset.is_ready_to_repair() {
                        chunkset.add_chunk_unvalidated(chunk)
                    } else {
                        Err(DecdsError::ChunksetReadyToRepair(chunkset_id))
                    }
                } else {
                    Err(DecdsError::InvalidProofInChunk(chunkset_id))
                }
            }
            None => Err(DecdsError::ChunksetAlreadyRepaired(chunkset_id)),
        }
    }

    /// Checks if a specific chunkset within the blob is ready to be repaired (reconstructed).
    ///
    /// # Arguments
    ///
    /// * `chunkset_id` - The ID of the chunkset to check.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(bool)`: `true` if the chunkset is ready for repair, `false` otherwise.
    /// - `Err(DecdsError::InvalidChunksetId)` if `chunkset_id` is out of bounds.
    pub fn is_chunkset_ready_to_repair(&self, chunkset_id: usize) -> Result<bool, DecdsError> {
        Ok(self
            .body
            .get(&chunkset_id)
            .ok_or(DecdsError::InvalidChunksetId(chunkset_id, self.header.get_num_chunksets()))?
            .as_ref()
            .is_some_and(|x| x.is_ready_to_repair()))
    }

    /// Checks if a specific chunkset within the blob has already been successfully repaired.
    ///
    /// # Arguments
    ///
    /// * `chunkset_id` - The ID of the chunkset to check.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(bool)`: `true` if the chunkset has already been repaired, `false` otherwise.
    /// - `Err(DecdsError::InvalidChunksetId)` if `chunkset_id` is out of bounds.
    pub fn is_chunkset_already_repaired(&self, chunkset_id: usize) -> Result<bool, DecdsError> {
        Ok(self
            .body
            .get(&chunkset_id)
            .ok_or(DecdsError::InvalidChunksetId(chunkset_id, self.header.get_num_chunksets()))?
            .is_none())
    }

    /// Retrieves the repaired (reconstructed) data for a specific chunkset.
    /// This method consumes the `RepairingChunkSet` for the given ID once successful,
    /// as the data is fully reconstructed.
    ///
    /// # Arguments
    ///
    /// * `chunkset_id` - The ID of the chunkset to retrieve repaired data for.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is:
    /// - `Ok(Vec<u8>)` containing the repaired chunkset data if successful.
    /// - `Err(DecdsError::ChunksetAlreadyRepaired)` if the chunkset has already been repaired and retrieved.
    /// - `Err(DecdsError::ChunksetNotYetReadyToRepair)` if not enough chunks have been added to repair the chunkset.
    /// - `Err(DecdsError::InvalidChunksetId)` if `chunkset_id` is out of bounds.
    /// - `Err(DecdsError::ChunksetRepairingFailed)` if an error occurs during the underlying chunkset repair process.
    pub fn get_repaired_chunkset(&mut self, chunkset_id: usize) -> Result<Vec<u8>, DecdsError> {
        self.is_chunkset_already_repaired(chunkset_id).and_then(|yes| {
            if yes {
                Err(DecdsError::ChunksetAlreadyRepaired(chunkset_id))
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
                        Err(DecdsError::ChunksetNotYetReadyToRepair(chunkset_id))
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
