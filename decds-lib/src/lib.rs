//! # DECDS-lib: Decentralized Erasure-Coded Data Storage Library
//!
//! `decds-lib` provides functionalities for disseminating, verifying and reconstructing arbitrary size data blobs
//! using Random Linear Network Coding (RLNC) based erasure-coding and binary Merkle trees for data integrity verification.
//!
//! This library is designed to enable decentralized data storage solutions by breaking down
//! large data into smaller, verifiable, and reconstructible chunks.
//!
//! ## How to Use
//!
//! To build a blob, first initialize the `BlobBuilder` struct, and incrementally keep putting data into it
//! by calling `BlobBuilder::update` function arbirary many times, possibly returning some `ProofCarryingChunk`s.
//! Once all data has been absorbed by the `BlobBuilder`` instance, it can be finalized, which returns the `BlobHeader`,
//! holding all necessary metadata for chunk validation and reconstruction.
//!
//! Note, the `ProofCarryingChunk`s which are generated during blob building, does only carry proof of
//! inclusion in respective `ChunkSet`s. Once the full blob is built, the proof carried by each chunk
//! needs to be extended for validating blob inclusion, during reconstruction. Following example demonstrates that.
//!
//! To reconstruct the original blob data, you need to collect *enough* `ProofCarryingChunk`s for all chunksets.
//! You initialize a `RepairingBlob` with the `BlobHeader`, which is the source of truth for validating `ProofCarryingChunk`s,
//! and then add chunks to it. Once *enough* chunks for a specific chunkset are collected, you can retrieve
//! its repaired data. Each chunkset requires at least 10 valid chunks to be recovered. To recover the full blob,
//! you need to collect at least 10 valid chunks per chunkset.
//!
//! For more details see README in `decds` repository @ <https://github.com/itzmeanjan/decds>.
//!
//! ```rust
//! use decds_lib::{BlobBuilder, BlobHeader, ProofCarryingChunk, RepairingBlob, DECDS_NUM_ERASURE_CODED_SHARES, DecdsError, MerkleTree};
//! use rand::{Rng, seq::SliceRandom};
//! use rayon::prelude::*;
//! use std::collections::HashMap;
//!
//! let mut rng = rand::rng();
//!
//! const ONE_MB: usize = 1usize << 20;
//! let original_data: Vec<u8> = (0..42 * ONE_MB).map(|_| rng.random()).collect(); // 42MB of random data
//! let original_data_copy = original_data.clone();
//!
//!
//! // Build the blob and collect all generated chunks.
//! // Remember these proof-carrying chunks don't carry a proof-of-inclusion
//! // in the blob, rather they carry only proof-of-inclusion in corresponding chunkset
//! // that they belong to.
//! let (mut chunks, blob_header) = {
//!     let mut all_chunks = Vec::new();
//!
//!     let mut blob_builder = BlobBuilder::init();
//!     if let Some(chunks) = blob_builder.update(&original_data) {
//!         all_chunks.extend(chunks);
//!     }
//!
//!     let (final_chunks, blob_header) = blob_builder.finalize().expect("Failed to finalize blob");
//!     all_chunks.extend(final_chunks);
//!
//!     (all_chunks, blob_header)
//! };
//!
//! // We have to collect root commitments of all chunksets, as we will build a Merkle tree on them,
//! // considering they are the leaf nodes of the Merkle tree.
//! let chunkset_root_commitments = (0..blob_header.get_num_chunksets())
//!     .map(|chunkset_id| unsafe { blob_header.get_chunkset_commitment(chunkset_id).unwrap_unchecked() })
//!     .collect();
//!
//! // This is the Merkle tree build on chunkset root commitments, giving us a blob level root commitment.
//! let merkle_tree = MerkleTree::new(chunkset_root_commitments).expect("Must be able to build Merkle tree");
//! // Let's generate Merkle proof-of-inclusion for each chunkset. We will extend each chunk's proof to include
//! // corresponding chunkset's inclusion proof in the blob root commitment.
//! let merkle_proofs = (0..blob_header.get_num_chunksets())
//!     .into_par_iter()
//!     .map(|chunkset_id| unsafe { (chunkset_id, merkle_tree.generate_proof(chunkset_id).unwrap_unchecked()) })
//!     .collect::<HashMap<usize, Vec<blake3::Hash>>>();
//! // Extend each proof-carrying chunk to include proof-of-inclusion in the blob.
//! // And this completes blob building phase.
//! chunks.par_iter_mut().for_each(|chunk| {
//!     chunk.append_proof_to_blob_root(&merkle_proofs[&chunk.get_chunkset_id()]);
//! });
//!
//! // Simulate data loss and reordering by shuffling and taking only a subset (but enough for repair).
//! // In a real scenario, you'd receive chunks from various sources.
//! chunks.shuffle(&mut rng);
//!
//! // Let's try to repair the full blob.
//! let mut repairer = RepairingBlob::new(blob_header.clone());
//! let num_chunksets = blob_header.get_num_chunksets();
//!
//! // Add chunks to the repairer until all chunksets are repaired.
//! let mut chunk_idx = 0;
//! let mut repaired_chunksets_count = 0;
//!
//! while repaired_chunksets_count < num_chunksets {
//!     if chunk_idx >= chunks.len() {
//!         println!("Not enough chunks to repair the entire blob!");
//!         break;
//!     }
//!
//!     let chunk = &chunks[chunk_idx];
//!     let chunkset_id = chunk.get_chunkset_id();
//!
//!     // Try to add the chunk, handling various repair states.
//!     match repairer.add_chunk(chunk) {
//!         Ok(_) => {
//!             if repairer.is_chunkset_ready_to_repair(chunkset_id).expect("Failed to check chunkset repair status") {
//!                 repaired_chunksets_count += 1;
//!                 println!("Repaired chunkset {}!", chunkset_id);
//!             }
//!         },
//!         Err(e) => {
//!             // Handle cases where the chunk is not useful or chunkset is already repaired
//!             match e {
//!                 DecdsError::ChunksetReadyToRepair(_) | DecdsError::ChunksetAlreadyRepaired(_) | DecdsError::InvalidProofInChunk(_) => {
//!                     // Chunk is redundant, already repaired, or invalid; simply skip it.
//!                     // In case we get invalid proof-of-inclusion, it means some intermediary must have tampered with it.
//!                 },
//!                 _ => {
//!                     eprintln!("Error adding chunk: {:?}", e);
//!                     std::process::exit(1);
//!                 },
//!             }
//!         },
//!     }
//!
//!     chunk_idx += 1;
//! }
//!
//! // As we didn't tamper with any proof-carrying chunks, it must be possible for us to recover the
//! // whole blob. Let's recover and compare.
//! let final_repaired_data = (0..blob_header.get_num_chunksets()).flat_map(|chunkset_id| {
//!     repairer.get_repaired_chunkset(chunkset_id).expect("Failed to get repaired chunkset")
//! }).collect::<Vec<u8>>();
//!
//! assert_eq!(original_data_copy, final_repaired_data);
//! println!("Blob successfully repaired and verified!");
//! ```

mod blob;
mod chunk;
mod chunkset;
mod consts;
mod errors;
mod merkle_tree;

#[cfg(test)]
mod tests;

pub use blob::{BlobBuilder, BlobHeader, RepairingBlob};
pub use chunk::ProofCarryingChunk;
pub use chunkset::RepairingChunkSet;
pub use consts::DECDS_NUM_ERASURE_CODED_SHARES;
pub use errors::DecdsError;
pub use merkle_tree::MerkleTree;
