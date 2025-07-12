//! # DECDS-lib: Decentralized Erasure-Coded Data Storage Library
//!
//! `decds-lib` provides functionalities for creating, storing, retrieving, and repairing arbitrary size data blobs
//! using Random Linear Network Coding (RLNC) based erasure-coding and binary Merkle trees for data integrity verification.
//!
//! This library is designed to enable decentralized data storage solutions by breaking down
//! large data into smaller, verifiable, and reconstructible chunks.
//!
//! ## How to Use
//!
//! ### 1. Create a Blob
//!
//! To store data, first create a `Blob` from a `Vec<u8>`. The `Blob::new` function
//! takes your raw data, divides it into chunksets, applies erasure coding, and builds
//! Merkle trees for both chunkset-level and blob-level integrity.
//!
//! ```rust
//! use decds_lib::Blob;
//! use rand::Rng; // Assuming `rand` is available in your project for example data
//!
//! let mut rng = rand::thread_rng();
//! let original_data: Vec<u8> = (0..1024 * 1024 * 50).map(|_| rng.random()).collect(); // 50MB of random data
//! let blob = Blob::new(original_data).expect("Failed to create blob");
//! println!("Blob created with size: {} bytes", blob.get_blob_header().get_blob_size());
//! ```
//!
//! ### 2. Retrieve Erasure-Coded Shares (Proof-Carrying Chunks)
//!
//! Once a `Blob` is created, you can retrieve its erasure-coded shares. Each share is a `Vec<ProofCarryingChunk>`,
//! where each `ProofCarryingChunk` is a verifiable piece of data.
//! You need `DECDS_NUM_ERASURE_CODED_SHARES` total shares per chunkset, but only `ChunkSet::NUM_ORIGINAL_CHUNKS`
//! (which is 10) are needed to reconstruct the original data of that chunkset.
//!
//! ```rust
//! use decds_lib::{Blob, DECDS_NUM_ERASURE_CODED_SHARES};
//! use rand::Rng;
//!
//! let mut rng = rand::thread_rng();
//! let original_data: Vec<u8> = (0..1024).map(|_| rng.random()).collect();
//! let blob = Blob::new(original_data).expect("Failed to create blob");
//!
//! let first_share = blob.get_share(0).expect("Failed to get share");
//! println!("Retrieved {} chunks for share 0.", first_share.len());
//!
//! // You can iterate through all available shares:
//! for share_id in 0..DECDS_NUM_ERASURE_CODED_SHARES {
//!     let share = blob.get_share(share_id).expect("Failed to get share");
//!     // Do something with the share, e.g., send it to a storage node
//! }
//! ```
//!
//! ### 3. Repair/Reconstruct a Blob
//!
//! To reconstruct the original blob data, you need to collect enough `ProofCarryingChunk`s.
//! You initialize a `RepairingBlob` with the `BlobHeader` (which can be serialized/deserialized),
//! and then add chunks to it. Once enough chunks for a specific chunkset are collected,
//! you can retrieve its repaired data.
//!
//! ```rust
//! use decds_lib::{Blob, BlobHeader, ProofCarryingChunk, RepairingBlob, DECDS_NUM_ERASURE_CODED_SHARES, DecdsError};
//! use rand::{Rng, seq::SliceRandom};
//!
//! let mut rng = rand::thread_rng();
//! let original_data: Vec<u8> = (0..1024 * 1024 * 50).map(|_| rng.random()).collect(); // 50MB of random data
//! let original_data_copy = original_data.clone();
//!
//! let blob = Blob::new(original_data).expect("Failed to create blob");
//! let blob_header = blob.get_blob_header().clone();
//!
//! // Collect all chunks from the blob (simulate receiving them from storage)
//! let mut all_chunks: Vec<ProofCarryingChunk> = (0..DECDS_NUM_ERASURE_CODED_SHARES)
//!     .flat_map(|share_id| blob.get_share(share_id).unwrap())
//!     .collect();
//!
//! // Simulate data loss by shuffling and taking only a subset (but enough for repair)
//! // In a real scenario, you'd receive chunks from various sources
//! all_chunks.shuffle(&mut rng);
//!
//! let mut repairer = RepairingBlob::new(blob_header.clone());
//! let num_chunksets = blob_header.get_num_chunksets();
//!
//! // Add chunks to the repairer until all chunksets are repaired
//! let mut chunk_idx = 0;
//! let mut repaired_chunksets_count = 0;
//!
//! while repaired_chunksets_count < num_chunksets {
//!     if chunk_idx >= all_chunks.len() {
//!         println!("Not enough chunks to repair the entire blob!");
//!         break;
//!     }
//!     let chunk = &all_chunks[chunk_idx];
//!     let chunkset_id = chunk.get_chunkset_id();
//!     // Try to add the chunk, handling various repair states
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
//!                     // In a real system, invalid chunks would indicate a security issue.
//!                 },
//!                 _ => {
//!                     eprintln!("Error adding chunk: {}", e);
//!                     std::process::exit(1);
//!                 },
//!             }
//!         },
//!     }
//!     chunk_idx += 1;
//! }
//!
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

pub use blob::{Blob, BlobHeader, RepairingBlob};
pub use chunk::ProofCarryingChunk;
pub use chunkset::RepairingChunkSet;
pub use consts::DECDS_NUM_ERASURE_CODED_SHARES;
pub use errors::DecdsError;
