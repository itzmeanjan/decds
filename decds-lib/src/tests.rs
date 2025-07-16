use crate::{BlobBuilder, DecdsError, MerkleTree, RepairingBlob};
use rand::{Rng, seq::SliceRandom};
use rayon::prelude::*;
use std::collections::HashMap;

#[test]
fn prop_test_blob_building_and_repairing_works() {
    const NUM_TEST_ITERATIONS: usize = 10;

    const MIN_BLOB_DATA_BYTE_LEN: usize = 1usize;
    const MAX_BLOB_DATA_BYTE_LEN: usize = 1usize << 28;

    let mut rng = rand::rng();

    (0..NUM_TEST_ITERATIONS).for_each(|_| {
        let blob_byte_len = rng.random_range(MIN_BLOB_DATA_BYTE_LEN..=MAX_BLOB_DATA_BYTE_LEN);
        let blob_data = (0..blob_byte_len).map(|_| rng.random()).collect::<Vec<u8>>();

        let (mut chunks, blob_header) = {
            let mut all_chunks = Vec::new();

            let mut blob_builder = BlobBuilder::init();
            if let Some(chunks) = blob_builder.update(&blob_data) {
                all_chunks.extend(chunks);
            }

            let (chunks, blob_header) = blob_builder.finalize().expect("Must be able to prepare blob");
            all_chunks.extend(chunks);

            (all_chunks, blob_header)
        };

        let chunkset_root_commitments = (0..blob_header.get_num_chunksets())
            .map(|chunkset_id| unsafe { blob_header.get_chunkset_commitment(chunkset_id).unwrap_unchecked() })
            .collect();

        let merkle_tree = MerkleTree::new(chunkset_root_commitments).expect("Must be able to build Merkle tree");
        let merkle_proofs = (0..blob_header.get_num_chunksets())
            .into_par_iter()
            .map(|chunkset_id| unsafe { (chunkset_id, merkle_tree.generate_proof(chunkset_id).unwrap_unchecked()) })
            .collect::<HashMap<usize, Vec<blake3::Hash>>>();

        chunks.par_iter_mut().for_each(|chunk| {
            chunk.append_proof_to_blob_root(&merkle_proofs[&chunk.get_chunkset_id()]);
        });

        chunks.shuffle(&mut rng);

        let mut repairer = RepairingBlob::new(blob_header.clone());
        let mut shares = chunks.iter();

        loop {
            if let Some(share) = shares.next() {
                match repairer.add_chunk(share) {
                    Ok(()) => { /* Found a useful chunk */ }
                    Err(e) => match e {
                        DecdsError::ChunkDecodingFailed(id, _) => unsafe {
                            assert!(!repairer.is_chunkset_ready_to_repair(id).unwrap_unchecked());
                            assert!(!repairer.is_chunkset_already_repaired(id).unwrap_unchecked());
                        },
                        DecdsError::ChunksetReadyToRepair(id) => unsafe {
                            assert!(repairer.is_chunkset_ready_to_repair(id).unwrap_unchecked());
                            assert!(!repairer.is_chunkset_already_repaired(id).unwrap_unchecked());
                        },
                        _ => {
                            panic!("Didn't expect to encounter: {}", e)
                        }
                    },
                }
            } else {
                break;
            }
        }

        let repaired_blob_data = (0..blob_header.get_num_chunksets())
            .flat_map(|chunkset_id| unsafe { repairer.get_repaired_chunkset(chunkset_id).unwrap_unchecked() })
            .collect::<Vec<u8>>();

        assert_eq!(repaired_blob_data, blob_data);
    });
}
