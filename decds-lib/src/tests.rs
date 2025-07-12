use crate::{Blob, ProofCarryingChunk, RepairingBlob, consts, errors::DecdsError};
use rand::{Rng, seq::SliceRandom};

#[test]
fn prop_test_blob_building_and_repairing_works() {
    const NUM_TEST_ITERATIONS: usize = 10;

    const MIN_BLOB_DATA_BYTE_LEN: usize = 1usize;
    const MAX_BLOB_DATA_BYTE_LEN: usize = 1usize << 28;

    let mut rng = rand::rng();

    (0..NUM_TEST_ITERATIONS).for_each(|_| {
        let blob_byte_len = rng.random_range(MIN_BLOB_DATA_BYTE_LEN..=MAX_BLOB_DATA_BYTE_LEN);
        let blob_data = (0..blob_byte_len).map(|_| rng.random()).collect::<Vec<u8>>();

        let blob = Blob::new(blob_data.clone()).expect("Must be able to prepare blob");

        let blob_header = blob.get_blob_header().to_owned();
        let mut chunk_shares = (0..consts::DECDS_NUM_ERASURE_CODED_SHARES)
            .flat_map(|share_id| unsafe { blob.get_share(share_id).unwrap_unchecked() })
            .collect::<Vec<ProofCarryingChunk>>();
        chunk_shares.shuffle(&mut rng);

        let mut repairer = RepairingBlob::new(blob_header.clone());
        let mut shares = chunk_shares.iter();

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
