use decds_lib::{BlobBuilder, MerkleTree, RepairingBlob};
use rand::{Rng, seq::SliceRandom};
use rayon::prelude::*;
use std::{collections::HashMap, fmt::Debug, time::Duration};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::Divan::default().bytes_format(divan::counter::BytesFormat::Binary).main();
}

struct BlobConfig {
    data_byte_len: usize,
}

fn bytes_to_human_readable(bytes: usize) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut bytes = bytes as f64;
    let mut unit_index = 0;

    while bytes >= 1024.0 && unit_index < units.len() - 1 {
        bytes /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", bytes, units[unit_index])
}

impl Debug for BlobConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("Verify + Repair Erasure Coded {} blob", &bytes_to_human_readable(self.data_byte_len),))
    }
}

const ARGS: &[BlobConfig] = &[
    BlobConfig { data_byte_len: 1usize << 20 },
    BlobConfig { data_byte_len: 1usize << 24 },
    BlobConfig { data_byte_len: 1usize << 28 },
    BlobConfig { data_byte_len: 1usize << 30 },
    BlobConfig { data_byte_len: 1usize << 32 },
];

#[divan::bench(args = ARGS, max_time = Duration::from_secs(100), skip_ext_time = true)]
fn repair_blob(bencher: divan::Bencher, rlnc_config: &BlobConfig) {
    bencher
        .with_inputs(|| {
            let mut rng = rand::rng();
            let data = (0..rlnc_config.data_byte_len).map(|_| rng.random()).collect::<Vec<u8>>();
            let (mut chunks, blob_header) = {
                let mut all_chunks = Vec::new();

                let mut blob_builder = BlobBuilder::init();
                if let Some(chunks) = blob_builder.update(&data) {
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
            (blob_header.to_owned(), chunks)
        })
        .input_counter(|(header, _)| divan::counter::BytesCount::new(header.get_blob_size()))
        .bench_values(|(header, chunks)| {
            let mut repairer = RepairingBlob::new(divan::black_box(header));
            for chunk in chunks.iter() {
                let _ = divan::black_box(&mut repairer).add_chunk(divan::black_box(chunk));
            }
        });
}
