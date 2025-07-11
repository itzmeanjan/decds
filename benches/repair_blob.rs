use decds::{Blob, DECDS_NUM_ERASURE_CODED_SHARES, ProofCarryingChunk, RepairingBlob};
use rand::{Rng, seq::SliceRandom};
use std::{fmt::Debug, time::Duration};

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
            let blob = unsafe { Blob::new(data).unwrap_unchecked() };

            let blob_header = blob.get_blob_header();
            let mut blob_shares = (0..(DECDS_NUM_ERASURE_CODED_SHARES - 4))
                .flat_map(|share_id| unsafe { blob.get_share(share_id).unwrap_unchecked() })
                .collect::<Vec<ProofCarryingChunk>>();
            blob_shares.shuffle(&mut rng);

            (blob_header.to_owned(), blob_shares)
        })
        .input_counter(|(header, _)| divan::counter::BytesCount::new(header.get_blob_size()))
        .bench_values(|(header, chunks)| {
            let mut repairer = RepairingBlob::new(divan::black_box(header));
            for chunk in chunks.iter() {
                let _ = divan::black_box(&mut repairer).add_chunk(divan::black_box(chunk));
            }
        });
}
