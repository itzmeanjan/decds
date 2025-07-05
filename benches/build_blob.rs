use decds::blob::Blob;
use rand::Rng;
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
        f.write_str(&format!(
            "Erasure code + Generate Merkle proof for {} blob",
            &bytes_to_human_readable(self.data_byte_len),
        ))
    }
}

const ARGS: &[BlobConfig] = &[
    BlobConfig { data_byte_len: 1usize << 20 },
    BlobConfig { data_byte_len: 1usize << 24 },
    BlobConfig { data_byte_len: 1usize << 28 },
    BlobConfig { data_byte_len: 1usize << 30 },
    BlobConfig { data_byte_len: 1usize << 32 },
];

#[divan::bench(args = ARGS, max_time = Duration::from_secs(200), skip_ext_time = true)]
fn build_blob(bencher: divan::Bencher, rlnc_config: &BlobConfig) {
    bencher
        .with_inputs(|| {
            let mut rng = rand::rng();
            (0..rlnc_config.data_byte_len).map(|_| rng.random()).collect::<Vec<u8>>()
        })
        .input_counter(|data| divan::counter::BytesCount::new(data.len()))
        .bench_values(|data| divan::black_box(Blob::new(divan::black_box(data))));
}
