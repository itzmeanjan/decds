use crate::utils::{format_bytes, read_blob_metadata, read_proof_carrying_chunk};
use decds_lib::{BlobHeader, DECDS_NUM_ERASURE_CODED_SHARES};
use std::{path::PathBuf, process::exit};

pub fn handle_verify_command(blob_dir_path: &PathBuf) {
    if !blob_dir_path.is_dir() {
        eprintln!("{:?} is not a directory", blob_dir_path);
        exit(1);
    }

    let mut blob_metadata_path = blob_dir_path.clone();
    blob_metadata_path.push("metadata.commit");

    println!("Looking for erasure-coded blob metadata file {:?}...", blob_metadata_path);
    let blob_metadata = read_blob_metadata(&blob_metadata_path);

    println!("Original blob size: {}", format_bytes(blob_metadata.get_blob_size()));
    println!("Original blob BLAKE3 Digest: {}", blob_metadata.get_blob_digest());
    println!("Original blob root commitment: {}", blob_metadata.get_root_commitment());
    println!("Original blob number of chunksets: {}", blob_metadata.get_num_chunksets());
    println!("Original blob number of chunks: {}", blob_metadata.get_num_chunks());

    verify_erasure_coded_chunks_and_report(blob_dir_path, &blob_metadata);
}

fn verify_erasure_coded_chunks_and_report(target_dir: &PathBuf, blob_metadata: &BlobHeader) {
    let mut blob_share_path = target_dir.clone();
    let mut indent = String::new();
    let mut total_num_valid_chunks = 0;

    println!("Verifying erasure-coded proof-carrying chunks...\n");
    println!("{}", blob_share_path.to_str().unwrap());

    (0..blob_metadata.get_num_chunksets()).for_each(|chunkset_id| {
        blob_share_path.push(format!("chunkset.{}", chunkset_id));
        indent.push('\t');

        let (console_log, num_valid_shares) =
            (0..DECDS_NUM_ERASURE_CODED_SHARES).fold((String::new(), 0usize), |(mut console_log, mut num_valid_shares), share_id| {
                blob_share_path.push(format!("share{:02}.data", share_id));
                indent.push('\t');

                let share_stat_log = if let Ok(ok) = blob_share_path.try_exists()
                    && ok
                {
                    match read_proof_carrying_chunk(&blob_share_path) {
                        Ok(chunk) => {
                            if blob_metadata.validate_chunk(&chunk) {
                                num_valid_shares += 1;
                                format!("{}- {}\t✅", indent, blob_share_path.file_name().unwrap().to_str().unwrap())
                            } else {
                                format!(
                                    "{}- {}\t🚫\tError: proof verification failed",
                                    indent,
                                    blob_share_path.file_name().unwrap().to_str().unwrap()
                                )
                            }
                        }
                        Err(e) => {
                            format!("{}- {}\t🚫\tError: {}", indent, blob_share_path.file_name().unwrap().to_str().unwrap(), e)
                        }
                    }
                } else {
                    format!(
                        "{}- {}\t🚫\tError: chunk not present",
                        indent,
                        blob_share_path.file_name().unwrap().to_str().unwrap()
                    )
                };

                blob_share_path.pop();
                indent.pop();

                console_log.push_str(&share_stat_log);
                console_log.push('\n');

                (console_log, num_valid_shares)
            });

        println!(
            "{}- {}\t({}/{})",
            indent,
            blob_share_path.file_name().unwrap().to_str().unwrap(),
            num_valid_shares,
            DECDS_NUM_ERASURE_CODED_SHARES
        );
        println!("{}", console_log);

        total_num_valid_chunks += num_valid_shares;

        blob_share_path.pop();
        indent.pop();
    });

    println!(
        "Found {}/{} valid chunks in {:?}.",
        total_num_valid_chunks,
        blob_metadata.get_num_chunks(),
        target_dir
    );
}
