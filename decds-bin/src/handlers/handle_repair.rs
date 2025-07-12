use crate::utils::{format_bytes, get_target_directory_path, read_blob_metadata, read_proof_carrying_chunk};
use decds_lib::{DECDS_NUM_ERASURE_CODED_SHARES, DECDSError, RepairingBlob};
use std::{io::Write, path::PathBuf, process::exit};

pub fn handle_repair_command(chunk_dir_path: &PathBuf, opt_target_dir: &Option<PathBuf>) {
    if !chunk_dir_path.is_dir() {
        eprintln!("{:?} is not a directory", chunk_dir_path);
        exit(1);
    }

    let mut blob_metadata_path = chunk_dir_path.clone();
    blob_metadata_path.push("metadata.commit");

    println!("Looking for erasure-coded blob metadata file {:?}...", blob_metadata_path);
    let blob_metadata = read_blob_metadata(&blob_metadata_path);

    println!("Original blob size: {}", format_bytes(blob_metadata.get_blob_size()));
    println!("Original blob BLAKE3 Digest: {}", blob_metadata.get_blob_digest());
    println!("Original blob root commitment: {}", blob_metadata.get_root_commitment());
    println!("Original blob number of chunksets: {}", blob_metadata.get_num_chunksets());
    println!("Original blob number of chunks: {}", blob_metadata.get_num_chunks());

    let mut rng = rand::rng();
    let mut target_dir_path = get_target_directory_path(chunk_dir_path, opt_target_dir, &mut rng);

    if let Err(e) = std::fs::DirBuilder::new().recursive(true).create(&target_dir_path) {
        eprintln!("Error: {}", e);
        exit(1);
    }

    println!("Repairing chunksets and blob in {:?}...", target_dir_path);

    let mut blob_share_path = chunk_dir_path.clone();
    let mut repairer = RepairingBlob::new(blob_metadata.clone());
    let mut chunkset_id = 0;

    while chunkset_id < blob_metadata.get_num_chunksets() {
        blob_share_path.push(format!("chunkset.{}", chunkset_id));
        target_dir_path.push(format!("chunkset.{}.data", chunkset_id));

        let mut share_id = 0;
        while (share_id < DECDS_NUM_ERASURE_CODED_SHARES) && unsafe { !repairer.is_chunkset_ready_to_repair(chunkset_id).unwrap_unchecked() } {
            blob_share_path.push(format!("share{:02}.data", share_id));

            if blob_share_path.is_file() {
                if let Ok(chunk) = read_proof_carrying_chunk(&blob_share_path) {
                    match repairer.add_chunk(&chunk) {
                        Ok(()) => {}
                        Err(e) => match e {
                            DECDSError::InvalidProofInChunk(_) => {}
                            DECDSError::InvalidChunkMetadata(_) => {}
                            DECDSError::ChunkDecodingFailed(_, _) => {}
                            _ => {
                                eprintln!("Encountered unexpected error: {}", e);
                                exit(1);
                            }
                        },
                    };
                }
            }

            blob_share_path.pop();
            share_id += 1;
        }

        if unsafe { !repairer.is_chunkset_ready_to_repair(chunkset_id).unwrap_unchecked() } {
            eprintln!("Failed repair chunkset {:?}", blob_share_path);
            exit(1);
        }

        let repaired_chunkset = unsafe { repairer.get_repaired_chunkset(chunkset_id).unwrap_unchecked() };
        if let Err(e) = std::fs::write(&target_dir_path, repaired_chunkset) {
            eprintln!("Error: {}", e);
            exit(1);
        }

        target_dir_path.pop();
        blob_share_path.pop();
        chunkset_id += 1;
    }

    let mut repaired_blob_path = target_dir_path.clone();
    repaired_blob_path.push("repaired.data");

    let repaired_blob_digest = match std::fs::OpenOptions::new().create_new(true).write(true).open(&repaired_blob_path) {
        Ok(fd) => {
            let mut buffered_fd = std::io::BufWriter::new(fd);
            let mut blake3_hasher = blake3::Hasher::new();

            let mut chunkset_id = 0;
            while chunkset_id < blob_metadata.get_num_chunksets() {
                target_dir_path.push(format!("chunkset.{}.data", chunkset_id));

                match std::fs::read(&target_dir_path) {
                    Ok(bytes) => {
                        if let Err(e) = buffered_fd.write_all(&bytes) {
                            eprintln!("Error: {}", e);
                            exit(1);
                        }

                        blake3_hasher.update(&bytes);
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        exit(1);
                    }
                }

                if let Err(e) = std::fs::remove_file(&target_dir_path) {
                    eprintln!("Error: {}", e);
                }

                target_dir_path.pop();
                chunkset_id += 1;
            }

            if let Err(e) = buffered_fd.flush() {
                eprintln!("Error: {}", e);
                exit(1);
            }

            blake3_hasher.finalize()
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            exit(1);
        }
    };

    println!("Repaired blob @ {:?}", repaired_blob_path);
    println!("BLAKE3 Digest of {:?}: {}", repaired_blob_path, repaired_blob_digest);
}
