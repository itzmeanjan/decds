use crate::{
    errors::DecdsCLIError,
    utils::{format_bytes, get_target_directory_path, read_proof_carrying_chunk},
};
use decds_lib::{BlobBuilder, BlobHeader, DECDS_NUM_ERASURE_CODED_SHARES, MerkleTree, ProofCarryingChunk};
use rayon::prelude::*;
use std::{fs::File, io::Read, path::PathBuf, process::exit};

pub fn handle_break_command(blob_path: &PathBuf, opt_target_dir: &Option<PathBuf>) {
    match std::fs::OpenOptions::new().read(true).open(blob_path) {
        Ok(fd) => {
            let mut rng = rand::rng();
            let target_dir_path = get_target_directory_path(blob_path, opt_target_dir, &mut rng);

            if let Err(e) = std::fs::DirBuilder::new().recursive(true).create(&target_dir_path) {
                eprintln!("Error: {}", e);
                exit(1);
            }

            println!("Reading {:?}", blob_path);
            println!("Writing blob metadata and erasure-coded chunks in {:?}", target_dir_path);

            let metadata = read_blob_data_and_write_partial_chunks(fd, &target_dir_path);

            println!("Blob size {}", format_bytes(metadata.get_blob_size()));
            println!("Blob BLAKE3 digest: {}", metadata.get_blob_digest());
            println!("Blob root commitment: {}", metadata.get_root_commitment());
            println!("Blob number of chunksets: {}", metadata.get_num_chunksets());
            println!("Blob number of chunks: {}", metadata.get_num_chunks());

            write_blob_metadata(&target_dir_path, &metadata);
            finalize_proof_carrying_chunks(&metadata, &target_dir_path);

            println!("Erasure-coded chunks placed in {:?}", &target_dir_path);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            exit(1);
        }
    }
}

fn read_blob_data_and_write_partial_chunks(fd: File, target_dir_path: &PathBuf) -> BlobHeader {
    const ONE_MB: usize = 1usize << 20;
    const TEN_MB: usize = 10 * ONE_MB;

    let mut buffered_fd = std::io::BufReader::with_capacity(TEN_MB, fd);
    let mut blob_builder = BlobBuilder::init();

    let (blob_reader, blob_builder_in) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
    let (blob_builder_out, chunk_writer) = std::sync::mpsc::sync_channel::<Vec<ProofCarryingChunk>>(1);

    // Thread for handling read from input data blob file.
    let reader_handle = std::thread::spawn(move || {
        let mut has_read_all = false;

        'OUTER: loop {
            let mut buffer_offset = 0;
            let mut buffer = vec![0u8; TEN_MB];

            'INNER: while buffer_offset < buffer.len() {
                match buffered_fd.read(&mut buffer[buffer_offset..]) {
                    Ok(n) => {
                        buffer_offset += n;
                        if n == 0 {
                            has_read_all = true;
                            break 'INNER;
                        }
                    }
                    Err(_) => {}
                }
            }

            if buffer_offset > 0 {
                buffer.truncate(buffer_offset);

                if let Err(e) = blob_reader.send(buffer) {
                    return Err(DecdsCLIError::FailedToSendBlobDataToBlobBuilder(format!(
                        "failed to send {} bytes blob data to blob builder, over sync channel",
                        e.0.len()
                    )));
                }
            }

            if has_read_all {
                break 'OUTER;
            }
        }

        Ok(())
    });

    // Thread for writing erasure-coded chunks to on-disk file.
    let target_dir_path_cloned = target_dir_path.clone();
    let writer_handle = std::thread::spawn(move || {
        while let Ok(chunks) = chunk_writer.recv() {
            chunks.into_par_iter().for_each(|chunk| {
                write_proof_carrying_chunk(&target_dir_path_cloned, chunk);
            });
        }
    });

    // Loop run by main thread for
    //
    // 1) Receiving input data blobs from one thread
    // 2) Updating blob-builder state
    // 3) Sending erasure-coded chunks to another thread
    while let Ok(buffer) = blob_builder_in.recv() {
        if let Some(chunks) = blob_builder.update(&buffer) {
            if let Err(e) = blob_builder_out.send(chunks) {
                eprintln!("Failed to send {} erasure-coded chunks to another thread, over sync channel", e.0.len());
                exit(1);
            }
        }
    }

    drop(blob_builder_out);

    if let Err(e) = reader_handle.join() {
        eprintln!("Error: {:?}", e);
        exit(1);
    }
    writer_handle.join().unwrap();

    match blob_builder.finalize() {
        Ok((chunks, blob_header)) => {
            chunks.into_par_iter().for_each(|chunk| {
                write_proof_carrying_chunk(&target_dir_path, chunk);
            });

            blob_header
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            exit(1);
        }
    }
}

fn finalize_proof_carrying_chunks(metadata: &BlobHeader, target_dir_path: &PathBuf) {
    if metadata.get_num_chunksets() == 1 {
        return;
    }

    let chunkset_root_commitments = (0..metadata.get_num_chunksets())
        .map(|chunkset_id| unsafe { metadata.get_chunkset_commitment(chunkset_id).unwrap_unchecked() })
        .collect();
    let merkle_tree = unsafe { MerkleTree::new(chunkset_root_commitments).unwrap_unchecked() };

    (0..metadata.get_num_chunks()).into_par_iter().for_each(|chunk_id| {
        let chunkset_id = chunk_id / DECDS_NUM_ERASURE_CODED_SHARES;
        let blob_level_proof = unsafe { merkle_tree.generate_proof(chunkset_id).unwrap_unchecked() };

        let mut blob_share_path = target_dir_path.clone();
        blob_share_path.push(format!("chunkset.{}", chunkset_id));
        blob_share_path.push(format!("share{:02}.data", chunk_id));

        if let Ok(mut chunk) = read_proof_carrying_chunk(&blob_share_path) {
            chunk.append_proof_to_blob_root(&blob_level_proof);

            if let Ok(bytes) = chunk.to_bytes() {
                if let Err(e) = std::fs::write(&blob_share_path, bytes) {
                    eprintln!("Error: {:?}", e);
                    exit(1);
                }
            }
        }
    });
}

fn write_blob_metadata(target_dir: &PathBuf, metadata: &BlobHeader) {
    let mut blob_metadata_path = target_dir.clone();
    blob_metadata_path.push("metadata.commit");

    match metadata.to_bytes() {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(blob_metadata_path, bytes) {
                eprintln!("Error: {}", e);
                exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            exit(1);
        }
    }
}

pub fn write_proof_carrying_chunk(target_dir: &PathBuf, chunk: ProofCarryingChunk) {
    match chunk.to_bytes() {
        Ok(bytes) => {
            let mut blob_share_path = target_dir.clone();
            blob_share_path.push(format!("chunkset.{}", chunk.get_chunkset_id()));

            if let Err(e) = std::fs::create_dir_all(&blob_share_path) {
                eprintln!("Error: {}", e);
                exit(1);
            }

            blob_share_path.push(format!("share{:02}.data", chunk.get_local_chunk_id()));

            if let Err(e) = std::fs::write(&blob_share_path, bytes) {
                eprintln!("Error: {}", e);
                exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            exit(1);
        }
    };
}
