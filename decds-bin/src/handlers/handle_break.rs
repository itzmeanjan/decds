use crate::utils::{format_bytes, get_target_directory_path};
use console::Term;
use console_static_text::{ConsoleSize, ConsoleStaticText};
use decds_lib::{BlobBuilder, BlobHeader, DECDS_NUM_ERASURE_CODED_SHARES, MerkleTree, ProofCarryingChunk};
use std::{
    io::Read,
    path::PathBuf,
    process::exit,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio::task::JoinSet;

pub fn handle_break_command(blob_path: &PathBuf, opt_target_dir: &Option<PathBuf>) {
    match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => {
            rt.block_on(async move {
                let mut rng = rand::rng();
                let target_dir_path = get_target_directory_path(blob_path, opt_target_dir, &mut rng);

                if let Err(e) = std::fs::DirBuilder::new().recursive(true).create(&target_dir_path) {
                    eprintln!("Failed to create target directory {:?} to put chunks: {:?}", target_dir_path, e);
                    exit(1);
                }

                println!("Reading {:?}", blob_path);
                println!("Writing blob metadata and erasure-coded chunks in {:?}", target_dir_path);

                let metadata = read_blob_and_partially_chunkify(blob_path.to_owned(), target_dir_path.to_owned()).await;

                println!("Blob size {}", format_bytes(metadata.get_blob_size()));
                println!("Blob BLAKE3 digest: {}", metadata.get_blob_digest());
                println!("Blob root commitment: {}", metadata.get_root_commitment());
                println!("Blob number of chunksets: {}", metadata.get_num_chunksets());
                println!("Blob number of chunks: {}", metadata.get_num_chunks());

                write_blob_metadata(&target_dir_path, &metadata).await;
                finalize_proof_carrying_chunks(metadata, target_dir_path.to_owned()).await;

                println!("Erasure-coded chunks placed in {:?}", target_dir_path);
            });
        }
        Err(e) => {
            eprintln!("Failed to create a `tokio` async runtime: {:?}", e);
            exit(1);
        }
    }
}

async fn read_blob_and_partially_chunkify(blob_path: PathBuf, target_dir_path: PathBuf) -> BlobHeader {
    let (blob_tx, blob_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(num_cpus::get() * 4);
    let (chunk_tx, chunk_rx) = tokio::sync::mpsc::channel::<Vec<ProofCarryingChunk>>(num_cpus::get() * 4);

    let blob_reader_task = tokio::task::spawn_blocking(move || read_blob_data(blob_path, blob_tx));
    let blob_builder_task = tokio::task::spawn_blocking(move || build_blob(blob_rx, chunk_tx));
    let chunk_writer_task = tokio::task::spawn(write_partial_chunks(target_dir_path, chunk_rx));

    if let Err(e) = blob_reader_task.await {
        eprintln!("Blob reader task failed to finish: {:?}", e);
        exit(1);
    }

    if let Err(e) = chunk_writer_task.await {
        eprintln!("Partial chunk writer task failed to finish: {:?}", e);
        exit(1);
    }

    match blob_builder_task.await {
        Ok(metadata) => metadata,
        Err(e) => {
            eprintln!("Blob builder task failed to finish: {:?}", e);
            exit(1);
        }
    }
}

fn read_blob_data(blob_path: PathBuf, blob_tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
    match std::fs::OpenOptions::new().read(true).open(&blob_path) {
        Ok(fd) => {
            const ONE_MB: usize = 1usize << 20;
            const TEN_MB: usize = 10 * ONE_MB;
            const SIXTEEN_MB: usize = 16 * ONE_MB;

            let mut has_read_all = false;
            let mut buffered_fd = std::io::BufReader::with_capacity(SIXTEEN_MB, fd);
            let mut buffer = vec![0u8; num_cpus::get() * TEN_MB];

            'OUTER: loop {
                let mut buffer_offset = 0;

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
                    if let Err(e) = blob_tx.blocking_send(buffer[..buffer_offset].to_vec()) {
                        eprintln!("Failed to send {} bytes blob data to blob builder task, over channel", e.0.len());
                        exit(1);
                    }
                }

                if has_read_all {
                    break 'OUTER;
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to open input blob file {:?}: {:?}", blob_path, e);
            exit(1);
        }
    }
}

fn build_blob(mut blob_rx: tokio::sync::mpsc::Receiver<Vec<u8>>, chunk_tx: tokio::sync::mpsc::Sender<Vec<ProofCarryingChunk>>) -> BlobHeader {
    let mut blob_builder = BlobBuilder::init();

    let mut progress = ConsoleStaticText::new(|| {
        let (rows, cols) = Term::stdout().size();
        ConsoleSize {
            rows: Some(rows),
            cols: Some(cols),
        }
    });
    let now = Instant::now();

    while let Some(buffer) = blob_rx.blocking_recv() {
        if let Some(chunks) = blob_builder.update(&buffer) {
            if let Err(e) = chunk_tx.blocking_send(chunks) {
                eprintln!("Failed to send {} erasure-coded chunks to chunk writer task, over channel", e.0.len());
                exit(1);
            }

            progress.eprint(&format!(
                "Processed {} in {:?}...",
                format_bytes(blob_builder.num_bytes_absorbed_so_far()),
                now.elapsed()
            ));
        }
    }

    match blob_builder.finalize() {
        Ok((chunks, blob_header)) => {
            if let Err(e) = chunk_tx.blocking_send(chunks) {
                eprintln!("Failed to send {} erasure-coded chunks to chunk writer task, over channel", e.0.len());
                exit(1);
            }

            progress.eprint_clear();
            blob_header
        }
        Err(e) => {
            eprintln!("Failed to finalize the blob builder: {:?}", e);
            exit(1);
        }
    }
}

async fn write_partial_chunks(target_dir_path: PathBuf, mut chunk_rx: tokio::sync::mpsc::Receiver<Vec<ProofCarryingChunk>>) {
    let max_num_pending_spawned_tasks: usize = num_cpus::get() * 4;
    let mut join_handles = JoinSet::new();

    while let Some(chunks) = chunk_rx.recv().await {
        for chunk in chunks {
            let mut blob_share_path = target_dir_path.clone();

            join_handles.spawn(async move {
                match chunk.to_bytes() {
                    Ok(bytes) => {
                        blob_share_path.push(format!("chunkset.{}", chunk.get_chunkset_id()));

                        if let Err(e) = tokio::fs::create_dir_all(&blob_share_path).await {
                            eprintln!("Failed to create directory {:?} for putting chunks: {:?}", blob_share_path, e);
                            exit(1);
                        }

                        blob_share_path.push(format!("share{:02}.data", chunk.get_local_chunk_id()));

                        if let Err(e) = tokio::fs::write(&blob_share_path, bytes).await {
                            eprintln!("Failed to write partial chunk to file {:?}: {:?}", blob_share_path, e);
                            exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to serialize partial chunk with chunk-id {}: {:?}", chunk.get_global_chunk_id(), e);
                        exit(1);
                    }
                }
            });
        }

        if join_handles.len() > max_num_pending_spawned_tasks {
            let mut idx = 0;
            let num_tasks_to_be_joined = join_handles.len() - max_num_pending_spawned_tasks;

            while idx < num_tasks_to_be_joined {
                if let Err(e) = unsafe { join_handles.join_next().await.unwrap_unchecked() } {
                    eprintln!("Partial chunk writer sub-task failed to finish: {:?}", e);
                    exit(1);
                }

                idx += 1;
            }
        }
    }

    while let Some(task_result) = join_handles.join_next().await {
        if let Err(e) = task_result {
            eprintln!("Partial chunk writer sub-task failed to finish: {:?}", e);
            exit(1);
        }
    }
}

async fn write_blob_metadata(target_dir: &PathBuf, metadata: &BlobHeader) {
    let mut blob_metadata_path = target_dir.clone();
    blob_metadata_path.push("metadata.commit");

    match metadata.to_bytes() {
        Ok(bytes) => {
            if let Err(e) = tokio::fs::write(&blob_metadata_path, bytes).await {
                eprintln!("Failed to write blob metadata to file {:?}: {:?}", blob_metadata_path, e);
                exit(1);
            }
        }
        Err(e) => {
            eprintln!("Failed to serialize blob metadata: {:?}", e);
            exit(1);
        }
    }
}

async fn finalize_proof_carrying_chunks(metadata: BlobHeader, target_dir_path: PathBuf) {
    if metadata.get_num_chunksets() == 1 {
        return;
    }

    let chunkset_root_commitments = (0..metadata.get_num_chunksets())
        .map(|chunkset_id| unsafe { metadata.get_chunkset_commitment(chunkset_id).unwrap_unchecked() })
        .collect();
    let merkle_tree = Arc::new(unsafe { MerkleTree::new(chunkset_root_commitments).unwrap_unchecked() });

    let max_num_pending_spawned_tasks: usize = num_cpus::get() * 4;
    let mut join_handles = JoinSet::new();

    let mut progress = ConsoleStaticText::new(|| {
        let (rows, cols) = Term::stdout().size();
        ConsoleSize {
            rows: Some(rows),
            cols: Some(cols),
        }
    });
    let num_finalized_chunks = Arc::new(AtomicUsize::new(0));
    let now = Instant::now();

    for chunkset_id in 0..metadata.get_num_chunksets() {
        for share_id in 0..DECDS_NUM_ERASURE_CODED_SHARES {
            let mut blob_share_path = target_dir_path.clone();
            let merkle_tree_cloned = merkle_tree.clone();
            let num_finalized_chunks_clone = num_finalized_chunks.clone();

            join_handles.spawn(async move {
                blob_share_path.push(format!("chunkset.{}", chunkset_id));
                blob_share_path.push(format!("share{:02}.data", share_id));

                let mut chunk = match tokio::fs::read(&blob_share_path).await {
                    Ok(bytes) => match ProofCarryingChunk::from_bytes(&bytes) {
                        Ok((chunk, n)) => {
                            if n != bytes.len() {
                                eprintln!("Chunk file {:?} is {} bytes longer than it should be", blob_share_path, bytes.len() - n);
                                exit(1);
                            } else {
                                chunk
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to deserialize partial chunk from file {:?}: {:?}", blob_share_path, e);
                            exit(1);
                        }
                    },
                    Err(e) => {
                        eprintln!("Failed to read partial chunk file {:?}: {:?}", blob_share_path, e);
                        exit(1);
                    }
                };

                match tokio::task::spawn_blocking(move || unsafe { merkle_tree_cloned.generate_proof(chunkset_id).unwrap_unchecked() }).await {
                    Ok(blob_level_proof) => {
                        chunk.append_proof_to_blob_root(&blob_level_proof);
                    }
                    Err(e) => {
                        eprintln!(
                            "Failed to generate blob-level Merkle proof-of-inclusion for chunk-id {}: {:?}",
                            chunk.get_global_chunk_id(),
                            e
                        );
                        exit(1);
                    }
                }

                if let Ok(bytes) = chunk.to_bytes() {
                    if let Err(e) = tokio::fs::write(&blob_share_path, bytes).await {
                        eprintln!("Failed to write complete chunk to file {:?}: {:?}", blob_share_path, e);
                        exit(1);
                    }

                    // Update atomic counter, which keeps track of how many sub-tasks completed its job
                    // of updating a partial chunk with blob-level proof-of-inclusion.
                    num_finalized_chunks_clone.fetch_add(1, Ordering::Relaxed);
                }
            });
        }

        if join_handles.len() > max_num_pending_spawned_tasks {
            let mut idx = 0;
            let num_tasks_to_be_joined = join_handles.len() - max_num_pending_spawned_tasks;

            while idx < num_tasks_to_be_joined {
                if let Err(e) = unsafe { join_handles.join_next().await.unwrap_unchecked() } {
                    eprintln!("Partial chunk writer sub-task failed to finish: {:?}", e);
                    exit(1);
                }

                idx += 1;
            }
        }

        progress.eprint(&format!(
            "Finalized chunks {}/{} in {:?}...",
            num_finalized_chunks.load(Ordering::Relaxed),
            metadata.get_num_chunks(),
            now.elapsed()
        ));
    }

    while let Some(task_result) = join_handles.join_next().await {
        if let Err(e) = task_result {
            eprintln!("Partial chunk writer sub-task failed to finish: {:?}", e);
            exit(1);
        }

        progress.eprint(&format!(
            "Finalized chunks {}/{} in {:?}...",
            num_finalized_chunks.load(Ordering::Relaxed),
            metadata.get_num_chunks(),
            now.elapsed()
        ));
    }

    progress.eprint_clear();
}
