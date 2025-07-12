use decds_lib::{BlobHeader, ProofCarryingChunk};
use rand::Rng;
use std::{path::PathBuf, process::exit, str::FromStr};

use crate::errors::DecdsCLIError;

pub fn format_bytes(bytes: usize) -> String {
    let suffixes = ["B", "KB", "MB", "GB"];
    let mut index = 0;
    let mut size = bytes as f64;

    while size >= 1024.0 && index < suffixes.len() - 1 {
        size /= 1024.0;
        index += 1;
    }

    format!("{:.1}{}", size, suffixes[index])
}

pub fn read_blob_metadata(blob_metadata_path: &PathBuf) -> BlobHeader {
    match std::fs::read(blob_metadata_path) {
        Ok(bytes) => match BlobHeader::from_bytes(&bytes) {
            Ok((blob_header, n)) => {
                if n != bytes.len() {
                    eprintln!(
                        "Erasure-coded blob metadata file {:?} is {} bytes longer than it should be",
                        blob_metadata_path,
                        bytes.len() - n
                    );
                    exit(1);
                }

                blob_header
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(1);
            }
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            exit(1);
        }
    }
}

pub fn read_proof_carrying_chunk(chunk_path: &PathBuf) -> Result<ProofCarryingChunk, DecdsCLIError> {
    match std::fs::read(chunk_path) {
        Ok(bytes) => match ProofCarryingChunk::from_bytes(&bytes) {
            Ok((chunk, n)) => {
                if n != bytes.len() {
                    Err(DecdsCLIError::FailedToReadProofCarryingChunk(format!(
                        "Erasure-coded chunk file {:?} is {} bytes longer than it should be",
                        chunk_path,
                        bytes.len() - n
                    )))
                } else {
                    Ok(chunk)
                }
            }
            Err(e) => Err(DecdsCLIError::FailedToReadProofCarryingChunk(e.to_string())),
        },
        Err(e) => Err(DecdsCLIError::FailedToReadProofCarryingChunk(e.to_string())),
    }
}

pub fn get_target_directory_path<R: Rng + ?Sized>(blob_path: &PathBuf, opt_target_dir: &Option<PathBuf>, rng: &mut R) -> PathBuf {
    match opt_target_dir {
        Some(path) => match path.try_exists() {
            Ok(ok) => {
                if ok {
                    prepare_random_target_directory_name(unsafe { path.to_str().unwrap_unchecked() }, rng)
                } else {
                    path.clone()
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(1);
            }
        },
        None => prepare_random_target_directory_name(unsafe { blob_path.file_name().unwrap_unchecked().to_str().unwrap_unchecked() }, rng),
    }
}

fn prepare_random_target_directory_name<R: Rng + ?Sized>(prefix: &str, rng: &mut R) -> PathBuf {
    let mut rand_suffix = [0u8; 4];
    rng.fill_bytes(&mut rand_suffix);

    let mut res = String::new();
    res.push_str(prefix);
    res.push('-');
    res.push_str(&const_hex::encode(rand_suffix));

    unsafe { PathBuf::from_str(&res).unwrap_unchecked() }
}
