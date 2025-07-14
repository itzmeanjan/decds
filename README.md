# decds
A Distributed Erasure-Coded Data Storage System

`decds` is a command-line utility and library, written in Rust, for reliably storing and recovering arbitrary-size data blob using Merkle Tree-based cryptographic commitments (with BLAKE3 hash function) and Random Linear Network Coding (RLNC)-based erasure coding. It allows you to break large data blobs into smaller, verifiable, and reconstructible Proof-Carrying Chunks (PCC), ensuring data integrity and availability even in the presence of partial data loss.

![decds-architecture](./assets/decds-architecture_diagram.png)

This design collects some inspiration from https://arxiv.org/pdf/2506.19233.

> [!TIP]
> How to use `decds`? Watch hands-on experience @ https://youtu.be/vpxDwGcd55Q.

## Features
A simple command-line interface tool to perform operations like breaking data blob, verifying proof-carrying chunks, and repairing blob from sufficient number of proof-carrying chunks.

- **Data Splitting**:
  - **Erasure Coding (RLNC):** Zero pads arbitrary sized original data blob to be a multiple of 10MB, if not already. Divides zero-padded blob into fixed-size (= 10MB) chunksets. Then it splits each chunkset into 10 chunks, each of 1MB, on which Random Linear Network Coding is applied, generating 16 erasure-coded chunks from each chunkset. This allows reconstruction of the chunkset even if a some chunks are lost or corrupted - we need at least 10 valid chunks per chunkset for successful recovery.
  - **Merkle Trees:** Builds binary Merkle tree (using BLAKE3 hash function) over erasure-coded chunks, generates inclusion proofs for each chunk, ensuring data integrity and verifiable retrieval. Each chunk carries proof of its inclusion in its chunkset and the overall blob.
- **Data Verification:** Provides a mechanism to verify the integrity of individual chunks against the original blob root commitment and corresponding chunkset commitment. These commitments are stored in `metadata.commit` file - which is the source of truth for `decds` CLI tool.
- **Data Repairing:** Enables the reconstruction of original data blob from at least 10 valid erasure-coded chunks, for each chunkset. All the chunksets must be recoverable to be able to reconstruct whole blob.

## Prerequisites
Rust stable toolchain; see https://rustup.rs for installation guide. MSRV for this crate is `1.85.0`.

```bash
# While developing this library, I was using
$ rustc --version
rustc 1.88.0 (6b00bc388 2025-06-23)
```

## Testing
It features comprehensive tests to ensure functional correctness of data dissemination and reconstruction.

```bash
make test
```

> [!NOTE]
> There is a help menu, which introduces you to all available commands; just run `$ make` from the root directory of this project.

```bash
running 32 tests
test blob::tests::test_blob_new_empty_data ... ok
test chunk::tests::test_chunk_digest ... ok
test chunkset::tests::test_chunkset_new_invalid_size ... ok
test chunk::tests::test_proof_carrying_chunk_serialization_deserialization ... ok
test chunkset::tests::test_repairing_chunkset_add_chunk_invalid_proof_in_chunk ... ok
test chunkset::tests::test_chunkset_get_chunk_out_of_bounds ... ok
test blob::tests::test_blob_get_share_invalid_id ... ok
test chunkset::tests::test_chunkset_append_blob_inclusion_proof_unit ... ok
test blob::tests::test_get_byte_range_for_chunkset ... ok
test merkle_tree::tests::test_generate_and_verify_proof_for_two_leaf_nodes ... ok
test merkle_tree::tests::test_generate_proof_out_of_bounds ... ok
test merkle_tree::tests::test_generate_proof_single_leaf_node ... ok
test merkle_tree::tests::test_new_with_empty_leaf_nodes ... ok
test merkle_tree::tests::test_new_with_single_leaf_node ... ok
test merkle_tree::tests::test_new_with_two_leaf_nodes ... ok
test merkle_tree::tests::test_verify_proof_single_leaf_node ... ok
test chunkset::tests::test_repairing_chunkset_add_chunk_unvalidated_invalid_chunk_metadata ... ok
test blob::tests::test_get_chunkset_size ... ok
test chunkset::tests::test_repairing_chunkset_add_chunk_after_ready_to_repair ... ok
test blob::tests::test_blob_header_serialization_deserialization ... ok
test blob::tests::test_get_chunkset_ids_for_byte_range ... ok
test blob::tests::test_get_chunkset_commitment ... ok
test blob::tests::test_repairing_blob_add_chunk ... ok
test blob::tests::test_repairing_blob_new ... ok
test chunkset::tests::test_repairing_chunkset_new ... ok
test chunkset::tests::test_repairing_chunkset_repair_when_not_ready ... ok
test blob::tests::test_repairing_blob_get_repaired_chunkset ... ok
test chunkset::tests::prop_test_erasure_coding_chunks_and_validating_proofs_work ... ok
test chunkset::tests::prop_test_repairing_erasure_coded_chunks_work ... ok
test blob::tests::prop_test_blob_preparation_and_commitment_works ... ok
test merkle_tree::tests::prop_test_merkle_tree_operations ... ok
test tests::prop_test_blob_building_and_repairing_works ... ok

test result: ok. 32 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 60.66s

   Doc-tests decds_lib

running 3 tests
test decds-lib/src/lib.rs - (line 34) ... ok
test decds-lib/src/lib.rs - (line 17) ... ok
test decds-lib/src/lib.rs - (line 59) ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.71s
```

## Code Coverage
To generate a detailed code coverage report in HTML format, use [cargo-tarpaulin](https://github.com/xd009642/tarpaulin):

```bash
# Install cargo-tarpaulin if not already installed
cargo install cargo-tarpaulin
make coverage
```

This will create an HTML coverage report at `tarpaulin-report.html` that you can open in your web browser to view detailed line-by-line coverage information for all source files.

```bash
Coverage Results:
|| Tested/Total Lines:
|| decds-bin/src/utils.rs: 0/19
|| decds-lib/src/blob.rs: 58/94
|| decds-lib/src/chunk.rs: 12/16
|| decds-lib/src/chunkset.rs: 29/36
|| decds-lib/src/errors.rs: 0/18
|| decds-lib/src/merkle_tree.rs: 32/33
|| 
60.65% coverage, 131/216 lines covered
```

## Installation
For hands-on experience, install `decds` on your `$HOME/.cargo/bin`.

```bash
cargo install --profile optimized --git https://github.com/itzmeanjan/decds.git --locked

# or

git clone https://github.com/itzmeanjan/decds.git
pushd decds
make install
popd

# now, try following, assuming $HOME/.cargo/bin is on your $PATH.
decds -V
```

## Usage
The `decds` CLI provides three main commands: `break`, `verify`, and `repair`.

```bash
decds help
```

```bash
A Distributed Erasure-Coded Data Storage System

Usage: decds <COMMAND>

Commands:
  break   Splits given data blob into small erasure-coded chunks, carrying proof of inclusion
  verify  Validate proof of inclusion for erasure-coded chunks
  repair  Reconstructs original data blob using erasure-coded proof-carrying chunks
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

Have a look at following terminal recording of playing with `decds`. You can check out a bash script, showing similar commands @ [decds-hands-on-linux](./scripts/test_decds_on_linux.sh).

![decds-hands-on-experience](./assets/decds-hands-on-experience.gif)

> [!TIP]
> Don't like GIF? See it on https://youtu.be/vpxDwGcd55Q or locally play the [video](./assets/decds-hands-on-experience.mp4) from [assets](./assets) directory.

After recording a terminal session with asciinema @ https://github.com/asciinema/asciinema, I use [./scripts/asciinema_pipeline.sh](./scripts/asciinema_pipeline.sh) to productionize it.
