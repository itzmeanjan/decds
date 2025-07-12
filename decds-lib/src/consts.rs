/// Fixed configuration for `bincode` serialization and deserialization.
pub const DECDS_BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

/// Number of erasure-coded shares for each fixed-size (=10MB) chunkset.
pub const DECDS_NUM_ERASURE_CODED_SHARES: usize = 16;
