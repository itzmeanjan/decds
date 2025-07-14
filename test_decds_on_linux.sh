#!/usr/bin/bash

# Generate random 256MB data blob
dd if=/dev/urandom of=random.data bs=1M count=256

# Break blob into chunksets and verify each chunk's validity
cargo run --profile optimized -- break -b random.data -o broken
cargo run --profile optimized -- verify broken

# Repair chunksets and check SHA256 digest of original data blob and repaired data blob
cargo run --profile optimized -- repair -c broken -o repairing-with-16
echo "$(sha256sum random.data | awk '{print $1}') repairing-with-16/repaired.data" | sha256sum --check

# Mutate a single byte of a proof-carrying chunk belonging to chunkset-15
# Repairing with 15 valid chunks for chunkset-15 - must work!
dd if=/dev/urandom of=broken/chunkset.15/share00.data bs=1 seek=1 count=1 conv=notrunc
cargo run --profile optimized -- repair -c broken -o repairing-with-15
echo "$(sha256sum random.data | awk '{print $1}') repairing-with-15/repaired.data" | sha256sum --check

# Mutate a single byte of a proof-carrying chunk belonging to chunkset-15
# Repairing with 14 valid chunks for chunkset-15 - must work!
dd if=/dev/urandom of=broken/chunkset.15/share02.data bs=1 seek=11 count=1 conv=notrunc
cargo run --profile optimized -- repair -c broken -o repairing-with-14
echo "$(sha256sum random.data | awk '{print $1}') repairing-with-14/repaired.data" | sha256sum --check

# Mutate a single byte of a proof-carrying chunk belonging to chunkset-15
# Repairing with 13 valid chunks for chunkset-15 - must work!
dd if=/dev/urandom of=broken/chunkset.15/share04.data bs=1 seek=111 count=1 conv=notrunc
cargo run --profile optimized -- repair -c broken -o repairing-with-13
echo "$(sha256sum random.data | awk '{print $1}') repairing-with-13/repaired.data" | sha256sum --check

# Mutate a single byte of a proof-carrying chunk belonging to chunkset-15
# Repairing with 12 valid chunks for chunkset-15 - must work!
dd if=/dev/urandom of=broken/chunkset.15/share15.data bs=1 seek=1 count=1 conv=notrunc
cargo run --profile optimized -- repair -c broken -o repairing-with-12
echo "$(sha256sum random.data | awk '{print $1}') repairing-with-12/repaired.data" | sha256sum --check

# Mutate a single byte of a proof-carrying chunk belonging to chunkset-15
# Repairing with 11 valid chunks for chunkset-15 - must work!
dd if=/dev/urandom of=broken/chunkset.15/share12.data bs=1 seek=100 count=1 conv=notrunc
cargo run --profile optimized -- repair -c broken -o repairing-with-11
echo "$(sha256sum random.data | awk '{print $1}') repairing-with-11/repaired.data" | sha256sum --check

# Note:
# It should ideally be possible to recover a chunkset with 10 valid chunks.
# Though it is possible that all possible unique permutations of 10 valid chunks don't
# result in successful recovery of the chunkset - because some of those chunks might be
# linearly dependent. So we need to collect 10 linearly independent chunks for each chunkset.
# A safe bet is collecting minimum 11 chunks per chunkset, to be *almost* sure, that set will
# have 10 linearly independent i.e. useful chunks.

# Mutate a single byte of two proof-carrying chunks belonging to chunkset-15.
# Now chunkset-15 should have 9 valid proof-carrying chunks, which should not suffice for recovering that chunkset.
dd if=/dev/urandom of=broken/chunkset.15/share09.data bs=1 seek=781 count=1 conv=notrunc
dd if=/dev/urandom of=broken/chunkset.15/share07.data bs=1 seek=223 count=1 conv=notrunc

# Now trying to repair, with 9 valid chunks for chunkset-15, it should fail with return code 1, as chunkset-15 can't be recovered.
cargo run --profile optimized -- repair -c broken -o repairing-with-9 | tee console.out; test ${PIPESTATUS[0]} -eq 1

# Clean up
rm -rf random.data broken repairing-with* console.out
