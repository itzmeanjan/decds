#!/usr/bin/bash

# Trap failure of any following commands
set -e

# Detect operating system
case "$(uname -s)" in
    Linux*)     OS=Linux;;
    Darwin*)    OS=Mac;;
    *)          echo "Unsupported OS"; exit 1;;
esac

# Check for required commands
if ! command -v dd >/dev/null 2>&1; then
    echo "Error: dd command not found"
    exit 1
fi
if ! command -v make >/dev/null 2>&1; then
    echo "Error: make command not found"
    exit 1
fi
if ! command -v awk >/dev/null 2>&1; then
    echo "Error: awk command not found"
    exit 1
fi

# Set SHA256 command based on OS
if [ "$OS" = "Linux" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        SHA256CMD="sha256sum"
    else
        echo "Error: sha256sum not found on Linux"
        exit 1
    fi
elif [ "$OS" = "Mac" ]; then
    if command -v shasum >/dev/null 2>&1; then
        SHA256CMD="shasum -a 256"
    else
        echo "Error: shasum not found on macOS"
        exit 1
    fi
fi

# Function to verify checksum (handles Linux and macOS differences)
verify_checksum() {
    local hash="$1"
    local file="$2"
    if [ "$OS" = "Linux" ]; then
        echo "$hash $file" | $SHA256CMD --check
    elif [ "$OS" = "Mac" ]; then
        # Use a temporary file to ensure correct format
        echo "$hash  $file" > /tmp/checksum.txt
        $SHA256CMD -c /tmp/checksum.txt
        rm -f /tmp/checksum.txt
    fi
}

# Generate random 1GB data blob
dd if=/dev/urandom of=random.data bs=1M count=1024
ORIGINAL_HASH=$($SHA256CMD random.data | awk '{print $1}')

# Build `decds` executable
make build
echo "Using $(./target/optimized/decds -V)"

# Break blob into chunksets and verify each chunk's validity
time ./target/optimized/decds break -b random.data -o broken
time ./target/optimized/decds verify broken

# Repair chunksets and check SHA256 digest of original data blob and repaired data blob
time ./target/optimized/decds repair -c broken -o repairing-with-16
verify_checksum "$ORIGINAL_HASH" "repairing-with-16/repaired.data"

# Mutate a single byte of a proof-carrying chunk belonging to chunkset-15
# Repairing with 15 valid chunks for chunkset-15 - must work!
dd if=/dev/urandom of=broken/chunkset.15/share00.data bs=1 seek=1 count=1 conv=notrunc
time ./target/optimized/decds repair -c broken -o repairing-with-15
verify_checksum "$ORIGINAL_HASH" "repairing-with-15/repaired.data"

# Mutate a single byte of a proof-carrying chunk belonging to chunkset-15
# Repairing with 14 valid chunks for chunkset-15 - must work!
dd if=/dev/urandom of=broken/chunkset.15/share02.data bs=1 seek=11 count=1 conv=notrunc
time ./target/optimized/decds repair -c broken -o repairing-with-14
verify_checksum "$ORIGINAL_HASH" "repairing-with-14/repaired.data"

# Mutate a single byte of a proof-carrying chunk belonging to chunkset-15
# Repairing with 13 valid chunks for chunkset-15 - must work!
dd if=/dev/urandom of=broken/chunkset.15/share04.data bs=1 seek=111 count=1 conv=notrunc
time ./target/optimized/decds repair -c broken -o repairing-with-13
verify_checksum "$ORIGINAL_HASH" "repairing-with-13/repaired.data"

# Mutate a single byte of a proof-carrying chunk belonging to chunkset-15
# Repairing with 12 valid chunks for chunkset-15 - must work!
dd if=/dev/urandom of=broken/chunkset.15/share15.data bs=1 seek=77 count=1 conv=notrunc
time ./target/optimized/decds repair -c broken -o repairing-with-12
verify_checksum "$ORIGINAL_HASH" "repairing-with-12/repaired.data"

# Mutate a single byte of a proof-carrying chunk belonging to chunkset-15
# Repairing with 11 valid chunks for chunkset-15 - must work!
dd if=/dev/urandom of=broken/chunkset.15/share12.data bs=1 seek=175 count=1 conv=notrunc
time ./target/optimized/decds repair -c broken -o repairing-with-11
verify_checksum "$ORIGINAL_HASH" "repairing-with-11/repaired.data"

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
time ./target/optimized/decds repair -c broken -o repairing-with-9 | tee console.out; test ${PIPESTATUS[0]} -eq 1

# Clean up
rm -rf random.data broken repairing-with* console.out /tmp/checksum.txt
