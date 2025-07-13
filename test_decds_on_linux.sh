#!/usr/bin/bash

# Generate random 256MB data blob
head -c 256M /dev/urandom > random.data

# Break -> Verify -> Repair
cargo run --profile optimized -- break -b random.data
cargo run --profile optimized -- verify $(find -name random.data-*)
cargo run --profile optimized -- repair -c $(find -name random.data-*)

# Check SHA256 digest of original data blob and repaired data blob
echo "$(sha256sum random.data | awk '{print $1}') $(find -name random.data-*-*)/repaired.data" | sha256sum --check

# Clean up
find -name 'random.data*' | xargs rm -rf
