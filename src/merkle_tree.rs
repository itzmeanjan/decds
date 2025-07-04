use blake3;
use std::collections::VecDeque;

pub struct MerkleTree {
    root: blake3::Hash,
    leaves: Vec<blake3::Hash>,
}

impl MerkleTree {
    pub fn new(leaf_nodes: Vec<blake3::Hash>) -> Option<Self> {
        if leaf_nodes.is_empty() {
            return None;
        }

        let mut zero_hash = blake3::Hash::from_bytes([0u8; 32]);
        let mut current_level = VecDeque::from(leaf_nodes.clone());

        while current_level.len() > 1 {
            let mut parent_level = VecDeque::new();

            while !current_level.is_empty() {
                let left = unsafe { current_level.pop_front().unwrap_unchecked() };
                let right = current_level.pop_front().unwrap_or(zero_hash);

                let parent = Self::parent_hash(left.as_bytes(), right.as_bytes());
                parent_level.push_back(parent);
            }

            zero_hash = blake3::Hasher::new().update(zero_hash.as_bytes()).update(zero_hash.as_bytes()).finalize();
            current_level = parent_level;
        }

        Some(MerkleTree {
            root: unsafe { current_level.pop_front().unwrap_unchecked() },
            leaves: leaf_nodes,
        })
    }

    pub fn get_root_commitment(&self) -> blake3::Hash {
        self.root
    }

    pub fn generate_proof(&self, leaf_index: usize) -> Option<Vec<blake3::Hash>> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let num_leaf_nodes = self.leaves.len();
        let proof_size = num_leaf_nodes.next_power_of_two().ilog2() as usize;

        let mut proof = Vec::with_capacity(proof_size);

        let mut current_level: VecDeque<blake3::Hash> = self.leaves.clone().into();
        let mut current_index = leaf_index;

        let mut zero_hash = blake3::Hash::from_bytes([0u8; 32]);

        while current_level.len() > 1 {
            let mut parent_level = VecDeque::new();
            let mut i = 0;

            while i < current_level.len() {
                let left = current_level[i];
                let right = *current_level.get(i + 1).unwrap_or(&zero_hash);
                let parent = Self::parent_hash(left.as_bytes(), right.as_bytes());

                if current_index == i {
                    proof.push(right);
                } else if current_index == i + 1 {
                    proof.push(left);
                }

                parent_level.push_back(parent);
                i += 2;
            }

            current_index /= 2;
            current_level = parent_level;

            zero_hash = blake3::Hasher::new().update(zero_hash.as_bytes()).update(zero_hash.as_bytes()).finalize();
        }

        Some(proof)
    }

    pub fn verify_proof(leaf_index: usize, leaf_node: blake3::Hash, proof: &[blake3::Hash], root_hash: blake3::Hash) -> bool {
        let mut current_hash = leaf_node;
        let mut current_index = leaf_index;

        for sibling_hash in proof {
            current_hash = if current_index & 1 == 0 {
                Self::parent_hash(current_hash.as_bytes(), sibling_hash.as_bytes())
            } else {
                Self::parent_hash(sibling_hash.as_bytes(), current_hash.as_bytes())
            };

            current_index /= 2;
        }

        current_hash == root_hash
    }

    fn parent_hash(left: &[u8], right: &[u8]) -> blake3::Hash {
        blake3::Hasher::new().update(left).update(right).finalize()
    }
}

#[cfg(test)]
mod tests {
    use crate::merkle_tree::MerkleTree;
    use rand::Rng;

    fn generate_random_leaf_hashes<R: Rng + ?Sized>(leaf_count: usize, rng: &mut R) -> Vec<blake3::Hash> {
        let mut leaf_nodes = Vec::with_capacity(leaf_count);

        (0..leaf_count).for_each(|_| {
            let random_input = (0..blake3::OUT_LEN).map(|_| rng.random()).collect::<Vec<u8>>();
            leaf_nodes.push(blake3::hash(&random_input));
        });

        leaf_nodes
    }

    /// Flips bit at index `bit_idx`, returning resulting byte.
    /// Caller must ensure that `bit_idx <= 7`.
    fn flip_a_bit(byte: u8, bit_idx: usize) -> u8 {
        byte ^ (1u8 << bit_idx)
    }

    fn flip_a_single_bit_in_merkle_proof<R: Rng + ?Sized>(mut proof: Vec<blake3::Hash>, rng: &mut R) -> Vec<blake3::Hash> {
        if proof.is_empty() {
            return proof;
        }

        let random_node_index = rng.random_range(0..proof.len());
        let random_byte_index = rng.random_range(0..blake3::OUT_LEN);
        let random_bit_index = rng.random_range(0..u8::BITS) as usize;

        let mut bytes = [0u8; blake3::OUT_LEN];
        bytes.copy_from_slice(proof[random_node_index].as_bytes());

        bytes[random_byte_index] = flip_a_bit(bytes[random_byte_index], random_bit_index);

        proof[random_node_index] = blake3::Hash::from_bytes(bytes);
        proof
    }

    #[test]
    fn prop_test_merkle_tree_operations() {
        const NUM_TEST_ITERAATIONS: usize = 10;

        const MIN_LEAF_NODE_COUNT: usize = 1;
        const MAX_LEAF_NODE_COUNT: usize = 10_000;

        let mut rng = rand::rng();

        (0..NUM_TEST_ITERAATIONS).for_each(|_| {
            let leaf_count = rng.random_range(MIN_LEAF_NODE_COUNT..=MAX_LEAF_NODE_COUNT);
            let leaf_nodes = generate_random_leaf_hashes(leaf_count, &mut rng);

            let merkle_tree = MerkleTree::new(leaf_nodes.clone()).expect("Must be able to build Merkle Tree");
            let root_hash = merkle_tree.get_root_commitment();

            leaf_nodes.iter().enumerate().for_each(|(leaf_index, &leaf_node)| {
                let mut merkle_proof = merkle_tree.generate_proof(leaf_index).expect("Must be able to generate Merkle Proof");

                let is_valid = MerkleTree::verify_proof(leaf_index, leaf_node, &merkle_proof, root_hash);
                assert!(is_valid);

                merkle_proof = flip_a_single_bit_in_merkle_proof(merkle_proof, &mut rng);

                let is_valid = MerkleTree::verify_proof(leaf_index, leaf_node, &merkle_proof, root_hash);
                assert!(!is_valid);
            });
        });
    }

    #[test]
    fn test_new_with_empty_leaf_nodes() {
        let leaf_nodes: Vec<blake3::Hash> = Vec::new();
        assert!(MerkleTree::new(leaf_nodes).is_none());
    }

    #[test]
    fn test_new_with_single_leaf_node() {
        let leaf_nodes = vec![blake3::hash(b"hello")];
        let merkle_tree = MerkleTree::new(leaf_nodes.clone()).expect("Must be able to build Merkle Tree");
        assert_eq!(merkle_tree.get_root_commitment(), leaf_nodes[0]);
    }

    #[test]
    fn test_new_with_two_leaf_nodes() {
        let leaf1 = blake3::hash(b"hello");
        let leaf2 = blake3::hash(b"world");
        let leaf_nodes = vec![leaf1, leaf2];

        let merkle_tree = MerkleTree::new(leaf_nodes.clone()).expect("Must be able to build Merkle Tree");
        let expected_root = MerkleTree::parent_hash(leaf1.as_bytes(), leaf2.as_bytes());

        assert_eq!(merkle_tree.get_root_commitment(), expected_root);
    }

    #[test]
    fn test_generate_proof_out_of_bounds() {
        let leaf_nodes = generate_random_leaf_hashes(5, &mut rand::rng());
        let merkle_tree = MerkleTree::new(leaf_nodes).expect("Must be able to build Merkle Tree");

        assert_eq!(merkle_tree.generate_proof(5), None);
        assert_eq!(merkle_tree.generate_proof(100), None);
    }

    #[test]
    fn test_generate_proof_single_leaf_node() {
        let leaf_node = blake3::hash(b"single");
        let leaf_nodes = vec![leaf_node];
        let merkle_tree = MerkleTree::new(leaf_nodes).expect("Must be able to build Merkle Tree");

        let proof = merkle_tree.generate_proof(0).expect("Proof generation failed");
        assert!(proof.is_empty());
    }

    #[test]
    fn test_verify_proof_single_leaf_node() {
        let leaf_node = blake3::hash(b"single_leaf");
        let leaf_nodes = vec![leaf_node];
        let merkle_tree = MerkleTree::new(leaf_nodes).expect("Must be able to build Merkle Tree");
        let root_hash = merkle_tree.get_root_commitment();

        let proof = merkle_tree.generate_proof(0).expect("Proof generation failed");
        assert!(proof.is_empty());

        let is_valid = MerkleTree::verify_proof(0, leaf_node, &proof, root_hash);
        assert!(is_valid);

        // Tamper with the leaf node
        let tampered_leaf = blake3::hash(b"tampered");
        let is_valid_tampered = MerkleTree::verify_proof(0, tampered_leaf, &proof, root_hash);
        assert!(!is_valid_tampered);
    }

    #[test]
    fn test_generate_and_verify_proof_for_two_leaf_nodes() {
        let leaf1 = blake3::hash(b"first");
        let leaf2 = blake3::hash(b"second");
        let leaf_nodes = vec![leaf1, leaf2];
        let merkle_tree = MerkleTree::new(leaf_nodes.clone()).expect("Must be able to build Merkle Tree");
        let root_hash = merkle_tree.get_root_commitment();

        // Test leaf1
        let proof1 = merkle_tree.generate_proof(0).expect("Proof for leaf1 failed");
        assert_eq!(proof1.len(), 1);
        assert_eq!(proof1[0], leaf2); // Sibling for leaf1 should be leaf2
        assert!(MerkleTree::verify_proof(0, leaf1, &proof1, root_hash));

        // Test leaf2
        let proof2 = merkle_tree.generate_proof(1).expect("Proof for leaf2 failed");
        assert_eq!(proof2.len(), 1);
        assert_eq!(proof2[0], leaf1); // Sibling for leaf2 should be leaf1
        assert!(MerkleTree::verify_proof(1, leaf2, &proof2, root_hash));

        // Negative test: Tamper proof1 and verify
        let tampered_proof1 = vec![blake3::hash(b"fake_sibling")];
        assert!(!MerkleTree::verify_proof(0, leaf1, &tampered_proof1, root_hash));

        // Negative test: Tamper leaf1 and verify with correct proof
        let tampered_leaf1 = blake3::hash(b"tampered_first");
        assert!(!MerkleTree::verify_proof(0, tampered_leaf1, &proof1, root_hash));
    }
}
