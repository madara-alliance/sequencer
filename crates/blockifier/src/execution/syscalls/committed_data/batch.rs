//! Standard Patricia preimages shared by the requested paths.
use std::collections::HashMap;

use starknet_types_core::felt::Felt;

use super::{
    CommittedDataError,
    CommittedDataSet,
    CommittedDataWitness,
    MAX_COMMITTED_DATA_READ_KEYS,
    MAX_COMMITTED_DATA_WITNESSES,
};

#[derive(Debug, PartialEq, Eq)]
pub struct CommittedDataBatchProof {
    pub facts: HashMap<Felt, Vec<Felt>>,
    pub leaves: Vec<Felt>,
    pub indices: Vec<usize>,
    pub branches: usize,
    pub branch_hashes: Vec<Felt>,
}
impl CommittedDataBatchProof {
    pub fn new(
        root: Felt,
        keys: &[Felt],
        witness: impl FnMut(Felt) -> Result<Option<CommittedDataWitness>, CommittedDataError>,
    ) -> Result<Self, CommittedDataError> {
        if keys.len() > MAX_COMMITTED_DATA_READ_KEYS {
            return Err(CommittedDataError::InvalidLength);
        }
        Self::new_for_read_set(root, keys, witness)
    }
    pub fn new_for_read_set(
        root: Felt,
        keys: &[Felt],
        mut witness: impl FnMut(Felt) -> Result<Option<CommittedDataWitness>, CommittedDataError>,
    ) -> Result<Self, CommittedDataError> {
        if keys.is_empty() || keys.len() > MAX_COMMITTED_DATA_WITNESSES {
            return Err(CommittedDataError::InvalidLength);
        }
        let mut result = Self {
            facts: HashMap::new(),
            leaves: vec![],
            indices: vec![],
            branches: 0,
            branch_hashes: vec![],
        };
        let mut unique = HashMap::new();
        for &key in keys {
            let index = if let Some(&index) = unique.get(&key) {
                index
            } else {
                let proof = witness(key)?.ok_or(CommittedDataError::Unavailable { root, key })?;
                if proof.root != root || proof.key != key {
                    return Err(CommittedDataError::InvalidWitness);
                }
                for (hash, preimage) in proof.facts().ok_or(CommittedDataError::InvalidWitness)? {
                    if let Some(previous) = result.facts.insert(hash, preimage.clone()) {
                        if previous != preimage {
                            return Err(CommittedDataError::InvalidWitness);
                        }
                    }
                }
                let index = result.unique_leaves();
                unique.insert(key, index);
                result.leaves.extend([key, proof.read_value()]);
                index
            };
            result.indices.push(index);
        }
        result.branch_hashes = result.facts.keys().copied().collect();
        result.branch_hashes.sort_unstable();
        result.branches = result.branch_hashes.len();
        Ok(result)
    }
    pub fn from_dataset(
        tree: &CommittedDataSet,
        keys: &[Felt],
    ) -> Result<Self, CommittedDataError> {
        Self::new(tree.root(), keys, |key| Ok(Some(tree.lookup_witness(key))))
    }
    pub fn unique_leaves(&self) -> usize {
        self.leaves.len() / 2
    }
}
