//! Trusted local values and pricing geometry, authenticated when an immutable root is published.
//! This is not a wire proof. Remote input and absent keys retain the authenticated proof path.
use std::collections::HashMap;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use starknet_types_core::felt::Felt;

use super::pricing::ReadClass;
use super::{COMMITTED_DATA_TREE_HEIGHT, CommittedDataError, valid_key};

/// A nonzero value plus top-down binary ancestors: (branch bit, sibling hash > 251).
/// Compressed edges are implicit in the gaps. Providers must derive this from an authenticated
/// tree and publish it atomically with the complete flat map; the OS still verifies real proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedDataFlatValue {
    pub value: Felt,
    pub path: Vec<(u8, bool)>,
}

#[derive(PartialEq, Eq)]
enum Opening {
    Edge(usize),
    Binary { seen: u8, left_large: Option<bool>, right_large: Option<bool> },
}

// Node identity is its position, not its hash: equal hashes at different positions cost twice.
fn position(mut key: [u8; 32], height: usize) -> (usize, [u8; 32]) {
    let whole = height / 8;
    key[32 - whole..].fill(0);
    if height % 8 != 0 {
        key[31 - whole] &= !((1 << (height % 8)) - 1);
    }
    (height, key)
}

impl CommittedDataFlatValue {
    /// Reproduce the present-key Cairo pricing class using integers and already authenticated
    /// geometry. No proof construction or Poseidon hashes occur on this local execution path.
    pub(super) fn priced_values(
        keys: &[Felt],
        flat: &[Self],
        batch: bool,
    ) -> Result<(Vec<Felt>, ExecutionResources), CommittedDataError> {
        let invalid = || CommittedDataError::InvalidWitness;
        if keys.is_empty() || keys.len() != flat.len() {
            return Err(invalid());
        }
        let mut unique = HashMap::new();
        let mut openings = HashMap::new();
        let mut values = Vec::with_capacity(keys.len() + usize::from(batch));
        if batch {
            values.push(Felt::from(keys.len()));
        }
        for (&key, row) in keys.iter().zip(flat) {
            if !valid_key(key)
                || row.value == Felt::ZERO
                || row.path.len() > COMMITTED_DATA_TREE_HEIGHT
            {
                return Err(invalid());
            }
            values.push(row.value);
            if let Some(previous) = unique.insert(key, row) {
                if previous != row {
                    return Err(invalid());
                }
                continue;
            }
            let bytes = key.to_bytes_be();
            let mut height = COMMITTED_DATA_TREE_HEIGHT;
            for &(bit, large) in &row.path {
                let bit = usize::from(bit);
                if bit >= height {
                    return Err(invalid());
                }
                if bit + 1 < height {
                    let edge = Opening::Edge(bit + 1);
                    if openings
                        .insert(position(bytes, height), edge)
                        .is_some_and(|old| old != Opening::Edge(bit + 1))
                    {
                        return Err(invalid());
                    }
                }
                let node = openings.entry(position(bytes, bit + 1)).or_insert(Opening::Binary {
                    seen: 0,
                    left_large: None,
                    right_large: None,
                });
                let Opening::Binary { seen, left_large, right_large } = node else {
                    return Err(invalid());
                };
                let right = bytes[31 - bit / 8] & (1 << (bit % 8)) != 0;
                *seen |= if right { 2 } else { 1 };
                let sibling = if right { left_large } else { right_large };
                if sibling.replace(large).is_some_and(|old| old != large) {
                    return Err(invalid());
                }
                height = bit;
            }
            if height > 0
                && openings
                    .insert(position(bytes, height), Opening::Edge(0))
                    .is_some_and(|old| old != Opening::Edge(0))
            {
                return Err(invalid());
            }
        }
        let large = openings
            .values()
            .filter(|opening| {
                matches!(
                    opening,
                    Opening::Binary { seen: 1, right_large: Some(true), .. }
                        | Opening::Binary { seen: 2, left_large: Some(true), .. }
                )
            })
            .count();
        let class = ReadClass { hashes: openings.len(), absent: 0, large };
        Ok((values, class.resources(keys.len(), unique.len())?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::syscalls::committed_data::{CommittedDataBatchProof, CommittedDataSet};

    fn rows(tree: &CommittedDataSet, keys: &[Felt]) -> Vec<CommittedDataFlatValue> {
        keys.iter()
            .map(|&key| {
                let witness = tree.lookup_witness(key);
                assert!(witness.verify() && witness.terminal_key.is_none());
                CommittedDataFlatValue {
                    value: witness.value,
                    path: witness
                        .siblings
                        .iter()
                        .rev()
                        .map(|s| (s.bit, s.hash > Felt::from(251)))
                        .collect(),
                }
            })
            .collect()
    }

    /// Exact equality, not just an average upper bound: both paths must consume the Cairo charge.
    #[test]
    fn flat_quotes_equal_authenticated_proofs_for_shapes_orders_and_small_siblings() {
        let mut seed = 1729u64;
        let mut entries = vec![(Felt::ZERO, Felt::ONE)];
        for i in 1..100u64 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_be_bytes());
            bytes[0] &= 7;
            bytes[24..].copy_from_slice(&i.to_be_bytes());
            entries.push((
                Felt::from_bytes_be(&bytes),
                Felt::from([1, 251, 252, 1000000][i as usize % 4]),
            ));
        }
        let ladder: Vec<_> = (0..251).map(|bit| (Felt::TWO.pow(bit as u128), Felt::from(251))).collect();
        for entries in [
            vec![(Felt::ONE, Felt::ONE)],
            vec![
                (Felt::ZERO, Felt::ONE),
                (Felt::ONE, Felt::from(251)),
                (Felt::TWO, Felt::from(252)),
            ],
            entries,
            ladder,
        ] {
            let tree = CommittedDataSet::new(entries.clone()).unwrap();
            for stride in [1, 2, 3, 17, 1000] {
                let mut keys: Vec<_> = entries.iter().step_by(stride).map(|e| e.0).collect();
                keys.reverse();
                keys.extend_from_within(..keys.len().min(3));
                let proof = CommittedDataBatchProof::from_dataset(&tree, &keys).unwrap();
                assert_eq!(
                    CommittedDataFlatValue::priced_values(&keys, &rows(&tree, &keys), true)
                        .unwrap(),
                    proof.priced_values(tree.root(), &keys, true).unwrap()
                );
            }
            let key = entries[0].0;
            assert_eq!(
                CommittedDataFlatValue::priced_values(&[key], &rows(&tree, &[key]), false).unwrap(),
                CommittedDataBatchProof::from_dataset(&tree, &[key])
                    .unwrap()
                    .priced_values(tree.root(), &[key], false)
                    .unwrap()
            );
        }
    }

    #[test]
    fn malformed_or_ambiguous_flat_geometry_is_rejected() {
        let row = CommittedDataFlatValue { value: Felt::ONE, path: vec![(0, true)] };
        for invalid in [
            CommittedDataFlatValue { value: Felt::ZERO, ..row.clone() },
            CommittedDataFlatValue { path: vec![(251, true)], ..row.clone() },
            CommittedDataFlatValue { path: vec![(0, true), (0, true)], ..row.clone() },
        ] {
            assert!(
                CommittedDataFlatValue::priced_values(&[Felt::ONE], &[invalid], false).is_err()
            );
        }
        assert!(
            CommittedDataFlatValue::priced_values(&[Felt::MAX], &[row.clone()], false).is_err()
        );
        assert!(
            CommittedDataFlatValue::priced_values(
                &[Felt::ONE, Felt::ONE],
                &[row.clone(), CommittedDataFlatValue { value: Felt::TWO, ..row }],
                true
            )
            .is_err()
        );
    }

    /// Both VM and Native enter read_values_shared. A local hit must not request any proof;
    /// an absent key still falls through and consumes the same authenticated zero-read charge.
    #[test]
    fn shared_syscall_uses_flat_present_values_and_falls_back_for_absence() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use starknet_api::abi::abi_utils::selector_from_name;

        use super::super::{
            CommittedDataProvider,
            CommittedDataReadSet,
            CommittedDataWitnesses,
            read_values_shared,
            resources_gas,
        };
        #[derive(Debug)]
        struct Provider {
            tree: CommittedDataSet,
            batches: AtomicUsize,
        }
        impl CommittedDataProvider for Provider {
            fn flat_values(
                &self,
                _: Felt,
                keys: &[Felt],
            ) -> Result<Option<Vec<CommittedDataFlatValue>>, CommittedDataError> {
                if keys.iter().any(|&k| self.tree.lookup_witness(k).read_value() == Felt::ZERO) {
                    return Ok(None);
                }
                Ok(Some(rows(&self.tree, keys)))
            }
            fn batch(
                &self,
                root: Felt,
                keys: &[Felt],
            ) -> Result<CommittedDataBatchProof, CommittedDataError> {
                assert_eq!(root, self.tree.root());
                self.batches.fetch_add(1, Ordering::Relaxed);
                CommittedDataBatchProof::from_dataset(&self.tree, keys)
            }
            fn value(&self, _: Felt, _: Felt) -> Result<Option<(Felt, usize)>, CommittedDataError> {
                panic!("scalar provider not used")
            }
        }
        let tree = CommittedDataSet::new(vec![
            (Felt::ONE, Felt::from(251)),
            (Felt::THREE, Felt::from(252)),
        ])
        .unwrap();
        let root = tree.root();
        let provider = Arc::new(Provider { tree, batches: AtomicUsize::new(0) });
        let witnesses = CommittedDataWitnesses::from_provider(provider.clone());
        for (key, expected_batches) in [(Felt::ONE, 0), (Felt::TWO, 1)] {
            let expected = CommittedDataBatchProof::from_dataset(&provider.tree, &[key])
                .unwrap()
                .priced_values(root, &[key], false)
                .unwrap();
            let mut gas = resources_gas(&expected.1);
            let reads = CommittedDataReadSet::default();
            let actual = read_values_shared(
                true,
                &witnesses,
                &reads,
                selector_from_name("get_value").0,
                &[root, key],
                &mut gas,
                &mut None,
            )
            .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(gas, 0);
            assert_eq!(provider.batches.load(Ordering::Relaxed), expected_batches);
        }
    }
}
