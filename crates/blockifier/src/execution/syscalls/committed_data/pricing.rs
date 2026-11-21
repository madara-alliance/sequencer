//! Exact per-call pricing for the experimental standard Patricia reader.
//!
//! A quote covers the call's dictionary, returned values and authenticated traversal. The OS
//! independently derives the same class and constrains the returned gas. Earlier calls do not
//! discount this work; the ordinary CallContract charge remains outside this reservation.
//! These coefficients bound the compiled committed_data.cairo paths, including memory holes.
//! Changes to those paths require rechecking the bound, not just adjusting measured averages.
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use num_traits::ToPrimitive;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

use super::{COMMITTED_DATA_TREE_HEIGHT, CommittedDataBatchProof, CommittedDataError, valid_key};
use crate::blockifier_versioned_constants::VersionedConstants;

/// Reject an enabled call when the active schedule differs from the compiled OS charge.
/// This checks arithmetic agreement; selecting the historical OS remains the caller's concern.
pub fn read_permission(
    enabled: bool,
    version: &VersionedConstants,
) -> Result<bool, CommittedDataError> {
    let costs = &version.os_constants.gas_costs;
    if enabled
        && !(version.block_direct_execute_call
            && costs.base.step_gas_cost == 100
            && costs.base.memory_hole_gas_cost == 10
            && costs.builtins.range_check == 70
            && costs.builtins.poseidon == 491)
    {
        return Err(CommittedDataError::UnsupportedReadSchedule);
    }
    Ok(enabled)
}

pub(super) fn malformed_resources() -> ExecutionResources {
    ExecutionResources {
        n_steps: 184,
        n_memory_holes: 43,
        builtin_instance_counter: [(BuiltinName::range_check, 9)].into(),
    }
}

#[derive(Default)]
struct ReadClass {
    // Count positions opened, including residual edge hashes; repeated fact hashes still cost
    // work.
    hashes: usize,
    // Distinct queried keys authenticated as zero, including absence.
    absent: usize,
    // Authenticated frontier siblings greater than 251 cannot be compressed-length markers.
    large: usize,
}

impl ReadClass {
    fn resources(
        &self,
        count: usize,
        unique: usize,
    ) -> Result<ExecutionResources, CommittedDataError> {
        let Self { hashes, absent, large } = *self;
        let present = unique.checked_sub(absent).ok_or(CommittedDataError::InvalidWitness)?;
        // A binary tree connecting these present leaves and frontier siblings needs at least
        // F = max(0, large + present - 1) binary openings. They are cheaper than the generic
        // opening bound, so subtract only these guaranteed savings. Small siblings are ignored
        // by F, which conservatively covers legitimate small leaf values as well as markers.
        let binary_floor = (large + present).saturating_sub(1);
        if binary_floor > hashes || hashes > 2 * COMMITTED_DATA_TREE_HEIGHT * unique {
            return Err(CommittedDataError::InvalidWitness);
        }
        let mut resources = base_resources(count, unique);
        resources.n_steps += 249 * hashes + 287 * absent - 167 * binary_floor;
        resources.n_memory_holes += 31 * hashes + 50 * absent - 19 * binary_floor;
        *resources.builtin_instance_counter.entry(BuiltinName::range_check).or_default() +=
            20 * hashes + 28 * absent - 16 * binary_floor;
        resources.builtin_instance_counter.insert(BuiltinName::poseidon, hashes);
        Ok(resources)
    }
}

pub(super) fn base_resources(count: usize, unique: usize) -> ExecutionResources {
    // Fixed, occurrence and unique-key terms are payable for every valid plan.
    // The compiled Cairo charge adds the nonnegative authenticated class terms.
    ExecutionResources {
        n_steps: 2415 + 86 * count + 231 * unique,
        n_memory_holes: 345 + 18 * count + 31 * unique,
        builtin_instance_counter: [(BuiltinName::range_check, 9 + 5 * count + 16 * unique)].into(),
    }
}

type Leaf = ([u8; 32], Felt);

fn bit(bytes: &[u8; 32], index: usize) -> u8 {
    (bytes[31 - index / 8] >> (index % 8)) & 1
}

fn suffix(path: &[u8; 32], length: usize) -> Felt {
    let mut result = [0; 32];
    let start = 32 - length / 8;
    result[start..].copy_from_slice(&path[start..]);
    if length % 8 != 0 {
        result[start - 1] = path[start - 1] & ((1 << (length % 8)) - 1);
    }
    Felt::from_bytes_be(&result)
}

impl CommittedDataBatchProof {
    /// Authenticate the requested path occurrences and provider's response in one traversal.
    pub(super) fn priced_values(
        &self,
        root: Felt,
        keys: &[Felt],
        batch: bool,
    ) -> Result<(Vec<Felt>, ExecutionResources), CommittedDataError> {
        let invalid = || CommittedDataError::InvalidWitness;
        if self.indices.len() != keys.len()
            || self.leaves.len() % 2 != 0
            || self.unique_leaves() > keys.len()
        {
            return Err(invalid());
        }
        let mut leaves = Vec::with_capacity(keys.len());
        let mut values = Vec::with_capacity(keys.len() + usize::from(batch));
        if batch {
            values.push(Felt::from(keys.len()));
        }
        for (&key, &idx) in keys.iter().zip(&self.indices) {
            if idx >= self.unique_leaves() || self.leaves[2 * idx] != key || !valid_key(key) {
                return Err(invalid());
            }
            let value = self.leaves[2 * idx + 1];
            leaves.push((key.to_bytes_be(), value));
            values.push(value);
        }
        leaves.sort_unstable();
        leaves.dedup();
        if leaves.len() != self.unique_leaves() || leaves.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(invalid());
        }
        let mut class = ReadClass::default();
        self.visit(root, COMMITTED_DATA_TREE_HEIGHT, &leaves, &mut class)?;
        Ok((values, class.resources(keys.len(), leaves.len())?))
    }

    fn visit(
        &self,
        root: Felt,
        height: usize,
        keys: &[Leaf],
        class: &mut ReadClass,
    ) -> Result<(), CommittedDataError> {
        let invalid = || CommittedDataError::InvalidWitness;
        if keys.is_empty() {
            return Ok(());
        }
        if root == Felt::ZERO {
            if keys.iter().any(|(_, value)| *value != Felt::ZERO) {
                return Err(invalid());
            }
            class.absent += keys.len();
            return Ok(());
        }
        if height == 0 {
            if keys.len() != 1 || keys[0].1 != root {
                return Err(invalid());
            }
            return Ok(());
        }
        class.hashes += 1;
        let threshold = Felt::from(COMMITTED_DATA_TREE_HEIGHT);
        match self.facts.get(&root).ok_or_else(invalid)?.as_slice() {
            [left, right] => {
                if *left == Felt::ZERO
                    || *right == Felt::ZERO
                    || Poseidon::hash(left, right) != root
                {
                    return Err(invalid());
                }
                let split = keys.partition_point(|(key, _)| bit(key, height - 1) == 0);
                if (split == 0 && *left > threshold) || (split == keys.len() && *right > threshold)
                {
                    class.large += 1;
                }
                self.visit(*left, height - 1, &keys[..split], class)?;
                self.visit(*right, height - 1, &keys[split..], class)
            }
            [len, path, bottom] => {
                let length =
                    len.to_usize().filter(|n| (1..=height).contains(n)).ok_or_else(invalid)?;
                let bits = path.to_bytes_be();
                if *bottom == Felt::ZERO
                    || suffix(&bits, length) != *path
                    || Poseidon::hash(bottom, path) + *len != root
                {
                    return Err(invalid());
                }
                let mut first = keys.len();
                let mut matches = 0;
                let mut longest = 0;
                for (i, (key, value)) in keys.iter().enumerate() {
                    let common = (0..length)
                        .take_while(|j| bit(key, height - 1 - j) == bit(&bits, length - 1 - j))
                        .count();
                    longest = longest.max(common);
                    if common == length {
                        first = first.min(i);
                        matches += 1;
                    } else if *value == Felt::ZERO {
                        class.absent += 1;
                    } else {
                        return Err(invalid());
                    }
                }
                if matches != 0 {
                    return self.visit(
                        *bottom,
                        height - length,
                        &keys[first..first + matches],
                        class,
                    );
                }
                let remaining = length - longest - 1;
                let sibling = if remaining == 0 {
                    *bottom
                } else {
                    class.hashes += 1;
                    Poseidon::hash(bottom, &suffix(&bits, remaining)) + Felt::from(remaining)
                };
                class.large += usize::from(sibling > threshold);
                Ok(())
            }
            _ => Err(invalid()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::syscalls::committed_data::{
        CommittedDataSet,
        CommittedDataWitnesses,
        read_values,
        resources_gas,
    };

    #[test]
    fn malformed_response_is_paid_or_transaction_fatal() {
        let charge = resources_gas(&malformed_resources());
        let mut failure = None;
        let mut gas = charge;
        assert!(matches!(
            read_values(
                true,
                &CommittedDataWitnesses::default(),
                Felt::ZERO,
                &[],
                &mut gas,
                &mut failure
            ),
            Err(super::super::SyscallExecutorBaseError::Revert { .. })
        ));
        assert_eq!(gas, 0);
        assert!(failure.is_none());
        let mut gas = charge - 1;
        assert!(
            read_values(
                true,
                &CommittedDataWitnesses::default(),
                Felt::ZERO,
                &[],
                &mut gas,
                &mut failure
            )
            .is_err()
        );
        assert_eq!(gas, charge - 1);
        assert!(matches!(failure, Some(CommittedDataError::InsufficientGas { .. })));
    }

    #[test]
    fn provider_response_must_match_the_requested_authenticated_leaves() {
        let tree = CommittedDataSet::new(vec![(Felt::TWO, Felt::from(252))]).unwrap();
        let keys = [Felt::ONE, Felt::TWO, Felt::ONE];
        let mut proof = CommittedDataBatchProof::from_dataset(&tree, &keys).unwrap();
        let (values, resources) = proof.priced_values(tree.root(), &keys, true).unwrap();
        assert_eq!(values, vec![Felt::THREE, Felt::ZERO, Felt::from(252), Felt::ZERO]);
        assert!(resources.n_memory_holes > 0);
        proof.indices.swap(0, 1);
        assert!(proof.priced_values(tree.root(), &keys, true).is_err());
        proof.indices.swap(0, 1);
        proof.leaves[1] = Felt::ONE;
        assert!(proof.priced_values(tree.root(), &keys, true).is_err());
    }
}
