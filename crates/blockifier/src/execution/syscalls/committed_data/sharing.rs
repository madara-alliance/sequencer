//! The block read set carries the private witnesses needed for replay.
//! Each admitted request funds its own proof, regardless of prior reads.
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;

use super::*;

#[derive(Clone, Debug, Default)]
struct ReadSet {
    witnesses: HashSet<(Felt, Felt)>,
}

/// One ordered block's charged (root, key) reads, including authenticated absence.
/// Clone shares state within a transaction; `fork` isolates speculative execution.
#[derive(Clone, Debug, Default)]
pub struct CommittedDataReadSet(Arc<Mutex<ReadSet>>);

impl CommittedDataReadSet {
    /// Witnesses required by admitted execution through either selector.
    pub fn witness_keys(&self) -> Vec<(Felt, Felt)> {
        let mut keys: Vec<_> = self
            .0
            .lock()
            .expect("Committed-data read set poisoned")
            .witnesses
            .iter()
            .copied()
            .collect();
        keys.sort_unstable();
        keys
    }

    pub fn is_empty(&self) -> bool {
        self.0.lock().expect("Committed-data read set poisoned").witnesses.is_empty()
    }

    pub fn fork(&self) -> Self {
        Self(Arc::new(Mutex::new(self.0.lock().expect("Committed-data read set poisoned").clone())))
    }

    /// Publish an accepted fork, or restore a checkpoint when execution is omitted by SNOS.
    pub fn replace_with(&self, other: &Self) {
        let replacement = other.0.lock().expect("Committed-data read set poisoned").clone();
        *self.0.lock().expect("Committed-data read set poisoned") = replacement;
    }
}

/// The cf40 block-sharing estimate retained for older tooling.
#[deprecated(note = "PR10 estimate. Use read_values with authenticated witnesses for PR11 pricing.")]
pub fn shared_request_resources(count: usize) -> ExecutionResources {
    cf40_request(count)
}
fn cf40_request(count: usize) -> ExecutionResources {
    use cairo_vm::types::builtin_name::BuiltinName;
    ExecutionResources {
        n_steps: 800 + 80 * count,
        n_memory_holes: 0,
        builtin_instance_counter: std::collections::BTreeMap::from([(
            BuiltinName::range_check,
            20 + 4 * count,
        )]),
    }
}

pub fn resources_gas(resources: &ExecutionResources) -> u64 {
    use cairo_vm::types::builtin_name::BuiltinName;
    let count = |name| resources.builtin_instance_counter.get(&name).copied().unwrap_or(0) as u64;
    resources.n_steps as u64 * STEP_SIERRA_GAS
        + resources.n_memory_holes as u64 * 10
        + count(BuiltinName::range_check) * RANGE_CHECK_SIERRA_GAS
        + count(BuiltinName::poseidon) * POSEIDON_SIERRA_GAS
        + count(BuiltinName::bitwise) * BITWISE_SIERRA_GAS
}

/// The cf40 cold-path estimate retained for older tooling.
#[deprecated(note = "PR10 estimate. Use read_values with authenticated witnesses for PR11 pricing.")]
pub fn standard_path_resources(count: usize) -> ExecutionResources {
    cf40_paths(count)
}
pub(super) fn cf40_resources(count: usize, unique: usize) -> ExecutionResources {
    &cf40_request(count) + &cf40_paths(unique)
}
fn cf40_paths(count: usize) -> ExecutionResources {
    if count == 0 {
        return ExecutionResources::default();
    }
    use cairo_vm::types::builtin_name::BuiltinName;
    ExecutionResources {
        n_steps: 252000 * count,
        n_memory_holes: 0,
        builtin_instance_counter: [
            (BuiltinName::range_check, 25200 * count),
            (BuiltinName::poseidon, 502 * count),
        ]
        .into(),
    }
}

/// Both selectors fund per-call authentication. Publish the block witness set only after payment.
pub fn read_values_shared(
    enabled: bool,
    witnesses: &CommittedDataWitnesses,
    read_set: &CommittedDataReadSet,
    selector: Felt,
    calldata: &[Felt],
    remaining_gas: &mut u64,
    failure: &mut Option<CommittedDataError>,
) -> Result<(Vec<Felt>, ExecutionResources), SyscallExecutorBaseError> {
    if !enabled {
        let error = CommittedDataError::Disabled;
        let info = error.to_string();
        failure.get_or_insert(error);
        return Err(SyscallExecutorBaseError::InvalidSyscallInput { input: selector, info });
    }
    let (keys, batch) = metered_read_keys(selector, calldata, remaining_gas, failure)?;
    let root = calldata[0];
    let availability = |error: CommittedDataError, failure: &mut Option<CommittedDataError>| {
        let result = SyscallExecutorBaseError::InvalidSyscallInput {
            input: selector,
            info: error.to_string(),
        };
        failure.get_or_insert(error);
        result
    };
    if keys.iter().any(|key| !valid_key(*key)) {
        return Err(availability(CommittedDataError::InvalidWitness, failure));
    }
    let requested: HashSet<_> = keys.iter().map(|key| (root, *key)).collect();
    let fits = |seen: &ReadSet| {
        seen.witnesses.len() + requested.difference(&seen.witnesses).count()
            <= MAX_COMMITTED_DATA_WITNESSES
    };
    if !fits(&read_set.0.lock().expect("Committed-data read set poisoned")) {
        return Err(availability(CommittedDataError::TooManyWitnesses, failure));
    }
    let minimum = resources_gas(&pricing::base_resources(keys.len(), requested.len()));
    if *remaining_gas < minimum {
        return Err(availability(
            CommittedDataError::InsufficientGas { required: minimum, remaining: *remaining_gas },
            failure,
        ));
    }
    let (values, resources) =
        witnesses.priced_values(root, keys, batch).map_err(|error| availability(error, failure))?;
    let mut seen = read_set.0.lock().expect("Committed-data read set poisoned");
    if !fits(&seen) {
        return Err(availability(CommittedDataError::TooManyWitnesses, failure));
    }
    charge_authenticated_read(selector, resources_gas(&resources), remaining_gas, failure)?;
    seen.witnesses.extend(requested);
    Ok((values, resources))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_reads_pay_for_both_outcomes_and_publish_only_paid_forks() {
        let tree = CommittedDataSet::new(vec![(Felt::ONE, Felt::from(100))]).unwrap();
        let witnesses = CommittedDataWitnesses::new(vec![
            tree.lookup_witness(Felt::ZERO),
            tree.lookup_witness(Felt::ONE),
        ])
        .unwrap();
        let block = CommittedDataReadSet::default();
        let call = |read_set: &CommittedDataReadSet, mut gas| {
            read_values_shared(
                true,
                &witnesses,
                read_set,
                selector_from_name("get_values").0,
                &[tree.root(), Felt::THREE, Felt::ONE, Felt::ZERO, Felt::ONE],
                &mut gas,
                &mut None,
            )
        };
        let rejected = block.fork();
        assert!(call(&rejected, 0).is_err());
        assert!(rejected.is_empty());
        let accepted = block.fork();
        let (values, cold) = call(&accepted, u64::MAX).unwrap();
        assert_eq!(values, vec![Felt::THREE, Felt::from(100), Felt::ZERO, Felt::from(100)]);
        assert!(cold.n_memory_holes > 0);
        assert_eq!(call(&block, u64::MAX).unwrap().1, cold);
        block.replace_with(&accepted);
        assert_eq!(call(&block, u64::MAX).unwrap().1, cold);
        assert_eq!(block.witness_keys().len(), 2);
    }

    /// Both selectors consume the same block allowance; single reads keep their original gas.
    #[rstest::rstest]
    #[case::single("get_value", false)]
    #[case::batch("get_values", true)]
    fn witness_capacity_defers_a_transaction_without_consuming_its_nonce(
        #[case] selector: &str,
        #[case] batch: bool,
    ) {
        use blockifier_test_utils::cairo_versions::{CairoVersion, RunnableCairo1};
        use blockifier_test_utils::calldata::create_calldata;
        use starknet_api::invoke_tx_args;

        use crate::blockifier::config::TransactionExecutorConfig;
        use crate::blockifier::transaction_executor::{
            TransactionExecutor,
            TransactionExecutorError,
        };
        use crate::context::BlockContext;
        use crate::state::state_api::StateReader;
        use crate::transaction::test_utils::{
            create_test_init_data,
            default_all_resource_bounds,
            invoke_tx_with_default_flags,
        };
        use crate::transaction::transaction_execution::Transaction;

        let tree = CommittedDataSet::new(vec![(Felt::ZERO, Felt::TWO)]).unwrap();
        let mut context = BlockContext::create_for_testing();
        context.use_committed_data = true;
        context.committed_data_witnesses =
            Arc::new(CommittedDataWitnesses::new(vec![tree.witness(Felt::ZERO).unwrap()]).unwrap());
        let data =
            create_test_init_data(&context.chain_info, CairoVersion::Cairo1(RunnableCairo1::Casm));
        let args = if batch {
            vec![tree.root(), Felt::ONE, Felt::ZERO]
        } else {
            vec![tree.root(), Felt::ZERO]
        };
        let transaction = Transaction::Account(invoke_tx_with_default_flags(invoke_tx_args! {
            sender_address: data.account_address,
            resource_bounds: default_all_resource_bounds(),
            calldata: create_calldata(COMMITTED_DATA_ADDRESS.try_into().unwrap(), selector, &args),
        }));
        let mut executor = TransactionExecutor::new(
            data.state,
            context.clone(),
            TransactionExecutorConfig::default(),
        );
        // Model the distinct keys admitted before this transaction without executing 65k calls.
        executor
            .block_context
            .committed_data_read_set
            .0
            .lock()
            .unwrap()
            .witnesses
            .extend((0..MAX_COMMITTED_DATA_WITNESSES).map(|key| (Felt::ONE, Felt::from(key))));
        let nonce =
            executor.block_state.as_ref().unwrap().get_nonce_at(data.account_address).unwrap();
        assert!(matches!(executor.execute(&transaction), Err(TransactionExecutorError::BlockFull)));
        assert_eq!(
            executor.block_state.as_ref().unwrap().get_nonce_at(data.account_address).unwrap(),
            nonce
        );
        assert_eq!(
            executor.block_context.committed_data_read_set.witness_keys().len(),
            MAX_COMMITTED_DATA_WITNESSES
        );
        let state = executor.block_state.take().unwrap();
        let mut next =
            TransactionExecutor::new(state, context, TransactionExecutorConfig::default());
        let (execution, _) = next.execute(&transaction).unwrap();
        assert!(execution.revert_error.is_none());
        assert_eq!(
            next.block_context.committed_data_read_set.witness_keys(),
            vec![(tree.root(), Felt::ZERO)]
        );
        assert_ne!(
            next.block_state.as_ref().unwrap().get_nonce_at(data.account_address).unwrap(),
            nonce
        );
    }
}
