//! Paid non-membership failures. A failed batch authenticates its successful prefix and then
//! the first absent key; unavailable evidence still aborts admission instead of inventing a revert.
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;

use super::*;

pub const MISSING_KEY_FELT: Felt = Felt::from_hex_unchecked("0x43445f4b45595f4e4f545f464f554e44"); // CD_KEY_NOT_FOUND

// A second traversal compares both keys at every committed branch. High-bit extraction
// is the worst case; the direct Cairo matrix includes memory holes in the step bound.
const ABSENCE_STEPS_BASE: usize = 200;
const ABSENCE_STEPS_PER_LEVEL: usize = 300;
const ABSENCE_RANGE_CHECKS_BASE: usize = 20;
const ABSENCE_RANGE_CHECKS_PER_LEVEL: usize = 20;

/// Additional key decomposition/routing checks; leaf and branch hashes are unchanged.
/// These bounds must cover Cairo steps plus memory holes at every supported depth.
pub fn absence_os_resources(height: usize) -> ExecutionResources {
    use cairo_vm::types::builtin_name::BuiltinName;
    let mut resources = read_os_resources(height);
    resources.n_steps += ABSENCE_STEPS_BASE + ABSENCE_STEPS_PER_LEVEL * height;
    *resources.builtin_instance_counter.entry(BuiltinName::range_check).or_default() +=
        ABSENCE_RANGE_CHECKS_BASE + ABSENCE_RANGE_CHECKS_PER_LEVEL * height;
    resources
}

/// Successful admission can contain a paid syscall failure. Keep its resources separate from
/// node availability errors so both VM and Native account caught failures without rejecting them.
pub fn read_outcome(
    enabled: bool,
    witnesses: &CommittedDataWitnesses,
    read_set: &CommittedDataReadSet,
    selector: Felt,
    calldata: &[Felt],
    remaining_gas: &mut u64,
    failure: &mut Option<CommittedDataError>,
) -> Result<(Result<Vec<Felt>, Felt>, ExecutionResources), SyscallExecutorBaseError> {
    // Keep the successful fast path unchanged. A failed authenticated lookup has not charged
    // gas or warmed the read set; only then do we look for evidence of the first absent key.
    let mut lookup_failure = None;
    let result = read_values_shared(
        enabled,
        witnesses,
        read_set,
        selector,
        calldata,
        remaining_gas,
        &mut lookup_failure,
    );
    if let Ok((values, resources)) = result {
        return Ok((Ok(values), resources));
    }
    let keys = read_keys(selector, calldata).ok().filter(|_| {
        enabled
            && !matches!(
                lookup_failure,
                Some(
                    CommittedDataError::InsufficientGas { .. }
                        | CommittedDataError::TooManyWitnesses
                )
            )
    });
    let Some((keys, batch)) = keys else {
        if failure.is_none() {
            *failure = lookup_failure;
        }
        return result.map(|(values, resources)| (Ok(values), resources));
    };
    let root = calldata[0];
    let mut missing = None;
    for (index, key) in keys.iter().copied().enumerate() {
        match witnesses.value(root, key) {
            Ok(Some(_)) => {}
            Ok(None) => {
                missing = Some((index, key));
                break;
            }
            Err(error) => return Err(availability(selector, error, failure)),
        }
    }
    let Some((index, key)) = missing else {
        if failure.is_none() {
            *failure = lookup_failure;
        }
        return result.map(|(values, resources)| (Ok(values), resources));
    };
    let witness =
        witnesses.absence(root, key).map_err(|error| availability(selector, error, failure))?;
    let mut resources = ExecutionResources::default();
    if index > 0 {
        debug_assert!(batch);
        let mut prefix = vec![root, Felt::from(index)];
        prefix.extend_from_slice(&keys[..index]);
        let (_, prefix_resources) = read_values_shared(
            true,
            witnesses,
            read_set,
            selector,
            &prefix,
            remaining_gas,
            failure,
        )?;
        resources += &prefix_resources;
        // Prefix and terminal verification share one outer call_contract allowance, not two.
        let overhead = ExecutionResources {
            n_steps: CALL_CONTRACT_STEPS,
            builtin_instance_counter: [(
                cairo_vm::types::builtin_name::BuiltinName::range_check,
                CALL_CONTRACT_RANGE_CHECKS,
            )]
            .into(),
            n_memory_holes: 0,
        };
        charge_authenticated_read(selector, resources_gas(&overhead), remaining_gas, failure)?;
        resources += &overhead;
    }
    let absent_resources = absence_os_resources(witness.siblings.len());
    read_set
        .check_witness_capacity(root, key)
        .map_err(|error| availability(selector, error, failure))?;
    charge_authenticated_read(selector, resources_gas(&absent_resources), remaining_gas, failure)?;
    read_set.record_absence(root, key);
    resources += &absent_resources;
    Ok((Err(MISSING_KEY_FELT), resources))
}

fn availability(
    selector: Felt,
    error: CommittedDataError,
    failure: &mut Option<CommittedDataError>,
) -> SyscallExecutorBaseError {
    let result =
        SyscallExecutorBaseError::InvalidSyscallInput { input: selector, info: error.to_string() };
    failure.get_or_insert(error);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    #[case::single(false, 0)]
    #[case::first(true, 0)]
    #[case::middle(true, 2)]
    #[case::last(true, 3)]
    fn paid_absence_reverts_and_only_authenticates_the_prefix(
        #[case] batch: bool,
        #[case] position: usize,
    ) {
        let tree =
            CommittedDataSet::new(vec![(Felt::ZERO, Felt::ZERO), (Felt::ONE, Felt::MAX)]).unwrap();
        let keys: Vec<_> = if batch {
            (0..4).map(|index| if index == position { Felt::TWO } else { Felt::ONE }).collect()
        } else {
            vec![Felt::TWO]
        };
        let witnesses = CommittedDataWitnesses::new(vec![
            tree.lookup_witness(Felt::ONE),
            tree.lookup_witness(Felt::TWO),
        ])
        .unwrap();
        let selector = selector_from_name(if batch { "get_values" } else { "get_value" }).0;
        let mut calldata = vec![tree.root()];
        if batch {
            calldata.push(Felt::from(keys.len()));
        }
        calldata.extend(keys);
        let read_set = CommittedDataReadSet::default();
        let mut gas = 100_000_000;
        let mut failure = None;
        let (outcome, resources) =
            read_outcome(true, &witnesses, &read_set, selector, &calldata, &mut gas, &mut failure)
                .unwrap();
        assert_eq!(outcome, Err(MISSING_KEY_FELT));
        assert!(failure.is_none());
        assert_eq!(100_000_000 - gas, resources_gas(&resources));
        let used = read_set.witness_keys();
        assert!(used.contains(&(tree.root(), Felt::TWO)));
        assert_eq!(used.contains(&(tree.root(), Felt::ONE)), position > 0);
        let mut underfunded_failure = None;
        assert!(
            read_outcome(
                true,
                &witnesses,
                &CommittedDataReadSet::default(),
                selector,
                &calldata,
                &mut (resources_gas(&resources) - 1),
                &mut underfunded_failure
            )
            .is_err()
        );
        assert!(matches!(underfunded_failure, Some(CommittedDataError::InsufficientGas { .. })));
    }

    #[test]
    fn absent_evidence_is_not_an_availability_fallback() {
        let mut failure = None;
        assert!(
            read_outcome(
                true,
                &CommittedDataWitnesses::default(),
                &CommittedDataReadSet::default(),
                selector_from_name("get_value").0,
                &[Felt::ONE, Felt::TWO],
                &mut u64::MAX,
                &mut failure
            )
            .is_err()
        );
        let error = failure.unwrap();
        assert!(matches!(
            error,
            CommittedDataError::Unavailable { root, key } if root == Felt::ONE && key == Felt::TWO
        ));
        assert_eq!(
            error.to_string(),
            "Committed-data witness unavailable for root 0x1 and key 0x2"
        );
    }
}
