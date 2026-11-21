//! Missing keys use the same standard Patricia verifier and tariff as present keys.
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;

use super::*;
#[deprecated(note = "PR10 estimate. Use read_values with authenticated witnesses for PR11 pricing.")]
pub fn absence_os_resources(_height: usize) -> ExecutionResources {
    sharing::cf40_resources(1, 1)
}
pub fn read_outcome(
    enabled: bool,
    witnesses: &CommittedDataWitnesses,
    read_set: &CommittedDataReadSet,
    selector: Felt,
    calldata: &[Felt],
    remaining_gas: &mut u64,
    failure: &mut Option<CommittedDataError>,
) -> Result<(Vec<Felt>, ExecutionResources), SyscallExecutorBaseError> {
    read_values_shared(enabled, witnesses, read_set, selector, calldata, remaining_gas, failure)
}

pub(crate) fn read_outcome_with_permission(
    permission: Result<bool, CommittedDataError>,
    witnesses: &CommittedDataWitnesses,
    read_set: &CommittedDataReadSet,
    selector: Felt,
    calldata: &[Felt],
    remaining_gas: &mut u64,
    failure: &mut Option<CommittedDataError>,
) -> Result<(Vec<Felt>, ExecutionResources), SyscallExecutorBaseError> {
    let enabled = permission.map_err(|error| {
        let info = error.to_string();
        failure.get_or_insert(error);
        SyscallExecutorBaseError::InvalidSyscallInput { input: selector, info }
    })?;
    read_outcome(enabled, witnesses, read_set, selector, calldata, remaining_gas, failure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    #[case::single(false, 0)]
    #[case::first(true, 0)]
    #[case::middle(true, 2)]
    #[case::last(true, 3)]
    fn paid_absence_returns_zero_and_authenticates_the_whole_batch(
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
        calldata.extend_from_slice(&keys);
        let read_set = CommittedDataReadSet::default();
        let mut gas = 100_000_000;
        let mut failure = None;
        let (outcome, resources) =
            read_outcome(true, &witnesses, &read_set, selector, &calldata, &mut gas, &mut failure)
                .unwrap();
        let mut expected = if batch { vec![Felt::from(keys.len())] } else { vec![] };
        expected
            .extend(keys.iter().map(|key| if *key == Felt::TWO { Felt::ZERO } else { Felt::MAX }));
        assert_eq!(outcome, expected);
        assert!(failure.is_none());
        assert_eq!(100_000_000 - gas, resources_gas(&resources));
        let used = read_set.witness_keys();
        assert!(used.contains(&(tree.root(), Felt::TWO)));
        assert_eq!(used.contains(&(tree.root(), Felt::ONE)), batch);
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

    /// An explicit zero and absence have equal return values but different authenticated paths.
    #[rstest::rstest]
    #[case::all_absent(vec![Felt::TWO, Felt::THREE, Felt::TWO])]
    #[case::alternating(vec![Felt::TWO, Felt::ONE, Felt::THREE, Felt::ZERO, Felt::TWO])]
    #[case::maximum_duplicates(vec![Felt::TWO; MAX_COMMITTED_DATA_READ_KEYS])]
    fn mixed_reads_preserve_order_and_cache_absence(#[case] keys: Vec<Felt>) {
        let tree =
            CommittedDataSet::new(vec![(Felt::ZERO, Felt::ZERO), (Felt::ONE, Felt::MAX)]).unwrap();
        let witnesses = CommittedDataWitnesses::new(
            [Felt::ZERO, Felt::ONE, Felt::TWO, Felt::THREE]
                .map(|key| tree.lookup_witness(key))
                .to_vec(),
        )
        .unwrap();
        let mut calldata = vec![tree.root(), Felt::from(keys.len())];
        calldata.extend_from_slice(&keys);
        let read_set = CommittedDataReadSet::default();
        for _ in 0..2 {
            let mut gas = u64::MAX;
            let (values, resources) = read_outcome(
                true,
                &witnesses,
                &read_set,
                selector_from_name("get_values").0,
                &calldata,
                &mut gas,
                &mut None,
            )
            .unwrap();
            let expected: Vec<_> = std::iter::once(Felt::from(keys.len()))
                .chain(
                    keys.iter().map(|key| if *key == Felt::ONE { Felt::MAX } else { Felt::ZERO }),
                )
                .collect();
            assert_eq!(values, expected);
            assert_eq!(u64::MAX - gas, resources_gas(&resources));
        }
    }

    #[rstest::rstest]
    #[case::unavailable_suffix(false)]
    #[case::insufficient_gas(true)]
    fn incomplete_mixed_read_does_not_publish_partial_accounting(#[case] supplied_suffix: bool) {
        let tree = CommittedDataSet::new(vec![(Felt::ZERO, Felt::ONE)]).unwrap();
        let mut proofs = vec![tree.lookup_witness(Felt::ZERO), tree.lookup_witness(Felt::ONE)];
        if supplied_suffix {
            proofs.push(tree.lookup_witness(Felt::TWO));
        }
        let witnesses = CommittedDataWitnesses::new(proofs).unwrap();
        let reads = CommittedDataReadSet::default();
        let mut gas = if supplied_suffix { 0 } else { u64::MAX };
        let before = gas;
        let mut failure = None;
        assert!(
            read_outcome(
                true,
                &witnesses,
                &reads,
                selector_from_name("get_values").0,
                &[tree.root(), Felt::THREE, Felt::ZERO, Felt::ONE, Felt::TWO],
                &mut gas,
                &mut failure
            )
            .is_err()
        );
        assert!(reads.is_empty());
        assert_eq!(gas, before);
        assert!(failure.is_some());
    }

    #[test]
    fn absent_evidence_is_not_an_availability_fallback() {
        let mut failure = None;
        let mut gas = u64::MAX;
        assert!(
            read_outcome(
                true,
                &CommittedDataWitnesses::default(),
                &CommittedDataReadSet::default(),
                selector_from_name("get_value").0,
                &[Felt::ONE, Felt::TWO],
                &mut gas,
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
