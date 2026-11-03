//! Exercise the Cairo entrypoint directly: Rust validation must not hide unconstrained hints.
use std::collections::HashMap;

use apollo_starknet_os_program::OS_PROGRAM_BYTES;
use apollo_starknet_os_program::test_programs::COMMITTED_DATA_TEST_BYTES;
use blockifier::execution::syscalls::committed_data::{
    CommittedDataSet,
    CommittedDataSibling,
    CommittedDataWitness,
    MISSING_KEY_FELT,
    absence_os_resources,
    batch_gas,
    read_gas,
    resources_gas,
};
use blockifier::test_utils::dict_state_reader::DictStateReader;
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::cairo_runner::CairoArg;
use starknet_os::hint_processor::snos_hint_processor::SnosHintProcessor;
use starknet_os::io::os_input::OsHintsConfig;
use starknet_os::test_utils::cairo_runner::{
    EMPTY_BLOCK_INPUT,
    EntryPointRunnerConfig,
    ImplicitArg,
    initialize_cairo_runner,
};
use starknet_types_core::felt::Felt;

fn read_authenticated(
    witness: CommittedDataWitness,
    gas: u64,
    batch: bool,
) -> Result<Vec<MaybeRelocatable>, Box<dyn std::error::Error>> {
    read_measured(witness, gas, batch).map(|(values, _)| values)
}

fn read_measured(
    witness: CommittedDataWitness,
    gas: u64,
    batch: bool,
) -> Result<
    (Vec<MaybeRelocatable>, cairo_vm::vm::runners::cairo_runner::ExecutionResources),
    Box<dyn std::error::Error>,
> {
    let entrypoint = if batch {
        "starkware.starknet.core.os.execution.committed_data.committed_data_read_batch"
    } else {
        "starkware.starknet.core.os.execution.committed_data.committed_data_read_one"
    };
    let builtins = if batch {
        vec![BuiltinName::range_check, BuiltinName::bitwise, BuiltinName::poseidon]
    } else {
        vec![BuiltinName::range_check, BuiltinName::poseidon]
    };
    let (mut runner, program, _) = initialize_cairo_runner(
        &EntryPointRunnerConfig {
            layout: LayoutName::all_cairo,
            add_main_prefix_to_entrypoint: false,
            ..Default::default()
        },
        if batch { COMMITTED_DATA_TEST_BYTES } else { OS_PROGRAM_BYTES },
        entrypoint,
        &builtins.iter().copied().map(ImplicitArg::Builtin).collect::<Vec<_>>(),
        HashMap::new(),
    )?;
    // Runner builtins use canonical order; the function takes poseidon before bitwise.
    let function_builtins = if batch {
        vec![BuiltinName::range_check, BuiltinName::poseidon, BuiltinName::bitwise]
    } else {
        builtins
    };
    let mut args: Vec<_> = function_builtins
        .iter()
        .map(|name| {
            CairoArg::Single(
                runner
                    .vm
                    .get_builtin_runners()
                    .iter()
                    .find(|builtin| builtin.name() == *name)
                    .unwrap()
                    .initial_stack()[0]
                    .clone(),
            )
        })
        .collect();
    if batch {
        args.extend([
            CairoArg::Single(witness.root.into()),
            CairoArg::Array(vec![witness.key.into()]),
            CairoArg::Single(Felt::ONE.into()),
            CairoArg::Array(vec![witness.value.into()]),
            CairoArg::Single(Felt::from(gas).into()),
        ]);
    } else {
        args.extend(
            [witness.root, witness.key, Felt::from(gas)]
                .map(|value| CairoArg::Single(value.into())),
        );
    }
    let mut hints = SnosHintProcessor::<DictStateReader>::new_for_testing(
        None,
        &program,
        Some(OsHintsConfig {
            use_committed_data: true,
            committed_data_witnesses: vec![witness],
            ..Default::default()
        }),
        &EMPTY_BLOCK_INPUT,
    )?;
    runner.run_from_entrypoint(
        program.get_identifier(entrypoint).unwrap().pc.unwrap(),
        &args.iter().collect::<Vec<_>>(),
        true,
        None,
        &mut hints,
    )?;
    Ok((runner.vm.get_return_values(if batch { 2 } else { 3 })?, runner.get_execution_resources()?))
}

#[test]
fn single_read_requires_authenticated_height_and_sufficient_gas() {
    let tree = CommittedDataSet::new(vec![(Felt::ZERO, Felt::ONE)]).unwrap();
    let witness = tree.witness(Felt::ZERO).unwrap();
    let gas = 100_000;
    assert_eq!(
        read_authenticated(witness.clone(), gas, false).unwrap(),
        [Felt::ONE, Felt::from(gas - read_gas(0)), Felt::ZERO].map(MaybeRelocatable::from)
    );
    assert!(read_authenticated(witness.clone(), 0, false).is_err());
    assert!(read_authenticated(witness.clone(), read_gas(0) - 1, false).is_err());
    assert_eq!(
        read_authenticated(witness.clone(), read_gas(0), false).unwrap(),
        [Felt::ONE, Felt::ZERO, Felt::ZERO].map(MaybeRelocatable::from)
    );
    let forged = CommittedDataWitness {
        siblings: (0..252_u8).map(|bit| CommittedDataSibling { bit, hash: Felt::ZERO }).collect(),
        ..witness
    };
    assert!(!forged.verify());
    assert!(read_authenticated(forged, gas, false).is_err());
}

#[test]
fn batch_read_cannot_prove_unpaid_verification() {
    let tree = CommittedDataSet::new(vec![(Felt::ZERO, Felt::ONE)]).unwrap();
    let witness = tree.witness(Felt::ZERO).unwrap();
    let charge = batch_gas(1, 1, 0);
    for budget in [0, charge - 1] {
        assert!(read_authenticated(witness.clone(), budget, true).is_err());
    }
    assert_eq!(
        read_authenticated(witness, charge, true).unwrap(),
        [Felt::ZERO, Felt::ZERO].map(MaybeRelocatable::from)
    );
}

/// A comb-shaped tree reaches every supported bit boundary without exponential fixtures.
/// Bit zero is omitted, so query 1 reaches leaf 0 and is provably absent even at depth 251.
#[rstest::rstest]
#[case(0)]
#[case(1)]
#[case(17)]
#[case(20)]
#[case(63)]
#[case(127)]
#[case(128)]
#[case(251)]
fn absence_cairo_is_paid_and_rejects_forged_routes(
    #[case] height: usize,
    #[values(false, true)] high_bits: bool,
) {
    let mut entries = vec![(Felt::ZERO, Felt::ZERO)];
    for bit in 1..=height {
        entries.push((
            Felt::TWO.pow(if high_bits { (252 - bit) as u32 } else { bit as u32 }),
            Felt::from(bit),
        ));
    }
    let tree = CommittedDataSet::new(entries).unwrap();
    let witness = tree.lookup_witness(Felt::ONE);
    assert_eq!(witness.siblings.len(), height);
    assert!(witness.verify());
    let budget = absence_os_resources(height);
    let charge = resources_gas(&budget);
    let (response, actual) = read_measured(witness.clone(), charge, false).unwrap();
    assert_eq!(response, [Felt::ZERO, Felt::ZERO, MISSING_KEY_FELT].map(MaybeRelocatable::from));
    // CallContract's ordinary allowance is deducted from the committed-data surcharge.
    let total_steps = budget.n_steps + 903;
    assert!(
        actual.n_steps + actual.n_memory_holes <= total_steps,
        "{actual:?}, bound {total_steps}"
    );
    for (builtin, used) in &actual.builtin_instance_counter {
        let allowance = if *builtin == BuiltinName::range_check { 18 } else { 0 };
        assert!(
            *used <= budget.builtin_instance_counter.get(builtin).copied().unwrap_or(0) + allowance,
            "{builtin:?}: {used}"
        );
    }
    eprintln!(
        "ABSENCE_GAS height={height} high_bits={high_bits} surcharge={charge} actual={actual:?}"
    );
    assert!(read_authenticated(witness.clone(), charge - 1, false).is_err());
    let mut wrong_value = witness.clone();
    wrong_value.value = Felt::ONE;
    assert!(read_authenticated(wrong_value, charge, false).is_err());
    if height > 0 {
        // This key is present on a different route; its absence must never authenticate.
        let mut wrong_route = witness;
        wrong_route.key = if high_bits { Felt::TWO.pow(251_u32) } else { Felt::TWO };
        assert!(!wrong_route.verify());
        assert!(read_authenticated(wrong_route, charge, false).is_err());
    }
}
