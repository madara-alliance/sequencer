//! Exercise the Cairo entrypoint directly: Rust validation must not hide unconstrained hints.
use std::collections::HashMap;

use apollo_starknet_os_program::OS_PROGRAM_BYTES;
use blockifier::execution::syscalls::committed_data::{
    absence_os_resources,
    read_gas,
    resources_gas,
    CommittedDataSet,
    CommittedDataSibling,
    CommittedDataWitness,
};
use blockifier::test_utils::dict_state_reader::DictStateReader;
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::cairo_runner::CairoArg;
use starknet_os::hint_processor::snos_hint_processor::SnosHintProcessor;
use starknet_os::io::os_input::OsHintsConfig;
use starknet_os::test_utils::cairo_runner::{
    initialize_cairo_runner,
    EntryPointRunnerConfig,
    ImplicitArg,
    EMPTY_BLOCK_INPUT,
};
use starknet_types_core::felt::Felt;

fn read_authenticated(
    witness: CommittedDataWitness,
    gas: u64,
) -> Result<Vec<MaybeRelocatable>, Box<dyn std::error::Error>> {
    read_measured(witness, gas).map(|(values, _)| values)
}

fn read_measured(
    witness: CommittedDataWitness,
    gas: u64,
) -> Result<
    (Vec<MaybeRelocatable>, cairo_vm::vm::runners::cairo_runner::ExecutionResources),
    Box<dyn std::error::Error>,
> {
    let entrypoint = "starkware.starknet.core.os.execution.committed_data.committed_data_read_one";
    let builtins = [BuiltinName::range_check, BuiltinName::poseidon];
    let (mut runner, program, _) = initialize_cairo_runner(
        &EntryPointRunnerConfig {
            layout: LayoutName::all_cairo,
            add_main_prefix_to_entrypoint: false,
            ..Default::default()
        },
        OS_PROGRAM_BYTES,
        entrypoint,
        &builtins.iter().copied().map(ImplicitArg::Builtin).collect::<Vec<_>>(),
        HashMap::new(),
    )?;
    let mut args: Vec<_> = builtins
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
    args.extend(
        [witness.root, witness.key, Felt::from(gas)].map(|value| CairoArg::Single(value.into())),
    );
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
    Ok((runner.vm.get_return_values(2)?, runner.get_execution_resources()?))
}

#[test]
fn single_read_requires_authenticated_height_and_sufficient_gas() {
    let tree = CommittedDataSet::new(vec![(Felt::ZERO, Felt::ONE)]).unwrap();
    let witness = tree.witness(Felt::ZERO).unwrap();
    let gas = 100_000;
    assert_eq!(
        read_authenticated(witness.clone(), gas).unwrap(),
        [Felt::ONE, Felt::from(gas - read_gas(0))].map(MaybeRelocatable::from)
    );
    assert!(read_authenticated(witness.clone(), 0).is_err());
    assert!(read_authenticated(witness.clone(), read_gas(0) - 1).is_err());
    assert_eq!(
        read_authenticated(witness.clone(), read_gas(0)).unwrap(),
        [Felt::ONE, Felt::ZERO].map(MaybeRelocatable::from)
    );
    let forged = CommittedDataWitness {
        siblings: (0..252_u8).map(|bit| CommittedDataSibling { bit, hash: Felt::ZERO }).collect(),
        ..witness
    };
    assert!(!forged.verify());
    assert!(read_authenticated(forged, gas).is_err());
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
    let (response, actual) = read_measured(witness.clone(), charge).unwrap();
    assert_eq!(response, [Felt::ZERO, Felt::ZERO].map(MaybeRelocatable::from));
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
    assert!(read_authenticated(witness.clone(), charge - 1).is_err());
    let mut wrong_value = witness.clone();
    wrong_value.value = Felt::ONE;
    assert!(read_authenticated(wrong_value, charge).is_err());
    if height > 0 {
        // This key is present on a different route; its absence must never authenticate.
        let mut wrong_route = witness;
        wrong_route.key = if high_bits { Felt::TWO.pow(251_u32) } else { Felt::TWO };
        assert!(!wrong_route.verify());
        assert!(read_authenticated(wrong_route, charge).is_err());
    }
}
