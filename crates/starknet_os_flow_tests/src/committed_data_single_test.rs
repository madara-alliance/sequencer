//! Exercise the Cairo entrypoint directly: Rust validation must not hide unconstrained hints.
use std::collections::HashMap;

use apollo_starknet_os_program::test_programs::COMMITTED_DATA_TEST_BYTES;
use blockifier::execution::syscalls::committed_data::{
    CommittedDataSet,
    CommittedDataWitness,
    batch_gas,
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
    _batch: bool,
) -> Result<
    (Vec<MaybeRelocatable>, cairo_vm::vm::runners::cairo_runner::ExecutionResources),
    Box<dyn std::error::Error>,
> {
    let entrypoint = "__main__.read_batch";
    let builtins = vec![BuiltinName::range_check, BuiltinName::bitwise, BuiltinName::poseidon];
    let (mut runner, program, _) = initialize_cairo_runner(
        &EntryPointRunnerConfig {
            layout: LayoutName::all_cairo,
            add_main_prefix_to_entrypoint: false,
            ..Default::default()
        },
        COMMITTED_DATA_TEST_BYTES,
        entrypoint,
        &builtins.iter().copied().map(ImplicitArg::Builtin).collect::<Vec<_>>(),
        HashMap::new(),
    )?;
    // Runner builtins use canonical order; the function takes poseidon before bitwise.
    let function_builtins =
        vec![BuiltinName::range_check, BuiltinName::poseidon, BuiltinName::bitwise];
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
    args.extend([
        CairoArg::Single(witness.root.into()),
        CairoArg::Array(vec![witness.key.into()]),
        CairoArg::Single(Felt::ONE.into()),
        CairoArg::Array(vec![witness.read_value().into()]),
        CairoArg::Single(Felt::from(gas).into()),
    ]);
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
fn standard_reads_require_valid_witnesses_and_sufficient_gas() {
    let tree = CommittedDataSet::new(vec![(Felt::TWO, Felt::from(100))]).unwrap();
    for key in [Felt::ZERO, Felt::TWO, Felt::TWO.pow(250_u32)] {
        let proof = tree.lookup_witness(key);
        let charge = batch_gas(1, 1, 0);
        let (result, resources) = read_measured(proof.clone(), charge, true).unwrap();
        assert_eq!(result, vec![Felt::ZERO.into(), Felt::ZERO.into()]);
        assert!(
            resources.n_steps
                <= blockifier::execution::syscalls::committed_data::read_os_resources(0).n_steps
        );
        assert!(read_authenticated(proof.clone(), charge - 1, true).is_err());
        let mut forged = proof;
        forged.value += Felt::ONE;
        assert!(read_authenticated(forged, u64::MAX, true).is_err());
    }
}
