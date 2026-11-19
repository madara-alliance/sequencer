//! Run the Cairo verifier directly so malformed hints cannot be rejected only by the Rust builder.
use std::collections::HashMap;

use apollo_starknet_os_program::test_programs::COMMITTED_DATA_TEST_BYTES;
use blockifier::execution::syscalls::committed_data::{
    batch_os_resources,
    branch,
    leaf,
    CommittedDataBatchProof,
    CommittedDataSet,
    CommittedDataSibling,
    CommittedDataWitness,
};
use blockifier::execution::syscalls::vm_syscall_utils::SyscallSelector;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::get_const_syscall_resources;
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::runners::cairo_runner::{CairoArg, ExecutionResources};
use starknet_os::hint_processor::snos_hint_processor::SnosHintProcessor;
use starknet_os::test_utils::cairo_runner::{
    initialize_cairo_runner,
    EntryPointRunnerConfig,
    ImplicitArg,
    EMPTY_BLOCK_INPUT,
};
use starknet_types_core::felt::Felt;

fn verify(
    root: Felt,
    proof: &CommittedDataBatchProof,
) -> Result<ExecutionResources, Box<dyn std::error::Error>> {
    let entrypoint = "__main__.verify_union";
    let (mut runner, program, _) = initialize_cairo_runner(
        &EntryPointRunnerConfig {
            layout: LayoutName::all_cairo,
            add_main_prefix_to_entrypoint: false,
            ..Default::default()
        },
        COMMITTED_DATA_TEST_BYTES,
        entrypoint,
        &[
            ImplicitArg::Builtin(BuiltinName::range_check),
            ImplicitArg::Builtin(BuiltinName::bitwise),
            ImplicitArg::Builtin(BuiltinName::poseidon),
        ],
        HashMap::new(),
    )?;
    // The program's builtin order is canonical; the function takes poseidon before bitwise.
    let mut args: Vec<_> = [BuiltinName::range_check, BuiltinName::poseidon, BuiltinName::bitwise]
        .into_iter()
        .map(|name| {
            CairoArg::Single(
                runner
                    .vm
                    .get_builtin_runners()
                    .iter()
                    .find(|b| b.name() == name)
                    .unwrap()
                    .initial_stack()[0]
                    .clone(),
            )
        })
        .collect();
    let array = |values: Vec<Felt>| CairoArg::Array(values.into_iter().map(Into::into).collect());
    // The live union format adds a charge slot to each expanded branch and an owner to
    // each leaf. One call owns every branch here; shared-call ownership is exercised by
    // the independent dispatch/finalization tests in test_committed_data_union.py.
    let mut data = Vec::new();
    let mut cursor = 0;
    let mut slot = 0;
    while cursor < proof.proof.len() {
        let tag = proof.proof[cursor];
        data.extend_from_slice(&proof.proof[cursor..cursor + 2]);
        cursor += 2;
        if tag == Felt::TWO {
            data.push(Felt::from(slot));
            slot += 1;
        }
    }
    let size = data.len();
    let leaves = proof.leaves.chunks_exact(2).flat_map(|leaf| [leaf[0], leaf[1], Felt::ZERO]);
    args.extend([
        CairoArg::Single(root.into()),
        array(data),
        CairoArg::Single(Felt::from(size).into()),
        array(leaves.collect()),
        CairoArg::Single(Felt::from(proof.unique_leaves()).into()),
        CairoArg::Single(Felt::from(proof.branches).into()),
    ]);
    let mut hints = SnosHintProcessor::<DictStateReader>::new_for_testing(
        None,
        &program,
        None,
        &EMPTY_BLOCK_INPUT,
    )?;
    runner.run_from_entrypoint(
        program.get_identifier(entrypoint).unwrap().pc.unwrap(),
        &args.iter().collect::<Vec<_>>(),
        true,
        None,
        &mut hints,
    )?;
    Ok(runner.get_execution_resources()?)
}

/// Narrow paths exercise both opaque-child positions and cannot hide costs in a larger batch.
#[rstest::rstest]
fn union_verifier_accepts_repeated_hashes_as_opaque_siblings(
    #[values(0, 1, 2, 19, 64, 128, 252)] height: u8,
    #[values(Felt::ZERO, Felt::MAX)] key: Felt,
) {
    let mut root = leaf(key, Felt::ONE);
    let mut siblings = Vec::new();
    for bit in 0..height {
        siblings.push(CommittedDataSibling { bit, hash: root });
        root = branch(bit, root, root);
    }
    let witness =
        CommittedDataWitness { root, key, value: Felt::ONE, siblings, terminal_key: None };
    let keys = [key];
    let proof = CommittedDataBatchProof::new(root, &keys, |_| Ok(Some(witness.clone()))).unwrap();
    assert_eq!(proof.branches, usize::from(height));
    let actual = verify(root, &proof).unwrap();
    // Restore the ordinary CallContract allowance credited by the surcharge schedule.
    let bound = &get_const_syscall_resources(SyscallSelector::CallContract)
        + &batch_os_resources(1, 1, usize::from(height));
    let constants =
        blockifier::blockifier_versioned_constants::VersionedConstants::create_for_testing();
    let gas = &constants.os_constants.gas_costs;
    let proving = blockifier::bouncer::BuiltinWeights::default().gas_costs;
    for costs in [&gas.builtins, &proving] {
        let actual_gas =
            blockifier::utils::get_gas_cost_from_vm_resources(&actual, &gas.base, costs);
        let bound_gas = blockifier::utils::get_gas_cost_from_vm_resources(&bound, &gas.base, costs);
        assert!(actual_gas <= bound_gas, "actual={actual:?}, bound={bound:?}");
    }
}

#[test]
fn union_verifier_authenticates_keys_values_and_exact_work_counts() {
    let tree = CommittedDataSet::new(vec![
        (Felt::ZERO, Felt::MAX),
        (Felt::ONE, Felt::ZERO),
        (Felt::MAX, Felt::TWO),
    ])
    .unwrap();
    let keys = [Felt::MAX, Felt::ZERO, Felt::MAX, Felt::ONE];
    let fresh = || CommittedDataBatchProof::from_dataset(&tree, &keys).unwrap();
    verify(tree.root(), &fresh()).unwrap();
    let mut proof = fresh();
    proof.leaves[1] += Felt::ONE;
    assert!(verify(tree.root(), &proof).is_err());
    let mut proof = fresh();
    proof.leaves.swap(0, 2);
    assert!(verify(tree.root(), &proof).is_err());
    for delta in [-1_i32, 1] {
        let mut proof = fresh();
        proof.branches = (proof.branches as i32 + delta) as usize;
        assert!(verify(tree.root(), &proof).is_err());
    }
    let mut proof = fresh();
    proof.leaves.extend([Felt::TWO, Felt::ONE]);
    assert!(verify(tree.root(), &proof).is_err());
}

#[test]
fn union_verifier_rejects_wrong_routing_even_when_the_hash_matches() {
    // The claimed root really hashes these leaves, but its left leaf has bit zero set.
    // Root equality alone would incorrectly accept this malformed trie.
    let left = leaf(Felt::ONE, Felt::from(10));
    let right = leaf(Felt::ZERO, Felt::from(20));
    let root = branch(0, left, right);
    let proof = CommittedDataBatchProof {
        branch_hashes: Vec::new(),
        proof: vec![Felt::TWO, Felt::ZERO, Felt::ONE, Felt::ZERO, Felt::ZERO, right],
        leaves: vec![Felt::ONE, Felt::from(10)],
        indices: vec![0],
        branches: 1,
    };
    assert!(verify(root, &proof).is_err());
}

#[test]
fn union_verifier_cannot_inflate_work_by_expanding_an_unrequested_subtree() {
    let entries: Vec<_> = (0..4).map(|i| (Felt::from(i), Felt::from(i + 10))).collect();
    let tree = CommittedDataSet::new(entries.clone()).unwrap();
    let keys = [Felt::ZERO];
    verify(tree.root(), &CommittedDataBatchProof::from_dataset(&tree, &keys).unwrap()).unwrap();
    // All hashes and keys are correct. Only the right subtree was unnecessarily expanded.
    let proof = CommittedDataBatchProof {
        branch_hashes: Vec::new(),
        proof: vec![
            Felt::TWO,
            Felt::ONE,
            Felt::TWO,
            Felt::ZERO,
            Felt::ONE,
            Felt::ZERO,
            Felt::ZERO,
            leaf(entries[1].0, entries[1].1),
            Felt::TWO,
            Felt::ZERO,
            Felt::ZERO,
            leaf(entries[2].0, entries[2].1),
            Felt::ZERO,
            leaf(entries[3].0, entries[3].1),
        ],
        leaves: vec![entries[0].0, entries[0].1],
        indices: vec![0],
        branches: 3,
    };
    assert!(verify(tree.root(), &proof).is_err());
}
