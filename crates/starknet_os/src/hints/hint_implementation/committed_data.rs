use blockifier::state::state_api::StateReader;
use cairo_vm::hint_processor::hint_processor_utils::felt_to_usize;

use crate::hint_processor::snos_hint_processor::SnosHintProcessor;
use crate::hints::error::{OsHintError, OsHintResult};
use crate::hints::types::HintContext;
use crate::hints::vars::Ids;

pub(crate) fn load_use_committed_data<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    mut ctx: HintContext<'_>,
) -> OsHintResult {
    ctx.insert_value(Ids::UseCommittedData, usize::from(hp.os_hints_config.use_committed_data))?;
    Ok(())
}

// Returned values are constrained by the squashed read set at block finalization.
pub(crate) fn load_committed_data_deferred<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    ctx: HintContext<'_>,
) -> OsHintResult {
    let root = ctx.get_integer(Ids::CommittedDataRoot)?;
    let request_count = felt_to_usize(&ctx.get_integer(Ids::CommittedDataCount)?)?;
    let request_keys = ctx.get_ptr(Ids::CommittedDataKeys)?;
    let request = (0..request_count)
        .map(|i| Ok(*ctx.vm.get_integer((request_keys + i)?)?))
        .collect::<Result<Vec<_>, OsHintError>>()?;
    hp.get_mut_current_execution_helper()?.os_logger.mark_committed_request(root, request);
    let count = felt_to_usize(&ctx.get_integer(Ids::CommittedDataColdCount)?)?;
    let keys = ctx.get_ptr(Ids::CommittedDataColdKeys)?;
    let values = ctx.get_ptr(Ids::CommittedDataColdValues)?;
    for i in 0..count {
        let key = *ctx.vm.get_integer((keys + i)?)?;
        let proof = hp.committed_data_witness(root, key).ok_or_else(|| {
            OsHintError::AssertionFailed { message: "CommittedData witness unavailable".into() }
        })?;
        ctx.vm.insert_value((values + i)?, proof.read_value())?;
    }
    Ok(())
}

// The existing Patricia hints consume CommitmentInfo. No new tree traversal hints.
pub(crate) fn load_committed_data_root_union<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    ctx: HintContext<'_>,
) -> OsHintResult {
    use blockifier::execution::syscalls::committed_data::CommittedDataBatchProof;
    use starknet_api::hash::HashOutput;
    use starknet_patricia::patricia_merkle_tree::types::SubTreeHeight;

    use crate::commitment_infos::CommitmentInfo;
    use crate::hints::hint_implementation::state::CommitmentType;
    let root = ctx.get_integer(Ids::CommittedDataRoot)?;
    let count = felt_to_usize(&ctx.get_integer(Ids::CommittedDataCount)?)?;
    let reads = ctx.get_ptr(Ids::CommittedDataKeys)?;
    let keys = (0..count)
        .map(|i| Ok(*ctx.vm.get_integer((reads + 3 * i)?)?))
        .collect::<Result<Vec<_>, OsHintError>>()?;
    let proof = CommittedDataBatchProof::new_for_read_set(root, &keys, |key| {
        Ok(hp.committed_data_witness(root, key).cloned())
    })
    .map_err(|e| OsHintError::AssertionFailed { message: e.to_string() })?;
    hp.committed_data_commitment = Some(CommitmentInfo {
        previous_root: HashOutput(root),
        updated_root: HashOutput(root),
        tree_height: SubTreeHeight::ACTUAL_HEIGHT,
        commitment_facts: proof
            .facts
            .into_iter()
            .map(|(hash, preimage)| (HashOutput(hash), preimage))
            .collect(),
    });
    hp.commitment_type = CommitmentType::CommittedData;
    Ok(())
}

pub(crate) fn start_committed_data_finalization<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    ctx: HintContext<'_>,
) -> OsHintResult {
    hp.committed_finalization_start = Some((
        ctx.vm.get_current_step(),
        ctx.get_ptr(Ids::RangeCheckPtr)?,
        ctx.get_ptr(Ids::CommittedDataBitwisePtr)?,
        ctx.get_ptr(Ids::CommittedPoseidonPtr)?,
    ));
    Ok(())
}
pub(crate) fn end_committed_data_finalization<S: StateReader>(
    hp: &mut SnosHintProcessor<'_, S>,
    ctx: HintContext<'_>,
) -> OsHintResult {
    use cairo_vm::types::builtin_name::BuiltinName;
    hp.commitment_type = crate::hints::hint_implementation::state::CommitmentType::State;
    hp.committed_data_commitment = None;
    let (steps, rc, bitwise, poseidon) = hp.committed_finalization_start.take().unwrap();
    hp.committed_finalizations.push(cairo_vm::vm::runners::cairo_runner::ExecutionResources {
        n_steps: ctx.vm.get_current_step() - steps,
        n_memory_holes: 0,
        builtin_instance_counter: std::collections::BTreeMap::from([
            (BuiltinName::range_check, (ctx.get_ptr(Ids::RangeCheckPtr)? - rc)?),
            (BuiltinName::bitwise, (ctx.get_ptr(Ids::CommittedDataBitwisePtr)? - bitwise)? / 5),
            (BuiltinName::poseidon, (ctx.get_ptr(Ids::CommittedPoseidonPtr)? - poseidon)? / 6),
        ]),
    });
    Ok(())
}
