// Expose the production union verifier to adversarial tests without Rust hint validation.
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import PoseidonBuiltin, BitwiseBuiltin
from starkware.cairo.common.registers import get_label_location
from starkware.starknet.core.os.execution.committed_data import (
    CommittedDataClaim,
    committed_data_union_node,
    committed_data_powers,
)

func verify_union{range_check_ptr, poseidon_ptr: PoseidonBuiltin*, bitwise_ptr: BitwiseBuiltin*}(
    root: felt, data: felt*, size: felt, leaves: felt*, leaf_count: felt, branch_count: felt
) {
    alloc_locals;
    let (slots) = alloc();
    tempvar claims = new CommittedDataClaim(count=branch_count, slots=slots);
    let proof = data;
    let branches_left = branch_count;
    let leaves_left = leaf_count;
    let (masks) = get_label_location(committed_data_powers);
    with proof, branches_left, leaves_left {
        let (hash, owner) = committed_data_union_node(
            masks, leaves, leaf_count, claims, 1, 252, 0, 0, 0, 0
        );
        // The same exhaustion checks used by committed_data_finalize_roots.
        assert hash = root;
        assert branches_left = 0;
        assert leaves_left = 0;
        assert proof = data + size;
    }
    return ();
}
