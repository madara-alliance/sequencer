%builtins range_check bitwise poseidon

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin
from starkware.cairo.common.default_dict import default_dict_new
from starkware.starknet.core.os.execution.committed_data import (
    committed_data_constants_new,
    committed_data_dispatch,
    committed_data_finalize,
)

// Rust entrypoint tests provide witnesses through the production SNOS hint processor.
func read_batch{range_check_ptr, poseidon_ptr: PoseidonBuiltin*, bitwise_ptr: BitwiseBuiltin*}(
    root: felt, keys: felt*, count: felt, values: felt*, gas: felt
) -> (gas: felt, error: felt) {
    alloc_locals;
    let (local constants) = committed_data_constants_new(1);
    let (local start) = default_dict_new(0);
    let committed_data_cache = start;
    with committed_data_cache {
        let (local remaining, local error) = committed_data_dispatch(
            root, keys, count, values, gas, 1, constants
        );
    }
    committed_data_finalize(start, committed_data_cache);
    return (gas=remaining, error=error);
}
