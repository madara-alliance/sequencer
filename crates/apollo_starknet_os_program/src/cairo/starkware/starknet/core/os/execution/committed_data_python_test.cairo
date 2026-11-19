%builtins range_check bitwise poseidon

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin
from starkware.cairo.common.default_dict import default_dict_new
from starkware.starknet.core.os.execution.committed_data import (
    committed_data_dispatch,
    committed_data_finalize,
)

// Exercise the production collection and verification path, including repeated calls.
func main{range_check_ptr, bitwise_ptr: BitwiseBuiltin*, poseidon_ptr: PoseidonBuiltin*}() {
    alloc_locals;
    local root;
    local count;
    local keys: felt*;
    local gas;
    %{
        ids.root = fixture['root']
        ids.count = len(fixture['keys'])
        ids.keys = segments.gen_arg(fixture['keys'])
        ids.gas = fixture.get('gas', 2**64 - 1)
    %}
    let (local start) = default_dict_new(0);
    let committed_data_cache = start;
    let (local values) = alloc();
    with committed_data_cache {
        let (local first_gas, _) = committed_data_dispatch(root, keys, count, values, gas, 1);
        %{
            result['warm_start'] = step()
            result['warm_rc_start'] = ids.range_check_ptr
        %}
        let (local second_gas, _) = committed_data_dispatch(
            root, keys, count, values, first_gas, 1
        );
    }
    %{
        result['warm_steps'] = step() - result['warm_start']
        result['warm_rc'] = ids.range_check_ptr - result['warm_rc_start']
    %}
    committed_data_finalize(start, committed_data_cache);
    %{
        result['values'] = [memory[ids.values + i] for i in range(ids.count)]
        result['first_gas'] = ids.first_gas
        result['second_gas'] = ids.second_gas
    %}
    return ();
}
