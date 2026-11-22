// Standard Starknet Poseidon Patricia reads. Hints supply values and node preimages;
// the OS independently authenticates each call before returning values and remaining gas.
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.dict import DictAccess, dict_read, dict_write
from starkware.cairo.common.default_dict import default_dict_new, default_dict_finalize
from starkware.cairo.common.cairo_builtins import PoseidonBuiltin, BitwiseBuiltin
from starkware.cairo.common.math import assert_nn, assert_lt_felt, assert_nn_le
from starkware.cairo.common.patricia_with_sponge import (
    patricia_update_constants_new,
    traverse_prev_tree,
)
from starkware.cairo.common.patricia_utils import PatriciaUpdateConstants
from starkware.cairo.common.sponge_as_hash import SpongeHashBuiltin
from starkware.starknet.core.os.output import OsCarriedOutputs
from starkware.starknet.core.os.builtins import BuiltinPointers, SelectableBuiltins
from starkware.starknet.common.new_syscalls import (
    CallContractRequest,
    CallContractResponse,
    ResponseHeader,
    FailureReason,
)

const COMMITTED_DATA_CONTRACT_ADDRESS = 0x6c5f4559c7041984537bc078c71443fdc58b2e1bab302b341ec12b3d2cec44;
const COMMITTED_DATA_TREE_HEIGHT = 251;
const MAX_COMMITTED_DATA_READ_KEYS = 1024;
const COMMITTED_DATA_GET_VALUE_SELECTOR = 1088514629534027837943348492744869453336870381453867699032131389309368223152;
const COMMITTED_DATA_GET_VALUES_SELECTOR = 915235083203333064963171029839308968026302113527340519125611694343636180392;

// Called once from OS global initialization. Disabled runs need no price-tree table.
func committed_data_constants_new(use_committed_data: felt) -> (
    constants: PatriciaUpdateConstants*
) {
    if (use_committed_data == 0) {
        return (constants=cast(0, PatriciaUpdateConstants*));
    }
    let (constants) = patricia_update_constants_new();
    return (constants=constants);
}

func committed_data_collect{
    range_check_ptr, leaf_cache: DictAccess*, cold_keys: felt*, cold_values: felt*
}(keys: felt*, count: felt, references: felt*) {
    alloc_locals;
    if (count == 0) {
        return ();
    }
    assert_lt_felt(keys[0], 2 ** 251);
    let (cached) = dict_read{dict_ptr=leaf_cache}(key=keys[0]);
    if (cached == 0) {
        assert cold_keys[0] = keys[0];
        assert references[0] = cast(cold_values, felt);
        dict_write{dict_ptr=leaf_cache}(key=keys[0], new_value=cast(cold_values, felt));
        let cold_keys = cold_keys + 1;
        let cold_values = cold_values + 1;
        return committed_data_collect(keys + 1, count - 1, references + 1);
    }
    assert references[0] = cached;
    return committed_data_collect(keys + 1, count - 1, references + 1);
}

// The squashed dictionary fixes the exact set of reads. Convert its value pointers
// into standard read-only Patricia accesses, including absent keys with value zero.
func committed_data_fill_reads(
    entries: DictAccess*, count: felt, reads: DictAccess*, absent_so_far: felt
) -> (absent: felt) {
    if (count == 0) {
        return (absent=absent_so_far);
    }
    let value = [cast(entries.new_value, felt*)];
    assert reads[0] = DictAccess(key=entries.key, prev_value=value, new_value=value);
    if (value == 0) {
        return committed_data_fill_reads(
            entries + DictAccess.SIZE, count - 1, reads + DictAccess.SIZE, absent_so_far + 1
        );
    }
    return committed_data_fill_reads(
        entries + DictAccess.SIZE, count - 1, reads + DictAccess.SIZE, absent_so_far
    );
}

// Count every authenticated sibling whose canonical felt exceeds the tree height.
func count_large_siblings{range_check_ptr}(siblings: felt*, size: felt, large: felt) -> (
    total: felt
) {
    if (size == 0) {
        return (total=large);
    }
    let small = is_le_felt([siblings], COMMITTED_DATA_TREE_HEIGHT);
    return count_large_siblings(siblings + 1, size - 1, large + 1 - small);
}

func committed_data_finalize{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, poseidon_ptr: PoseidonBuiltin*
}(start: DictAccess*, end: DictAccess*) {
    // Successful calls use private leaf dictionaries. The carried pointer is unchanged.
    assert start = end;
    return ();
}

// A single bounded request owns the entire chronological dictionary.
func committed_data_verify{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, poseidon_ptr: PoseidonBuiltin*
}(
    committed_data_root: felt,
    start: DictAccess*,
    end: DictAccess*,
    constants: PatriciaUpdateConstants*,
) -> (unique: felt, hashes: felt, absent: felt, large: felt) {
    alloc_locals;
    %{ StartCommittedDataFinalization %}
    let (entries, entries_end) = default_dict_finalize(start, end, 0);
    local committed_data_count = (entries_end - entries) / DictAccess.SIZE;
    let (local committed_data_keys: DictAccess*) = alloc();
    let (local absent) = committed_data_fill_reads(
        entries, committed_data_count, committed_data_keys, 0
    );
    %{ LoadCommittedDataRootUnion %}
    let (local siblings_start) = alloc();
    let siblings = siblings_start;
    local hash_start: SpongeHashBuiltin* = cast(poseidon_ptr, SpongeHashBuiltin*);
    let hash_ptr = hash_start;
    with hash_ptr, siblings {
        traverse_prev_tree(
            patricia_update_constants=constants,
            update_ptr=committed_data_keys,
            n_updates=committed_data_count,
            height=COMMITTED_DATA_TREE_HEIGHT,
            prev_root=committed_data_root,
            new_root=committed_data_root,
        );
    }
    local s = siblings - siblings_start;
    local h = (hash_ptr - hash_start) / SpongeHashBuiltin.SIZE;
    assert_nn_le(h, 2 * COMMITTED_DATA_TREE_HEIGHT * committed_data_count);
    assert_nn_le(s, h + 2 * absent);
    let (large) = count_large_siblings(siblings_start, s, 0);
    let poseidon_ptr = cast(hash_ptr, PoseidonBuiltin*);
    %{ EndCommittedDataFinalization %}
    return (unique=committed_data_count, hashes=h, absent=absent, large=large);
}

func binary_floor(unique: felt, absent: felt, large: felt) -> (floor: felt) {
    let total = unique - absent + large;
    if (total == 0) {
        return (floor=0);
    }
    return (floor=total - 1);
}

// Coefficients combine the compiled step, hole, range-check and Poseidon envelopes.
func committed_data_charge{range_check_ptr}(n: felt, u: felt, h: felt, a: felt, k: felt) -> (
    charge: felt
) {
    let (f) = binary_floor(u, a, k);
    assert_nn_le(a, u);
    assert_nn_le(f, h);
    let steps = 2415 + 86 * n + 231 * u + 249 * h + 287 * a - 167 * f;
    let holes = 345 + 18 * n + 31 * u + 31 * h + 50 * a - 19 * f;
    let checks = 9 + 5 * n + 16 * u + 20 * h + 28 * a - 16 * f;
    return (
        charge=steps * STEP_GAS_COST + holes * MEMORY_HOLE_GAS_COST + checks *
        RANGE_CHECK_GAS_COST + h * POSEIDON_GAS_COST,
    );
}

func committed_data_copy_values(references: felt*, values: felt*, count: felt) {
    if (count == 0) {
        return ();
    }
    assert values[0] = [cast(references[0], felt*)];
    return committed_data_copy_values(references + 1, values + 1, count - 1);
}

func committed_data_dispatch{
    range_check_ptr,
    poseidon_ptr: PoseidonBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    committed_data_cache: DictAccess*,
}(
    root: felt,
    keys: felt*,
    count: felt,
    values: felt*,
    gas: felt,
    batch: felt,
    constants: PatriciaUpdateConstants*,
) -> (gas: felt, error: felt) {
    alloc_locals;
    local committed_data_root = root;
    local committed_data_keys: felt* = keys;
    local committed_data_count = count;
    let (local cold_keys_start) = alloc();
    let (local cold_values_start) = alloc();
    let (local references) = alloc();
    let cold_keys = cold_keys_start;
    let cold_values = cold_values_start;
    let (local leaf_start) = default_dict_new(0);
    let leaf_cache = leaf_start;
    with cold_keys, cold_values, leaf_cache {
        committed_data_collect(keys, count, references);
    }
    local committed_data_cold_keys: felt* = cold_keys_start;
    local committed_data_cold_values: felt* = cold_values_start;
    local committed_data_cold_count = cold_keys - cold_keys_start;
    %{ LoadCommittedDataDeferred %}
    let (u, h, a, k) = committed_data_verify(root, leaf_start, leaf_cache, constants);
    let (local charge) = committed_data_charge(count, u, h, a, k);
    local range_check_ptr = range_check_ptr;
    local poseidon_ptr: PoseidonBuiltin* = poseidon_ptr;
    local bitwise_ptr: BitwiseBuiltin* = bitwise_ptr;
    local committed_data_cache: DictAccess* = committed_data_cache;
    committed_data_copy_values(references, values, count);
    let sufficient = is_le_felt(charge, gas);
    with_attr error_message("Insufficient gas for committed-data verification") {
        assert sufficient = 1;
    }
    assert_nn(gas - charge);
    return (gas=gas - charge, error=0);
}

func execute_committed_data_call{
    range_check_ptr, syscall_ptr: felt*, builtin_ptrs: BuiltinPointers*, outputs: OsCarriedOutputs*
}(
    request: CallContractRequest*,
    remaining_gas: felt,
    use_committed_data: felt,
    constants: PatriciaUpdateConstants*,
) {
    alloc_locals;
    assert request.contract_address = COMMITTED_DATA_CONTRACT_ADDRESS;
    assert use_committed_data = 1;
    local keys: felt*;
    local count;
    local batch;
    local read_range_check_ptr;
    if (request.selector == COMMITTED_DATA_GET_VALUE_SELECTOR) {
        if (request.calldata_end != request.calldata_start + 2) {
            committed_data_failure(remaining_gas, ERROR_INVALID_ARGUMENT);
            return ();
        }
        assert keys = request.calldata_start + 1;
        assert count = 1;
        assert batch = 0;
        assert read_range_check_ptr = range_check_ptr;
    } else {
        if (request.selector != COMMITTED_DATA_GET_VALUES_SELECTOR) {
            committed_data_failure(remaining_gas, ERROR_INVALID_ARGUMENT);
            return ();
        }
        let length = request.calldata_end - request.calldata_start;
        let length_min = is_le_felt(3, length);
        let length_max = is_le_felt(length, MAX_COMMITTED_DATA_READ_KEYS + 2);
        let length_valid = length_min * length_max;
        if (length_valid == 0) {
            committed_data_failure(remaining_gas, ERROR_INVALID_ARGUMENT);
            return ();
        }
        if (request.calldata_start[1] != length - 2) {
            committed_data_failure(remaining_gas, ERROR_INVALID_ARGUMENT);
            return ();
        }
        assert count = length - 2;
        assert keys = request.calldata_start + 2;
        assert batch = 1;
        assert read_range_check_ptr = range_check_ptr;
    }
    let range_check_ptr = read_range_check_ptr;
    let (local values) = alloc();
    let selectable_builtins = &builtin_ptrs.selectable;
    let poseidon_ptr = selectable_builtins.poseidon;
    let bitwise_ptr = selectable_builtins.bitwise;
    let committed_data_cache = outputs.committed_data_cache;
    with poseidon_ptr, bitwise_ptr, committed_data_cache {
        let (local gas, local error) = committed_data_dispatch(
            request.calldata_start[0], keys, count, values, remaining_gas, batch, constants
        );
    }
    tempvar outputs = new OsCarriedOutputs(
        messages_to_l1=outputs.messages_to_l1,
        messages_to_l2=outputs.messages_to_l2,
        committed_data_cache=committed_data_cache,
    );
    tempvar builtin_ptrs = new BuiltinPointers(
        selectable=SelectableBuiltins(
            pedersen=selectable_builtins.pedersen,
            range_check=selectable_builtins.range_check,
            ecdsa=selectable_builtins.ecdsa,
            bitwise=bitwise_ptr,
            ec_op=selectable_builtins.ec_op,
            poseidon=poseidon_ptr,
            segment_arena=selectable_builtins.segment_arena,
            range_check96=selectable_builtins.range_check96,
            add_mod=selectable_builtins.add_mod,
            mul_mod=selectable_builtins.mul_mod,
        ),
        non_selectable=builtin_ptrs.non_selectable,
    );
    if (error != 0) {
        committed_data_failure(gas, error);
        return ();
    }
    assert [cast(syscall_ptr, ResponseHeader*)] = ResponseHeader(gas=gas, failure_flag=0);
    let response = cast(syscall_ptr + ResponseHeader.SIZE, CallContractResponse*);
    assert response.retdata_end = response.retdata_start + count + batch;
    if (batch != 0) {
        assert response.retdata_start[0] = count;
    }
    memcpy(response.retdata_start + batch, values, count);
    let syscall_ptr = syscall_ptr + ResponseHeader.SIZE + CallContractResponse.SIZE;
    return ();
}

from starkware.cairo.common.math_cmp import is_le_felt, is_le
from starkware.starknet.core.os.constants import (
    ERROR_INVALID_ARGUMENT,
    STEP_GAS_COST,
    MEMORY_HOLE_GAS_COST,
    RANGE_CHECK_GAS_COST,
    POSEIDON_GAS_COST,
)

func committed_data_failure{syscall_ptr: felt*, range_check_ptr}(remaining_gas: felt, error: felt) {
    let after_charge = remaining_gas - (
        184 * STEP_GAS_COST + 43 * MEMORY_HOLE_GAS_COST + 9 * RANGE_CHECK_GAS_COST
    );
    assert_nn(after_charge);
    assert [cast(syscall_ptr, ResponseHeader*)] = ResponseHeader(gas=after_charge, failure_flag=1);
    let reason = cast(syscall_ptr + ResponseHeader.SIZE, FailureReason*);
    assert reason.end = reason.start + 1;
    assert reason.start[0] = error;
    let syscall_ptr = syscall_ptr + ResponseHeader.SIZE + FailureReason.SIZE;
    return ();
}
