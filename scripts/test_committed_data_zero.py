"""Independently exercise zero-default Cairo dispatch, including malicious proof hints.

Run in the Cairo 0 environment. This uses the production verifier and shares only the
independent Python tree builder with the membership-union regression.
"""
from collections import defaultdict
import json

from test_committed_data_union import CAIRO_ROOT, tree, union
from starkware.cairo.lang.compiler.cairo_compile import compile_cairo
from starkware.cairo.lang.vm.cairo_runner import get_main_runner
from starkware.cairo.lang.vm.vm_exceptions import VmException

ENTRIES = {key: (key + 100 if key else 0) for key in range(0, 32, 2)}
ROOT = tree(list(ENTRIES.items()))
GAS = 2_000_000_000


def witness(key):
    node, siblings = ROOT, []
    while len(node) == 4:
        _, bit, left, right = node
        node, sibling = (right, left) if key & (1 << bit) else (left, right)
        siblings.append((bit, sibling[0]))
    return node[1], node[2], [item for pair in reversed(siblings) for item in pair]


def main():
    program = compile_cairo("""%builtins output range_check bitwise poseidon
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.default_dict import default_dict_new
from starkware.cairo.common.dict import DictAccess
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin
from starkware.starknet.core.os.execution.committed_data import committed_data_dispatch, committed_data_finalize
func main{output_ptr: felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*, poseidon_ptr: PoseidonBuiltin*}() {
    alloc_locals;
    let (local start: DictAccess*) = default_dict_new(0);
    let committed_data_cache = start;
    local keys: felt*;
    local count;
    local initial_gas;
    %{ ids.keys = segments.gen_arg(keys); ids.count = len(keys); ids.initial_gas = supplied_gas %}
    let (local values) = alloc();
    with committed_data_cache {
        let (local gas, error) = committed_data_dispatch(ROOT, keys, count, values, initial_gas, 1);
        assert error = 0;
    }
    committed_data_finalize(start, committed_data_cache);
    %{ check_values(ids, memory) %}
    assert [output_ptr] = gas;
    let output_ptr = output_ptr + 1;
    return ();
}
""".replace('ROOT', str(ROOT[0])), prime=2**251 + 17 * 2**192 + 1,
        cairo_path=[str(CAIRO_ROOT)], debug_info=True)
    replacements = {
        'LoadCommittedDataWitness': 'load_witness(ids, segments)',
        'LoadCommittedDataMissingIndex': 'missing_index(ids, memory)',
        'LoadCommittedDataDeferred': 'deferred(ids, memory)',
        'LoadCommittedDataRootUnion': 'finalize(ids, memory, segments)',
        'StartCommittedDataFinalization': 'pass',
        'EndCommittedDataFinalization': 'pass',
    }
    for hints in program.hints.values():
        for hint in hints:
            hint.code = replacements.get(hint.code.strip(), hint.code)
    cases = [
        ('stored_zero', [0]), ('absent', [1]), ('absent_first', [1, 2, 4]),
        ('absent_middle', [2, 1, 4]), ('absent_last', [2, 4, 1]),
        ('alternating', [1, 2, 3, 0, 1, 4]), ('all_absent', [1, 3, 5]),
        ('maximum_absent', [1] * 1024), ('maximum_alternating', [1, 2] * 512),
    ]
    reports = []
    for name, keys in cases:
        for attack in [None, 'underpayment', 'terminal_value', 'route', 'skip_absence', 'suffix']:
            if attack in ('terminal_value', 'route', 'skip_absence') and not any(k not in ENTRIES for k in keys):
                continue
            if attack == 'suffix' and name != 'absent_first':
                continue
            seen = set()
            supplied_gas = 0 if attack == 'underpayment' else GAS

            def missing_index(ids, memory):
                count = ids.committed_data_count
                requested = [memory[ids.committed_data_keys + i] for i in range(count)]
                ids.committed_data_missing_index = (count if attack == 'skip_absence' else
                    next((i for i, key in enumerate(requested) if key not in ENTRIES), count))

            def load_witness(ids, segments):
                key = ids.committed_data_key
                terminal, value, siblings = witness(key)
                if attack == 'terminal_value':
                    value += 1
                if attack == 'route':
                    terminal, value, siblings = witness(30 if key != 31 else 0)
                ids.committed_data_terminal_key = terminal
                ids.committed_data_value = value
                ids.committed_data_height = len(siblings) // 2
                ids.committed_data_siblings = segments.gen_arg(siblings)

            def deferred(ids, memory):
                count = ids.committed_data_cold_count
                requested = [memory[ids.committed_data_cold_keys + i] for i in range(count)]
                _, branches, _ = union(ROOT, dict(zip(requested, range(count))))
                ids.committed_data_branch_count = len(set(branches) - seen)
                seen.update(branches)
                for i, key in enumerate(requested):
                    memory[ids.committed_data_cold_values + i] = ENTRIES.get(key, 0) + (attack == 'suffix')

            def finalize(ids, memory, segments):
                count = ids.committed_data_leaf_count
                requested = [memory[ids.committed_data_leaves + 3 * i] for i in range(count)]
                owners = [memory[ids.committed_data_leaves + 3 * i + 2] for i in range(count)]
                proof, _, _ = union(ROOT, dict(zip(requested, range(count))), owners, defaultdict(int))
                ids.committed_data_proof = segments.gen_arg(proof)
                ids.committed_data_proof_end = ids.committed_data_proof + len(proof)

            def check_values(ids, memory):
                assert [memory[ids.values + i] for i in range(len(keys))] == [ENTRIES.get(k, 0) for k in keys]

            try:
                runner = get_main_runner(program, hint_locals={
                    'keys': keys, 'supplied_gas': supplied_gas, 'missing_index': missing_index,
                    'load_witness': load_witness, 'deferred': deferred, 'finalize': finalize,
                    'check_values': check_values,
                }, layout='recursive_with_poseidon')
            except VmException:
                assert attack is not None, name
                reports.append({'case': name, 'attack': attack, 'rejected': True})
            else:
                assert attack is None, (name, attack)
                remaining = runner.vm_memory[runner.builtin_runners['output_builtin'].base]
                resources = runner.get_execution_resources()
                rates = {'range_check_builtin': 70, 'bitwise_builtin': 583, 'poseidon_builtin': 491, 'output_builtin': 0}
                actual = (resources.n_steps + resources.n_memory_holes) * 100 + sum(
                    rates[builtin] * count for builtin, count in resources.builtin_instance_counter.items())
                charged = GAS - remaining
                assert actual <= charged + 903 * 100 + 18 * 70, (name, actual, charged)
                reports.append({'case': name, 'surcharge': charged, 'wrapper_resource_equivalent': actual})
    print(json.dumps(reports, indent=2))


if __name__ == '__main__':
    main()
