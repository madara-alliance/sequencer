"""Direct Cairo checks of the production committed-data read/finalization functions.

Run: uv run --with cairo-lang==0.14.1a0 --python 3.10 python scripts/test_committed_data_patricia.py
For cross-language proofs, first run:
COMMITTED_DATA_PATRICIA_PROOFS=/tmp/patricia-proofs.json cargo test -p blockifier standard_patricia_matches_independent_cairo_vectors
Then add --rust-proofs /tmp/patricia-proofs.json to this script.

Only private-input hints are substituted. All verifier instructions and standard Patricia
hints run unchanged, including when deliberately incorrect values/preimages are supplied.
"""
from pathlib import Path
from typing import NamedTuple
from starkware.cairo.lang.compiler.cairo_compile import compile_cairo_files
from starkware.cairo.lang.vm.cairo_runner import CairoRunner
from starkware.cairo.lang.instances import all_cairo_instance
from starkware.cairo.lang.vm.security import verify_secure_runner
from starkware.cairo.lang.vm.vm_exceptions import InconsistentAutoDeductionError, VmException
from starkware.cairo.common.poseidon_hash import poseidon_hash

ROOT = Path(__file__).resolve().parents[1]
CAIRO = ROOT / 'crates/apollo_starknet_os_program/src/cairo'
PROGRAM = compile_cairo_files([str(CAIRO / 'starkware/starknet/core/os/execution/committed_data_python_test.cairo')], cairo_path=[str(CAIRO)], prime=2**251+17*2**192+1, debug_info=True)
ADAPTERS = {
    'LoadCommittedDataDeferred': '''
for i in range(ids.committed_data_cold_count):
    key = memory[ids.committed_data_cold_keys + i]
    memory[ids.committed_data_cold_values + i] = fixture['values'].get(key, 0)
''',
    'LoadCommittedDataRootUnion': "preimage = fixture['facts']",
    'StartCommittedDataFinalization': 'pass',
    'EndCommittedDataFinalization': 'pass',
}
for hints in PROGRAM.hints.values():
    for hint in hints:
        if hint.code.strip() in ADAPTERS:
            hint.code = ADAPTERS[hint.code.strip()]


def tree(entries, height=251):
    """Independent standard Patricia reference. Zero leaves are omitted."""
    entries = sorted((k, v) for k, v in entries.items() if v)
    facts = {}
    def build(items, height):
        if not items:
            return 0
        if height == 0:
            return items[0][1]
        split = next((i for i, (k, _) in enumerate(items) if (k >> (height - 1)) & 1), len(items))
        if split in (0, len(items)):
            length = 0
            while length < height and (items[0][0] >> (height-length-1)) == (items[-1][0] >> (height-length-1)):
                length += 1
            path = (items[0][0] >> (height-length)) & ((1 << length)-1)
            bottom = build(items, height-length)
            hash_ = (poseidon_hash(bottom, path) + length) % PROGRAM.prime
            facts[hash_] = (length, path, bottom)
        else:
            left, right = build(items[:split], height-1), build(items[split:], height-1)
            hash_ = poseidon_hash(left, right)
            facts[hash_] = (left, right)
        return hash_
    return build(entries, height), facts


def run(fixture):
    runner = CairoRunner(PROGRAM, layout=all_cairo_instance)
    runner.initialize_segments()
    end = runner.initialize_main_entrypoint()
    result = {}
    runner.initialize_vm(hint_locals={'fixture': fixture, 'result': result, 'step': lambda: runner.vm.current_step})
    runner.run_until_pc(end)
    runner.end_run()
    runner.read_return_values()
    runner.vm.verify_auto_deductions()
    verify_secure_runner(runner)
    runner.get_cairo_pie().run_validity_checks()
    result['resources'] = runner.get_execution_resources()
    return result


def exact_class(root, keys, facts, height=251):
    """Count opening occurrences, all large emissions and zero values, independent of VM output."""
    if not keys:
        return 0,0,0
    if root == 0:
        return 0,0,len(keys)
    if height == 0:
        assert len(keys)==1
        return 0,0,0
    node=facts[root]
    if len(node)==2:
        left,right=node
        assert poseidon_hash(left,right)==root
        lkeys={key for key in keys if not key & (1<<(height-1))}
        rkeys=keys-lkeys
        lh,lk,la=exact_class(left,lkeys,facts,height-1)
        rh,rk,ra=exact_class(right,rkeys,facts,height-1)
        return 1+lh+rh, lk+rk+int(not lkeys and left>251)+int(not rkeys and right>251), la+ra
    length,path,bottom=node
    assert 1<=length<=height and path<(1<<length)
    assert (poseidon_hash(bottom,path)+length)%PROGRAM.prime==root
    diffs={q:((q>>(height-length))% (1<<length)) ^ path for q in keys}
    matches={q for q,diff in diffs.items() if diff==0}
    if matches:
        h,k,a=exact_class(bottom,matches,facts,height-length)
        return 1+h,k,a+len(keys)-len(matches)
    # The last query to diverge sees the whole residual committed-side child.
    # Earlier divergences query both sides of their fork and emit no sibling there.
    remaining=min(diff.bit_length()-1 for diff in diffs.values())
    low=path % (1<<remaining)
    sibling=(poseidon_hash(bottom,low)+remaining)%PROGRAM.prime if remaining else bottom
    return 1+int(remaining>0),int(sibling>251),len(keys)

class Quote(NamedTuple):
    gas: int
    steps: int
    holes: int
    checks: int
    hashes: int


def quote(root, keys, facts, entries):
    n, u = len(keys), len(set(keys))
    h, k, a = exact_class(root, set(keys), facts)
    assert a == sum(entries.get(key, 0) == 0 for key in set(keys))
    f = max(k+u-a-1, 0)
    assert 0 <= f <= h
    steps = 2415 + 86*n + 231*u + 249*h + 287*a - 167*f
    holes = 345 + 18*n + 31*u + 31*h + 50*a - 19*f
    rc = 9 + 5*n + 16*u + 20*h + 28*a - 16*f
    charge = 100*steps + 10*holes + 70*rc + 491*h
    return Quote(charge, steps, holes, rc, h)


def check(entries, keys, second_keys=None):
    root, facts = tree(entries)
    second_keys = keys if second_keys is None else second_keys
    fixture = dict(root=root, facts=facts, keys=keys, second_keys=second_keys, values=entries)
    result = run(fixture)
    assert result['values'] == [entries.get(key, 0) for key in keys]
    assert result['second_values'] == [entries.get(key, 0) for key in second_keys]
    first = quote(root, keys, facts, entries)
    second = quote(root, second_keys, facts, entries)
    assert 2**64-1-result['first_gas'] == first.gas
    assert result['first_gas']-result['second_gas'] == second.gas
    assert result['warm_steps'] <= second.steps and result['warm_rc'] <= second.checks
    resources = result['resources']
    assert resources.n_steps <= first.steps + second.steps
    assert resources.n_memory_holes <= first.holes + second.holes
    assert resources.builtin_instance_counter['range_check_builtin'] <= first.checks + second.checks
    assert resources.builtin_instance_counter['poseidon_builtin'] == first.hashes + second.hashes
    return fixture


def rejects(fixture):
    try:
        run(fixture)
    except (VmException, InconsistentAutoDeductionError):
        return
    raise AssertionError('Forged input was accepted')


def check_union():
    # Each call authenticates and pays for its own union, even with a partial or full overlap.
    entries = {key: key+100 for key in range(16)}
    fixture = check(entries, [0, 1, 0], [0, 8])
    check(entries, [0, 1, 0])
    check({0:1, (1<<251)-1:PROGRAM.prime-1}, [0, 1, (1<<251)-1])
    check({1<<bit:bit+1 for bit in range(251)}, [0, 1, 1<<250])
    check({i:i+1 for i in range(400)}, list(range(400)))
    root, facts = fixture['root'], fixture['facts']
    rejects({**fixture, 'values': {**entries, 0: entries[0] + 1}})
    rejects({**fixture, 'root': root + 1, 'facts': {**facts, root + 1: facts[root]}})
    rejects({**fixture, 'facts': {**facts, root: (1, 2)}})
    rejects({**fixture, 'keys': [1 << 251]})
    required = sum(quote(root, fixture[name], facts, entries).gas
                   for name in ('keys', 'second_keys'))
    assert run({**fixture, 'gas': required})['second_gas'] == 0
    rejects({**fixture, 'gas': required - 1})
    print('PASS: Patricia union values, per-call charges, resource vectors and invalid proofs')


def check_zero():
    # Standard Patricia commits an explicit zero and an absent key to the same empty leaf.
    check({}, [0, 1, (1<<251)-1])
    check({2:100}, [2, 0, 3, 1<<250, 2])
    entries = {0:0, 2:100, 4:200}
    assert tree(entries) == tree({2:100, 4:200})
    for keys in ([0], [1], [1,2,4], [2,1,4], [2,4,1], [1,2,3,0,1,4],
                 [1,3,5], [1]*1024, [1,2]*512):
        check(entries, keys)
    absent = check({2: 100}, [3])
    root, facts = absent['root'], absent['facts']
    length, path, bottom = facts[root]
    rejects({**absent, 'facts': {**facts, root: (length, path ^ 1, bottom)}})
    charge = quote(root, absent['keys'], facts, absent['values']).gas
    rejects({**absent, 'gas': charge - 1})
    fixture = check({2:100, 3:125, 8:0, 10:200}, list(range(16)))
    rejects({**fixture, 'values': {**fixture['values'], 6: 999}})
    print('PASS: zero and missing reads, mixed ordering, duplicates and maximum-size requests')


def main():
    check_union()
    check_zero()
    print('Singleton reference root:', hex(tree({0:PROGRAM.prime-1})[0]))
    import argparse, json
    parser = argparse.ArgumentParser()
    parser.add_argument('--rust-proofs', type=Path)
    args = parser.parse_args()
    if args.rust_proofs:
        for vector in json.loads(args.rust_proofs.read_text()):
            fixture = dict(root=int(vector['root']), keys=list(map(int, vector['keys'])),
                values={int(k):int(v) for k,v in vector['entries']},
                facts={int(k):tuple(map(int,v)) for k,v in vector['facts']})
            assert run(fixture)['values'] == [fixture['values'].get(k,0) for k in fixture['keys']]
        print('PASS: Rust-generated proof unions verified by production Cairo')

if __name__ == '__main__':
    main()
