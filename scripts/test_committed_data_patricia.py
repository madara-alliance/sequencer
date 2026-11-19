"""Direct Cairo checks of the production committed-data read/finalization functions.

Run: uv run --with cairo-lang==0.14.1a0 --python 3.10 python scripts/test_committed_data_patricia.py
For cross-language proofs, first run:
COMMITTED_DATA_PATRICIA_PROOFS=/tmp/patricia-proofs.json cargo test -p blockifier standard_patricia_matches_independent_cairo_vectors
Then add --rust-proofs /tmp/patricia-proofs.json to this script.

Only private-input hints are substituted. All verifier instructions and standard Patricia
hints run unchanged, including when deliberately incorrect values/preimages are supplied.
"""
import copy
from pathlib import Path
from starkware.cairo.lang.compiler.cairo_compile import compile_cairo_files
from starkware.cairo.lang.vm.cairo_runner import CairoRunner
from starkware.cairo.lang.instances import all_cairo_instance
from starkware.cairo.lang.vm.security import verify_secure_runner
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
    result['resources'] = runner.get_execution_resources()
    return result


def check(entries, keys):
    root, facts = tree(entries)
    fixture = dict(root=root, facts=facts, keys=keys, values=entries)
    result = run(fixture)
    assert result['values'] == [entries.get(key, 0) for key in keys]
    cold = len(set(keys))
    shared = (800+80*len(keys))*100 + (20+4*len(keys))*70
    charge = shared + cold*(252000*100+25200*70+502*491)
    assert result['first_gas'] == 2**64-1-charge
    assert result['second_gas'] == result['first_gas']-shared
    assert result['warm_rc'] <= 20+4*len(keys), (len(keys), result['warm_rc'])
    assert result['warm_steps'] <= 800+80*len(keys), (len(keys), result['warm_steps'])
    assert result['resources'].n_steps <= 2*(800+80*len(keys)) + 252000*cold
    return fixture


def rejects(fixture):
    try:
        run(fixture)
    except Exception:
        return
    raise AssertionError('Forged input was accepted')


def main():
    fixtures = [
        check({}, [0, 1, (1<<251)-1]),
        check({2:100}, [2, 0, 3, 1<<250, 2]),
        check({2:100, 3:125, 8:0, 10:200}, list(range(16))),
        check({0:1, (1<<251)-1:PROGRAM.prime-1}, [0, 1, (1<<251)-1]),
        check({1<<bit:bit+1 for bit in range(251)}, [0, 1, 1<<250]),
        check({i:i+1 for i in range(400)}, list(range(400))),
    ]
    bad = copy.deepcopy(fixtures[2]); bad['values'][2] += 1; rejects(bad)
    bad = copy.deepcopy(fixtures[2]); bad['values'][6] = 999; rejects(bad)
    bad = copy.deepcopy(fixtures[2]); bad['facts'][bad['root']+1] = bad['facts'][bad['root']]; bad['root'] += 1; rejects(bad)
    bad = copy.deepcopy(fixtures[2]); bad['facts'][bad['root']] = (1, 2); rejects(bad)
    bad = copy.deepcopy(fixtures[2]); bad['keys'] = [1<<251]; rejects(bad)
    bad = copy.deepcopy(fixtures[2]); bad['gas'] = 0; rejects(bad)
    print('PASS: 6 valid Cairo scenarios and 6 adversarial rejection scenarios')
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
