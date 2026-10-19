import argparse
from collections import defaultdict
from pathlib import Path
import subprocess
import tempfile

from TestSupport import Collector, open_trace


def reports(directory):
    return {int(path.stem): path.read_text().splitlines() for path in directory.glob('*.txt')}


def check(collector_path, fixtures, instructions, sibling):
    with tempfile.TemporaryDirectory(prefix='Detourist-HookLoading-') as temporary:
        root = Path(temporary)
        baselines = {}
        all_fixtures = list(fixtures)
        if sibling:
            all_fixtures += [sibling / fixture.name for fixture in fixtures]
        for index, fixture in enumerate(all_fixtures):
            directory = root / f'baseline-{index}'
            directory.mkdir()
            subprocess.run([str(fixture), str(directory)], check=True, timeout=30,
                           creationflags=subprocess.CREATE_NO_WINDOW)
            baseline = reports(directory)
            assert len(baseline) == 1, baseline
            baselines[fixture] = next(iter(baseline.values()))

        # Every import mode runs at the root and in a descendant; both architecture directions can be staged.
        chains = [fixtures, fixtures[1:] + fixtures[:1], fixtures[2:] + fixtures[:2]]
        if sibling:
            chains += [[fixtures[0], sibling / fixtures[1].name, fixtures[2]],
                       [fixtures[2], sibling / fixtures[0].name, fixtures[1]]]
        with Collector(collector_path) as collector:
            for index, chain in enumerate(chains):
                directory = root / f'capture-{index}'
                directory.mkdir()
                database = root / f'capture-{index}.db'
                status = collector.capture(database=str(database), executable=str(chain[0]),
                    arguments=subprocess.list2cmdline([str(directory), *(str(path) for path in chain[1:])]),
                    followChildren=True, instructionEngine=instructions, timeout=90)
                assert status['processes'] == 3 and not status['partial'] and not status['skippedChildren'], status
                assert 'nonzero' not in status['message'], status
                captured = reports(directory)
                with open_trace(database) as connection:
                    targets = connection.execute('SELECT id,pid,image,state FROM targets ORDER BY id').fetchall()
                    assert len(targets) == 3 and len(captured) == 3, (targets, captured, status)
                    for target, pid, image, state in targets:
                        fixture = Path(image)
                        assert state == 'Exited' and captured[pid] == baselines[fixture], (fixture, state, captured)
                        calls = connection.execute('SELECT c.result,c.error FROM calls c JOIN apis a '
                            'ON a.target IN (0,c.target) AND a.id=c.api '
                            'WHERE c.target=? AND a.name="RegQueryValueExW" '
                            'AND a.module="advapi32.dll" COLLATE NOCASE ORDER BY c.started', (target,)).fetchall()
                        assert len(calls) == 4, (fixture, calls)
                        registry = [line for line in baselines[fixture][1:] if line[0].isdigit()]
                        assert len(registry) == 2, registry
                        for pass_index, line in enumerate(registry):
                            _, _, result, last_error = map(int, line.split())
                            assert calls[pass_index * 2][0] == 0, calls
                            assert calls[pass_index * 2 + 1] == (result, last_error), calls
                        versions = defaultdict(list)
                        for line in baselines[fixture][1:]:
                            if line.startswith('version '):
                                _, name, result, error = line.split()
                                versions[name].append((int(result), int(error)))
                        assert len(versions) == 15, versions
                        # ANSI wrappers can call Unicode APIs internally; compare the fixture's own requests.
                        modules = connection.execute('SELECT base,size FROM modules WHERE target=? '
                            'AND path=? COLLATE NOCASE AND loaded=1', (target, image)).fetchall()
                        assert len(modules) == 1, (fixture, modules)
                        base, size = modules[0]
                        for name, expected in versions.items():
                            calls = connection.execute('SELECT c.result,c.error FROM calls c JOIN apis a '
                                'ON a.target IN (0,c.target) AND a.id=c.api '
                                'WHERE c.target=? AND c.caller>=? AND c.caller<? AND a.name=? '
                                'AND a.module="version.dll" COLLATE NOCASE '
                                'ORDER BY c.started', (target, base, base + size, name)).fetchall()
                            assert calls == expected, (fixture, name, calls, expected)
        print('PASS: imports, delay imports, reloads and suspended descendant chains preserve capture and results.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('collector', type=Path)
    parser.add_argument('fixtures', type=Path, nargs=3)
    parser.add_argument('--instructions', action='store_true')
    parser.add_argument('--sibling', type=Path)
    arguments = parser.parse_args()
    check(arguments.collector.resolve(), [path.resolve() for path in arguments.fixtures], arguments.instructions,
          arguments.sibling.resolve() if arguments.sibling else None)
