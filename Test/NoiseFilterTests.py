import argparse
import pathlib
import tempfile

from TestSupport import Collector, open_trace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('collector', type=pathlib.Path)
    parser.add_argument('target', type=pathlib.Path)
    parser.add_argument('--instructions', action='store_true')
    parser.add_argument('--iterations', type=int, default=200)
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='Detourist-Noise-') as temporary:
        with Collector(options.collector.resolve()) as collector:
            hello = collector.call('hello')
            profiles = {profile['id']: profile for profile in hello['noiseProfiles']}
            assert {'queries', 'runtime'} <= profiles.keys(), profiles
            scenarios = [('none', ()), ('queries', ()), ('runtime', ()), ('runtime', ('GetLastError',))]
            totals = []
            for index, (profile, recorded) in enumerate(scenarios):
                # Clients add profile APIs to editable exclusions; an unchecked entry is recorded again.
                excluded = [name for name in profiles.get(profile, {}).get('apis', []) if name not in recorded]
                database = pathlib.Path(temporary) / f'{index}.db'
                status = collector.capture(database=str(database), executable=str(options.target.resolve()),
                                           arguments=f'--noise {options.iterations}', followChildren=False,
                                           instructionEngine=options.instructions, excludedApis=excluded)
                assert status['processes'] == 1 and 'nonzero' not in status['message'], status
                with open_trace(database) as connection:
                    counts = dict(connection.execute('SELECT a.name,count(*) FROM calls c JOIN apis a '
                        'ON a.target IN (0,c.target) AND a.id=c.api GROUP BY a.name'))
                assert counts.get('WriteFile', 0) > 0, counts
                assert ('GetLastError' in counts) == (profile == 'none' or bool(recorded)), counts
                assert ('SetLastError' in counts) == (profile != 'runtime'), counts
                assert ('IsThreadAFiber' in counts) == (profile == 'none'), counts
                for name in ('GetProcessHeap', 'FlsGetValue'):
                    assert (name in counts) == (profile == 'none'), (name, counts)
                assert ('lstrcmpiW' in counts) == (profile != 'runtime'), counts
                totals.append(status['calls'])
                print(f'{profile}: {status["calls"]} calls, '
                      f'{status["blockedMilliseconds"]:.2f} ms blocked')
            assert totals[2] < totals[1] < totals[0], totals


if __name__ == '__main__':
    main()
