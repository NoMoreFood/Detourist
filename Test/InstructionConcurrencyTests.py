import os
import pathlib
import signal
import tempfile
import time

from TestSupport import Collector, open_trace, run_paths


def check(collector_path, target):
    # Cold multithreaded captures build translated blocks while engine callbacks wait for agent-held state.
    with tempfile.TemporaryDirectory(prefix='Detourist-InstructionConcurrency-') as temporary:
        with Collector(collector_path) as collector:
            files = next(item for item in collector.call('hello')['categories'] if item['name'] == 'Files and storage')
            for run in range(12):
                database = pathlib.Path(temporary) / f'{run}.db'
                collector.call('launch', database=str(database), executable=str(target), arguments='--leaf 20',
                               instructionEngine=True, followChildren=False, categoryMask=str(files['mask']))
                started = time.monotonic()
                try:
                    status = collector.wait(lambda value: value['finished'], timeout=30)
                except AssertionError:
                    for item in collector.call('page', database=str(database), limit=1)['targets']:
                        if item['state'] == 'Capturing':
                            os.kill(item['pid'], signal.SIGTERM)
                    raise
                assert 'nonzero' not in status['message'], status
                with open_trace(database) as connection:
                    notes = [row[0] for row in connection.execute('SELECT message FROM diagnostics')]
                assert not any('lost completion tracking' in note for note in notes), notes
                print(f'capture {run}: {time.monotonic() - started:.1f} s, {status["calls"]} calls')


if __name__ == '__main__':
    run_paths(check, 'collector', 'target')
