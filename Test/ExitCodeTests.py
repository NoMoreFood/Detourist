import argparse
import os
import pathlib
import subprocess
import tempfile

from TestSupport import Collector, open_trace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('collector', type=pathlib.Path)
    options = parser.parse_args()
    temporary = tempfile.TemporaryDirectory(prefix='Detourist-ExitCodes-')
    collector = Collector(options.collector.resolve())
    try:
        hello = collector.call('hello')
        system = pathlib.Path(os.environ['SystemRoot']) / ('SysWOW64' if hello['pointerSize'] == 4 else 'System32')
        root = pathlib.Path(temporary.name)
        source = root / 'source'
        source.mkdir()
        first = source / 'first.txt'
        second = source / 'second.txt'
        first.write_text('first\n')
        second.write_text('second\n')

        # Real utility workloads distinguish expected outcomes from unsuccessful operations.
        scenarios = [
            ('identical', 'fc.exe', ['/b', first, first], 0, [], False),
            ('different', 'fc.exe', ['/b', first, second], 1, [], True),
            ('expected-difference', 'fc.exe', ['/b', first, second], 1, [1], False),
            ('help', 'fc.exe', ['/?'], 0xFFFFFFFF, ['0xFFFFFFFF'], False),
            ('missing', 'fc.exe', ['/b', first, root / 'missing.txt'], 2, [1], True),
            ('copy', 'robocopy.exe', [source, root / 'copied', 'first.txt', '/r:0', '/w:0'],
             1, [0, 1, 2, 3, 4, 5, 6, 7], False),
            ('copy-error', 'robocopy.exe', [root / 'missing-source', root / 'failed-copy', '/r:0', '/w:0'],
             16, [0, 1, 2, 3, 4, 5, 6, 7], True),
        ]
        for name, executable, arguments, code, expected, warned in scenarios:
            database = root / f'{name}.db'
            status = collector.capture(database=str(database), executable=str(system / executable),
                arguments=subprocess.list2cmdline([str(value) for value in arguments]),
                expectedExitCodes=expected, followChildren=False, bufferLimit=64)
            assert status['processes'] == 1 and not status['partial'], status
            assert status['message'].startswith('Capture finished.'), status
            assert ('nonzero' in status['message']) == warned, (name, status)
            with open_trace(database) as connection:
                state = 'Exited' + (f' (0x{code:08X})' if code else '')
                assert connection.execute('SELECT state FROM targets').fetchall() == [(state,)], (name, state)
                messages = [row[0] for row in connection.execute('SELECT message FROM diagnostics')]
                errors = [message for message in messages if message.startswith('Target exited with code')]
                assert bool(errors) == warned, (name, messages)
                assert not any('uncommitted records' in message for message in messages), (name, messages)
            if name == 'copy':
                assert (root / 'copied' / 'first.txt').read_bytes() == first.read_bytes()

        # Invalid expectations must be rejected before creating a database or starting the target.
        for index, expected in enumerate(([1.5], [-1], [4294967296], ['bad'], [True], '1')):
            database = root / f'invalid-{index}.db'
            assert collector.call('launch', expected=False, database=str(database),
                executable=str(system / 'fc.exe'), arguments='/?', expectedExitCodes=expected)
            assert not database.exists(), (expected, database)
    finally:
        collector.close()
        temporary.cleanup()


if __name__ == '__main__':
    main()
