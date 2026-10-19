import argparse
import ctypes
import pathlib
import tempfile
import time
import uuid

from TestSupport import Collector, open_trace, kernel32 as kernel


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('collector', type=pathlib.Path)
    parser.add_argument('target', type=pathlib.Path)
    options = parser.parse_args()
    kernel.CreateEventW.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p)
    kernel.CreateEventW.restype = ctypes.c_void_p
    kernel.SetEvent.argtypes = kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel.ResetEvent.argtypes = (ctypes.c_void_p,)
    name = f'Local\\Detourist.Diagnostics.{uuid.uuid4()}'
    finish = kernel.CreateEventW(None, True, False, name)
    assert finish, ctypes.get_last_error()
    with tempfile.TemporaryDirectory(prefix='Detourist-Diagnostics-') as temporary:
        collector = Collector(options.collector.resolve())
        try:
            hello = collector.call('hello')
            wait = next(api for api in hello['catalog'] if api['name'] == 'NtWaitForSingleObject')
            for scenario in ('exit', 'terminate', 'detach'):
                kernel.ResetEvent(finish)
                database = pathlib.Path(temporary) / f'{scenario}.db'
                process = None
                try:
                    collector.call('launch', database=str(database), executable=str(options.target.resolve()),
                                   arguments=f'--unfinished-wait {name}', apiMask=wait['mask'], followChildren=False)
                    started = collector.wait(lambda value: value['capturing'] or value['finished'])
                    assert started['capturing'], started

                    # Persist a blocked worker and index its live state before interrupting capture.
                    deadline = time.monotonic() + 15
                    with open_trace(database) as connection:
                        while not connection.execute('SELECT 1 FROM calls WHERE api=? AND ended IS NULL LIMIT 1',
                                                     (wait['id'],)).fetchone():
                            assert time.monotonic() < deadline, 'Worker wait was not captured'
                            time.sleep(.02)
                        pid = connection.execute('SELECT pid FROM targets').fetchone()[0]
                        process = kernel.OpenProcess(0x100001, False, pid)
                        assert process, ctypes.get_last_error()
                        view, rows = collector.view(str(database), filter='NtWaitForSingleObject')
                        assert any(row['state'] == 'Running' for row in rows), rows
                        if scenario == 'exit':
                            kernel.SetEvent(finish)
                        elif scenario == 'terminate':
                            assert kernel.TerminateProcess(process, 0xC0000005), ctypes.get_last_error()
                        else:
                            collector.call('stop')
                        status = collector.wait(lambda value: value['finished'])
                        assert ('nonzero' in status['message']) == (scenario == 'terminate'), status
                        state = connection.execute('SELECT state FROM targets').fetchone()[0]
                        assert state == {'exit': 'Exited', 'terminate': 'Exited (0xC0000005)',
                                         'detach': 'Detached'}[scenario], state
                        pending = connection.execute('SELECT flags,result,ended,adjusted_duration FROM calls '
                            'WHERE api=? AND ended IS NULL', (wait['id'],)).fetchall()
                        assert pending and all(row[1:] == (None, None, None) for row in pending), pending
                        assert all(bool(row[0] & 32) == (scenario != 'detach') for row in pending), pending
                        messages = [row[0] for row in connection.execute('SELECT message FROM diagnostics')]
                        expected = [] if scenario == 'exit' else [
                            'Target exited with code 0xC0000005' if scenario == 'terminate' else
                            'Capture ended before all calls returned.']
                        assert messages == expected, messages

                    # Existing views must release their cached Running state after process termination.
                    refreshed = collector.call('view', view=view['view'])
                    rows = collector.rows(refreshed)
                    interrupted = [row for row in rows if row['durationUs'] < 0]
                    assert interrupted, rows
                    expected = 'Running' if scenario == 'detach' else 'Entry only'
                    assert all(row['state'] == expected for row in interrupted), interrupted
                    if scenario == 'detach':
                        assert kernel.WaitForSingleObject(process, 0) == 258, 'Detach terminated the target'
                finally:
                    kernel.SetEvent(finish)
                    if process:
                        assert kernel.WaitForSingleObject(process, 5000) == 0, 'Target did not exit'
                        kernel.CloseHandle(process)
        finally:
            kernel.SetEvent(finish)
            collector.close()
            kernel.CloseHandle(finish)


if __name__ == '__main__':
    main()
