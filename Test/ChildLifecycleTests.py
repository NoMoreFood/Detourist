import argparse
import ctypes
import pathlib
import subprocess
import tempfile
import uuid

from TestSupport import Collector, open_trace, exit_code, kernel32, snapshots, wait_for


def check(collector_path, target, instructions):
    with tempfile.TemporaryDirectory(prefix='Detourist-ChildLifecycle-') as temporary:
        with Collector(collector_path) as collector:
            hello = collector.call('hello')
            writes = next(api for api in hello['catalog'] if api['name'] == 'WriteFile')
            for protected in (False, True):
                database = pathlib.Path(temporary) / f'{protected}.db'
                status = collector.capture(database=str(database), executable=str(target),
                    arguments='--protected-child' if protected else '--handoff', followChildren=True,
                    apiMask=writes['mask'], instructionEngine=instructions,
                    excludedApis=['CreateProcessAsUserW', 'NtCreateUserProcess'])
                assert status['processes'] == (1 if protected else 2), status
                assert status['partial'] == protected and status['skippedChildren'] == int(protected), status
                assert 'nonzero' not in status['message'], status
                with open_trace(database) as connection:
                    diagnostics = connection.execute(
                        'SELECT target,message FROM diagnostics ORDER BY timestamp,rowid').fetchall()
                    if protected:
                        assert any('ProcessDynamicCodePolicy' in message and '--no-sandbox' in message and
                                   'disables' in message for _, message in diagnostics), diagnostics
                    else:
                        children = connection.execute('SELECT c.target,count(*) FROM calls c JOIN apis a '
                            'ON a.target IN (0,c.target) AND a.id=c.api '
                            'WHERE a.name="WriteFile" GROUP BY c.target').fetchall()
                        assert len(children) == 1 and children[0][0] == 2 and children[0][1] >= 30, children
                        states = connection.execute('SELECT state FROM targets ORDER BY id').fetchall()
                        assert states == [('Exited',), ('Exited',)], states

                # A collector with no live session can still report the saved partial capture and its cause.
                with Collector(collector_path) as viewer:
                    saved = viewer.call('view', database=str(database), advance=False)
                    assert saved['skippedChildren'] == int(protected), saved
                    assert [(item['target'], item['message']) for item in saved['diagnostics']] == diagnostics, saved


def check_suspended(collector_path, target, instructions, child=None):
    child = child or target
    kernel32.CreateEventW.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p)
    kernel32.CreateEventW.restype = ctypes.c_void_p
    kernel32.SetEvent.argtypes = (ctypes.c_void_p,)
    kernel32.OpenThread.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
    kernel32.OpenThread.restype = ctypes.c_void_p
    kernel32.ResumeThread.argtypes = (ctypes.c_void_p,)
    kernel32.ResumeThread.restype = ctypes.c_ulong
    with tempfile.TemporaryDirectory(prefix='Detourist-SuspendedChild-') as temporary:
        root = pathlib.Path(temporary)
        baseline = subprocess.run([str(target), '--suspended-children', '3', str(child)],
            creationflags=subprocess.CREATE_NO_WINDOW, capture_output=True, timeout=45)
        assert baseline.returncode == 0, (baseline.returncode, baseline.stderr)
        for mode, count in (('batch', 35), ('external', 3), ('stop', 3), ('collector-exit', 3)):
            database = root / f'{mode}.db'
            gate_name = 'Local\\DetouristChildTest-' + str(uuid.uuid4())
            gate = kernel32.CreateEventW(None, True, False, gate_name)
            assert gate
            process = None
            killed = False
            try:
                collector = Collector(collector_path)
                try:
                    hello = collector.call('hello')
                    writes = next(api for api in hello['catalog'] if api['name'] == 'WriteFile')
                    arguments = f'--suspended-children {count} "{child}"'
                    marker = root / f'{mode}.ready'
                    if mode != 'batch':
                        arguments += f' "{marker}" "{gate_name}"'
                    if mode == 'external':
                        arguments += ' --external'
                    collector.call('launch', database=str(database), executable=str(target), arguments=arguments,
                        followChildren=True, apiMask=writes['mask'], instructionEngine=instructions,
                        excludedApis=['CreateProcessAsUserW', 'NtCreateUserProcess', 'ResumeThread',
                                      'NtResumeThread', 'NtAlertResumeThread', 'NtResumeProcess'])
                    if mode != 'batch':
                        status = collector.wait(lambda value: value['capturing'] or value['finished'], timeout=45)
                        assert status['capturing'], status
                        with open_trace(database) as connection:
                            pid, = connection.execute('SELECT pid FROM targets WHERE parent=0').fetchone()
                        process = kernel32.OpenProcess(0x100000 | 0x1000 | 1, False, pid)
                        assert process
                        wait_for(marker, process, timeout=120)
                        children = [tuple(map(int, line.split())) for line in marker.read_text().splitlines()]
                        assert len(children) == count, children
                        if mode == 'stop':
                            collector.call('stop')
                        elif mode == 'collector-exit':
                            collector.process.kill()
                            collector.process.wait(timeout=15)
                            killed = True
                        assert kernel32.SetEvent(gate)
                        if mode == 'external':
                            for _, thread_id in children:
                                thread = kernel32.OpenThread(2, False, thread_id)
                                assert thread
                                try:
                                    assert kernel32.ResumeThread(thread) == 1
                                finally:
                                    kernel32.CloseHandle(thread)
                        assert kernel32.WaitForSingleObject(process, 90000) == 0
                        assert exit_code(process) == 0, exit_code(process)
                    if killed:
                        continue
                    status = collector.wait(lambda value: value['finished'], timeout=180)
                    if mode == 'stop':
                        continue
                    assert not status['partial'] and status['skippedChildren'] == 0, status
                    assert status['processes'] == count + 1 and 'nonzero' not in status['message'], status
                    with open_trace(database) as connection:
                        states = connection.execute('SELECT state FROM targets').fetchall()
                        assert states == [('Exited',)] * (count + 1), states
                        calls = connection.execute('SELECT c.target,count(*) FROM calls c JOIN targets t '
                            'ON t.id=c.target JOIN apis a ON a.target=0 AND a.id=c.api '
                            'WHERE t.parent<>0 AND a.name="WriteFile" GROUP BY c.target').fetchall()
                        assert len(calls) == count and all(total >= 4 for _, total in calls), calls
                finally:
                    if killed:
                        collector.process.stdin.close()
                    else:
                        collector.close()
            finally:
                kernel32.SetEvent(gate)
                kernel32.CloseHandle(gate)
                if process:
                    if kernel32.WaitForSingleObject(process, 0) != 0:
                        kernel32.TerminateProcess(process, 1)
                        kernel32.WaitForSingleObject(process, 5000)
                    kernel32.CloseHandle(process)


def check_startup_token(collector_path, target, instructions, child=None, low_integrity=False):
    child = child or target
    with tempfile.TemporaryDirectory(prefix='Detourist-StartupToken-') as temporary:
        root = pathlib.Path(temporary)
        report = root / 'security.txt'
        arguments = ['--startup-token', str(child), str(report)] + (['--low-integrity'] if low_integrity else [])
        baseline = subprocess.run([str(target), *arguments],
            creationflags=subprocess.CREATE_NO_WINDOW, capture_output=True, timeout=75)
        assert baseline.returncode == 0, ('Restricted-token fixture baseline failed',
            baseline.returncode, baseline.stderr.decode('utf-8', errors='replace'),
            report.read_bytes() if report.exists() else None)
        assert report.read_bytes() == b'startup\nrestricted\n'
        report.unlink()
        database = root / 'capture.db'
        with Collector(collector_path) as collector:
            catalog = collector.call('hello')['catalog']
            writes = next(api for api in catalog if api['name'] == 'WriteFile')
            status = collector.capture(database=str(database), executable=str(target),
                arguments=subprocess.list2cmdline(arguments), followChildren=True,
                apiMask=int(writes['mask']) | (1 << 19), instructionEngine=instructions, timeout=90,
                excludedApis=['CreateProcessAsUserW', 'NtCreateUserProcess'])
            assert not status['partial'] and status['skippedChildren'] == 0, status
            assert status['processes'] == 2 and 'nonzero' not in status['message'], status
            assert report.read_bytes() == b'startup\nrestricted\n'
            with open_trace(database) as connection:
                assert connection.execute('SELECT state FROM targets ORDER BY id').fetchall() == [
                    ('Exited',), ('Exited',)]
                errors = connection.execute('SELECT module_error FROM coverage ORDER BY target').fetchall()
                assert errors == [(0,), (0,)], errors
                diagnostics = connection.execute('SELECT target,message FROM diagnostics').fetchall()
                assert not diagnostics, diagnostics
                child_id, = connection.execute('SELECT id FROM targets WHERE parent<>0').fetchone()
                epochs = connection.execute('SELECT epoch FROM modules WHERE target=? AND loaded=1 AND epoch>0 '
                    'AND lower(path) LIKE ? ORDER BY epoch', (child_id, '%\\winmm.dll')).fetchall()
                assert epochs, epochs
                plays = connection.execute('SELECT coalesce(d.module,a.module),c.arguments,c.module_epoch '
                    'FROM calls c LEFT JOIN apis d ON d.target=c.target AND d.id=c.api '
                    'LEFT JOIN apis a ON a.target=0 AND a.id=c.api WHERE c.target=? '
                    'AND coalesce(d.name,a.name)="PlaySoundW" AND c.ended IS NOT NULL', (child_id,)).fetchall()
                assert any(module.lower() == 'winmm.dll' and arguments == bytes(24) and epoch >= epochs[0][0]
                           for module, arguments, epoch in plays), plays
                rows = connection.execute('SELECT coalesce(d.name,a.name),c.input,c.result FROM calls c '
                    'JOIN targets t ON t.id=c.target LEFT JOIN apis d ON d.target=c.target AND d.id=c.api '
                    'LEFT JOIN apis a ON a.target=0 AND a.id=c.api '
                    'WHERE t.parent<>0 AND coalesce(d.name,a.name)="WriteFile"').fetchall()
                captured = [data for name, payload, result in rows if name == 'WriteFile' and result
                            for _, _, data in snapshots(payload, 1, 0)]
                assert b'startup\n' in captured and b'restricted\n' in captured, captured


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('collector', type=pathlib.Path)
    parser.add_argument('target', type=pathlib.Path)
    parser.add_argument('--instructions', action='store_true')
    parser.add_argument('--low-integrity', action='store_true')
    scenario = parser.add_mutually_exclusive_group()
    scenario.add_argument('--suspended', action='store_true')
    scenario.add_argument('--startup-token', action='store_true')
    child_target = parser.add_mutually_exclusive_group()
    child_target.add_argument('--child', type=pathlib.Path)
    child_target.add_argument('--cross-architecture', action='store_true')
    options = parser.parse_args()
    if options.cross_architecture:
        from SessionTests import sibling_target
        options.child = sibling_target(options.target.resolve())
        if not options.child:
            print('The sibling architecture fixture is not built.')
            raise SystemExit(77)
    if options.startup_token:
        check_startup_token(options.collector.resolve(), options.target.resolve(), options.instructions,
            options.child.resolve() if options.child else None, options.low_integrity)
    elif options.suspended:
        check_suspended(options.collector.resolve(), options.target.resolve(), options.instructions,
            options.child.resolve() if options.child else None)
    else:
        check(options.collector.resolve(), options.target.resolve(), options.instructions)
