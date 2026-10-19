import sys
sys.dont_write_bytecode = True

import argparse
import ctypes
import tempfile
import time
from pathlib import Path
from ctypes import wintypes

from TestSupport import Collector, open_trace, kernel32, exit_code


def seed(collector, target, database):
    api = next(item for item in collector.call('hello')['catalog'] if item['name'] == 'WriteFile')
    collector.capture(database=str(database), executable=str(target), arguments='--leaf 1',
        apiMask=api['mask'], followChildren=False)
    return api


def slow_database(source, destination):
    # An expanded trace relation makes SQLite spend time inside a step, beyond the view's row-slice budget.
    with open_trace(source) as connection, open_trace(destination) as output:
        connection.backup(output)
        output.executescript('ALTER TABLE calls RENAME TO recorded_calls; CREATE VIEW calls AS '
            'WITH RECURSIVE copies(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM copies WHERE n<1000000000) '
            'SELECT c.rowid AS rowid,c.* FROM recorded_calls c CROSS JOIN copies;')


def queries(collector_path, target):
    with tempfile.TemporaryDirectory(prefix='Detourist-Queries-') as temporary:
        root = Path(temporary)
        collector = Collector(collector_path)
        monitored = None
        try:
            api = seed(collector, target, root / 'seed.db')
            slow_database(root / 'seed.db', root / 'slow.db')
            for ending in ('continue', 'stop', 'disconnect'):
                collector.call('launch', database=str(root / f'{ending}.db'), executable=str(target),
                    arguments='--leaf 20', apiMask=api['mask'], entryApi=api['id'], followChildren=False)
                status = collector.wait(lambda status: status['breakpoint'] or status['finished'])
                assert status['breakpoint'], status
                monitored = kernel32.OpenProcess(0x101001, False, status['stoppedCall']['pid'])
                assert monitored
                query = collector.send('view', database=str(root / 'slow.db'))
                time.sleep(.1)
                start = time.monotonic()
                assert collector.call('status')['breakpoint']
                assert time.monotonic() - start < 1, 'Slow SQL blocked status.'
                assert query not in collector.waiting, 'The slow query finished before controls were tested.'
                if ending == 'disconnect':
                    collector.close()
                else:
                    if ending == 'continue':
                        collector.call('breakApi', entryApi=-1, exitApi=-1)
                    start = time.monotonic()
                    collector.call(ending)
                    assert time.monotonic() - start < 1, f'Slow SQL blocked {ending}.'
                    collector.call('cancel', request=query)
                    assert 'canceled' in collector.receive(query, expected=False, timeout=2)
                    collector.wait(lambda status: status['finished'])
                assert kernel32.WaitForSingleObject(monitored, 10000) == 0
                assert exit_code(monitored) == 0
                kernel32.CloseHandle(monitored)
                monitored = None
                print(f'Slow query: {ending} released the breakpoint and target.', flush=True)
                if ending == 'disconnect':
                    collector = Collector(collector_path)

            start = time.monotonic()
            error = collector.call('view', expected=False, database=str(root / 'slow.db'), timeout=150)
            assert 'time limit' in error and time.monotonic() - start < 2, error
            view, rows = collector.view(str(root / 'seed.db'))
            assert rows and view['complete']
            query = collector.send('view', database=str(root / 'slow.db'))
            time.sleep(.1)
            start = time.monotonic()
            seed(collector, target, root / 'next.db')
            assert 'canceled' in collector.receive(query, expected=False)
            assert time.monotonic() - start < 5, 'A new capture waited for stale query work.'
            print('Slow query: cancellation, deadline, EOF cleanup and subsequent queries passed.', flush=True)
        finally:
            collector.close()
            if monitored:
                if kernel32.WaitForSingleObject(monitored, 5000) != 0:
                    kernel32.TerminateProcess(monitored, 1)
                kernel32.CloseHandle(monitored)


def snapshots(collector_path, target):
    with tempfile.TemporaryDirectory(prefix='Detourist-Snapshots-') as temporary:
        database = Path(temporary) / 'live.db'
        with Collector(collector_path) as collector:
            api = seed(collector, target, database)
            with open_trace(database) as writer:
                writer.executescript('DELETE FROM calls; DELETE FROM threads; INSERT INTO threads VALUES(1,1),(1,2);')
                count = 100500
                insert = ('INSERT INTO calls(target,id,tid,api,started,ended,parent,depth,caller,result,error,'
                    f'flags,arguments) VALUES(1,?,1,{api["id"]},?,?,0,0,0,?,0,0,zeroblob(40))')
                writer.executemany(insert, ((number, number * 10, None if number % 256 == 0 else number * 10 + 2, 0)
                    for number in range(1, count + 1)))
                writer.execute('UPDATE calls SET flags=1 WHERE id=256')
                writer.execute('UPDATE calls SET tid=2 WHERE id IN (1,256)')
                writer.execute('UPDATE session SET total_calls=?', (count,))
                writer.commit()
                views = {}
                for order in ('oldest', 'newest'):
                    for filter in ('', 'result:0'):
                        state = collector.call('view', database=str(database), order=order, filter=filter, budget=1000)
                        while not state['complete']:
                            state = collector.call('view', view=state['view'], budget=1000)
                        assert state['count'] == count
                        views[order, filter] = state
                ranked = collector.call('view', database=str(database), order='slowest', budget=1000)
                while not ranked['complete']:
                    ranked = collector.call('view', view=ranked['view'], budget=1000)
                assert ranked['count'] == 100000
                marked = views['oldest', '']
                marked.update(collector.call('mark', view=marked['view'], filters=['result:0']))
                sparse = {}
                for order in ('oldest', 'newest', 'slowest'):
                    state = collector.call('view', database=str(database), target=1, thread=2,
                        order=order, budget=1000)
                    while not state['complete']:
                        state = collector.call('view', view=state['view'], budget=1000)
                    sparse[order] = state

                # Returns remove checkpoint-boundary rows from a result filter; a late entry shifts earlier positions.
                writer.execute('UPDATE calls SET ended=started+4,result=1,flags=CASE WHEN id=256 THEN 0 ELSE 1 END '
                    'WHERE ended IS NULL')
                writer.execute(insert, (count + 1, 5, 9, 0))
                writer.execute(insert, (count + 2, (count + 2) * 10, (count + 2) * 10 + 2, 0))
                writer.execute('UPDATE session SET total_calls=?', (count + 2,))
                writer.commit()

                # Sparse summaries use the published membership and preserve pending returns and failure flags.
                for order, state in sparse.items():
                    summary = collector.call('summary', view=state['view'], restart=True, budget=1)
                    while not summary['complete']:
                        summary = collector.call('summary', view=state['view'], budget=1)
                    assert sum(item['calls'] for item in summary['items']) == (1 if order == 'slowest' else 2)
                    assert sum(item['returned'] for item in summary['items']) == 1
                    assert sum(item['failed'] for item in summary['items']) == (0 if order == 'slowest' else 1)
                    assert abs(sum(item['totalUs'] for item in summary['items']) -
                        2 * 1000000 / state['frequency']) < .001
                    if order != 'slowest':
                        density = collector.call('timeline', view=state['view'], buckets=20, budget=1000)
                        assert sum(density['failures']) == 1, density
                        state.update(collector.call('view', view=state['view']))
                        summary = collector.call('summary', view=state['view'], budget=1000)
                        assert summary['complete'] and sum(item['returned'] for item in summary['items']) == 2
                        assert sum(item['failed'] for item in summary['items']) == 0
                        assert abs(sum(item['totalUs'] for item in summary['items']) -
                            6 * 1000000 / state['frequency']) < .001
                    collector.call('release', view=state['view'])

                for (order, filter), state in views.items():
                    # All reads, even sparse seeks and summaries, stay at the published snapshot before advance.
                    positions = (0, 254, 255, 256, 32767, count - 2)
                    for index in positions:
                        rows = collector.call('rows', view=state['view'], revision=state['revision'],
                            index=index, limit=2)['calls']
                        expected = [index + 1, index + 2] if order == 'oldest' else [count - index, count - index - 1]
                        assert [row['id'] for row in rows] == expected, (order, filter, index, rows)
                        assert all(row['result'] == '0x0' for row in rows)
                    summary = collector.call('summary', view=state['view'], revision=state['revision'], restart=True)
                    while not summary['complete']:
                        summary = collector.call('summary', view=state['view'], revision=state['revision'])
                    assert sum(item['calls'] for item in summary['items']) == count
                    assert sum(item['failed'] for item in summary['items']) == 1
                    density = collector.call('timeline', view=state['view'], revision=state['revision'], buckets=20)
                    assert sum(density['failures']) == 1, (order, filter, density)
                    old_revision = state['revision']
                    state.update(collector.call('view', view=state['view']))
                    assert state['revision'] > old_revision
                    assert collector.call('rows', view=state['view'], revision=old_revision)['stale']
                    expected = [count + 1] + [number for number in range(1, count + 1)
                        if not filter or number % 256 != 0] + [count + 2]
                    if order == 'newest':
                        expected.reverse()
                    assert state['count'] == len(expected), (order, filter, state)
                    for index in (0, 254, 255, 256, 32767, len(expected) - 2):
                        rows = collector.call('rows', view=state['view'], revision=state['revision'],
                            index=index, limit=2)['calls']
                        assert [row['id'] for row in rows] == expected[index:index + 2], (order, filter, index, rows)
                        located = collector.call('locate', view=state['view'], revision=state['revision'],
                            target=1, callId=expected[index])
                        assert located['index'] == index, (order, filter, index, located)

                # The ranking excludes pending calls and summarizes only its displayed, capped membership.
                summary = collector.call('summary', view=ranked['view'], restart=True, budget=1)
                while not summary['complete']:
                    summary = collector.call('summary', view=ranked['view'], budget=1)
                assert sum(item['calls'] for item in summary['items']) == ranked['count']
                assert sum(item['returned'] for item in summary['items']) == ranked['count']
                assert sum(item['failed'] for item in summary['items']) == 0
                assert abs(sum(item['totalUs'] for item in summary['items']) -
                    2 * ranked['count'] * 1000000 / ranked['frequency']) < .001

                # A frozen or slowest-first view keeps its snapshot without pinning the write-ahead log.
                frozen = collector.call('view', database=str(database), order='newest', budget=1000)
                while not frozen['complete']:
                    frozen = collector.call('view', view=frozen['view'], budget=1000)
                slowest = collector.call('view', database=str(database), order='slowest', budget=1000)
                while not slowest['complete']:
                    slowest = collector.call('view', view=slowest['view'], budget=1000)
                slowest_rows = collector.call('rows', view=slowest['view'], revision=slowest['revision'],
                    index=0, limit=10)['calls']
                writer.execute(insert, (count + 3, (count + 3) * 10, (count + 3) * 10 + 2, 0))
                writer.commit()
                assert writer.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] == 0
                for turn in range(2500):
                    writer.execute('UPDATE calls SET result=? WHERE id=?', (turn, count + 3))
                    writer.commit()
                assert Path(f'{database}-wal').stat().st_size < 6 * 1024 * 1024
                assert writer.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone() == (0, 0, 0)
                assert Path(f'{database}-wal').stat().st_size == 0
                frozen.update(collector.call('view', view=frozen['view'], extend=False))
                assert frozen['count'] == count + 2
                slowest.update(collector.call('view', view=slowest['view'], extend=False))
                assert collector.call('rows', view=slowest['view'], revision=slowest['revision'],
                    index=0, limit=10)['calls'] == slowest_rows
                frozen.update(collector.call('view', view=frozen['view'], extend=True))
                assert frozen['count'] == count + 3

                # Text filters search bounded binary payloads in either encoding, including overlapping prefixes.
                payloads = [(1, b'\0MiXeD\0', None), (2, None, 'mIxEd'.encode('utf-16le')),
                    (3, b'A' * 4096 + b'Ab', b'\xff\0edge'), (4, b'aAaAc', b'x'),
                    (5, b'\xc3\xa9MixED', None)]
                for identifier, before, after in payloads:
                    writer.execute('UPDATE calls SET input=?,output=? WHERE id=?', (before, after, identifier))
                writer.commit()
                for text, expected in [('mixed', [1, 2, 5]), ('aaaab', [3]), ('aaaac', [4]),
                    ('edge', [3]), ('x', [1, 2, 4, 5]), ('\u00e9mixed', [5]), ('missing', [])]:
                    state, rows = collector.view(str(database), order='oldest', filter=f'text:{text}')
                    assert [row['id'] for row in rows] == expected, (text, rows)
                    summary = collector.call('summary', view=state['view'], restart=True, budget=1000)
                    assert summary['complete'] and sum(item['calls'] for item in summary['items']) == len(expected)
                    collector.call('release', view=state['view'])

                # A rare thread retains its failure markers even when failures fill the rest of the trace.
                writer.execute('UPDATE calls SET flags=1')
                writer.commit()
                state, rows = collector.view(str(database), target=1, thread=2)
                density = collector.call('timeline', view=state['view'], budget=1000)
                assert state['count'] == len(rows) == sum(density['failures']) == 2, density
                print('Live snapshots: sparse rows, returns, late entries, text, summary, timeline and resume passed.',
                    flush=True)


class ProcessEntry(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('usage', wintypes.DWORD), ('pid', wintypes.DWORD),
        ('heap', ctypes.c_size_t), ('module', wintypes.DWORD), ('threads', wintypes.DWORD),
        ('parent', wintypes.DWORD), ('priority', wintypes.LONG), ('flags', wintypes.DWORD),
        ('name', wintypes.WCHAR * 260)]


def children(parent, image):
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(ProcessEntry))
    kernel32.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(ProcessEntry))
    snapshot = kernel32.CreateToolhelp32Snapshot(2, 0)
    result = []
    try:
        entry = ProcessEntry(size=ctypes.sizeof(ProcessEntry))
        more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            if entry.parent == parent and entry.name.casefold() == image.casefold():
                result.append(entry.pid)
            more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        return result
    finally:
        kernel32.CloseHandle(snapshot)


def pressure(collector_path, target):
    ntdll = ctypes.WinDLL('ntdll')
    ntdll.NtSuspendProcess.argtypes = ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
    with tempfile.TemporaryDirectory(prefix='Detourist-Children-') as temporary:
        collector = Collector(collector_path)
        stalled = None
        parent = None
        try:
            for stop in (False, True):
                database = str(Path(temporary) / f'pressure-{stop}.db')
                collector.call('launch', database=database, executable=str(target), arguments='--burst 34',
                    bufferLimit=128)
                collector.wait(lambda status: status['capturing'])
                page = collector.call('page', database=database, limit=0)
                pid = page['targets'][0]['pid']
                parent = kernel32.OpenProcess(0x101001, False, pid)
                if stop:
                    collector.wait(lambda status: status['attaching'] > 0)
                    start = time.monotonic()
                    collector.call('stop')
                    assert time.monotonic() - start < 1
                    collector.wait(lambda status: status['finished'], timeout=10)
                else:
                    deadline = time.monotonic() + 10
                    while not stalled and time.monotonic() < deadline:
                        registered = {item['pid'] for item in page['targets']}
                        for child in children(pid, target.name):
                            if child in registered:
                                continue
                            process = kernel32.OpenProcess(0x100800, False, child)
                            if not process:
                                continue
                            if ntdll.NtSuspendProcess(process) >= 0:
                                time.sleep(.05)
                                page = collector.call('page', database=database, limit=0)
                                if child not in {item['pid'] for item in page['targets']}:
                                    stalled = process
                                    break
                                ntdll.NtResumeProcess(process)
                            kernel32.CloseHandle(process)
                        if not stalled:
                            page = collector.call('page', database=database, limit=0)
                    assert stalled, 'No pending child attachment was stalled.'
                    initial = collector.call('status')
                    start = time.monotonic()
                    progressed = collector.wait(lambda status: status['calls'] > initial['calls'] and
                        status['processes'] > initial['processes'], timeout=5)
                    assert time.monotonic() - start < 5 and progressed['attaching'] > 0
                    ntdll.NtResumeProcess(stalled)
                    kernel32.CloseHandle(stalled)
                    stalled = None
                    status = collector.wait(lambda status: status['finished'], timeout=60)
                    assert status['processes'] == 35, status
                    page = collector.call('page', database=database, api='WriteFile', limit=1000)
                    assert all(item['state'] == 'Exited' for item in page['targets']), page['targets']
                    completed = {row['target'] for row in page['calls'] if row['durationUs'] >= 0}
                    assert {item['id'] for item in page['targets'][1:]} <= completed
                assert kernel32.WaitForSingleObject(parent, 15000) == 0
                assert exit_code(parent) == 0
                kernel32.CloseHandle(parent)
                parent = None
                scenario = 'stop during attachment' if stop else 'stalled child and 34 launches'
                print(f'Child pressure: {scenario} passed.', flush=True)
        finally:
            if stalled:
                ntdll.NtResumeProcess(stalled)
                kernel32.CloseHandle(stalled)
            collector.close()
            if parent:
                if kernel32.WaitForSingleObject(parent, 15000) != 0:
                    kernel32.TerminateProcess(parent, 1)
                kernel32.CloseHandle(parent)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('scenario', choices=('queries', 'snapshots', 'pressure'))
    parser.add_argument('collector', type=Path)
    parser.add_argument('target', type=Path)
    arguments = parser.parse_args()
    globals()[arguments.scenario](arguments.collector.resolve(), arguments.target.resolve())
