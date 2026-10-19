import sys
sys.dont_write_bytecode = True

import ctypes
import json
import mmap
import subprocess
import time
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from ctypes import wintypes

from TestSupport import Collector

user = ctypes.WinDLL('user32', use_last_error=True)
user.SendMessageTimeoutW.argtypes = (wintypes.HWND, wintypes.UINT, ctypes.c_size_t, ctypes.c_ssize_t,
                                   wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t))
user.SendMessageTimeoutW.restype = ctypes.c_ssize_t
user.PostMessageW.argtypes = (wintypes.HWND, wintypes.UINT, ctypes.c_size_t, ctypes.c_ssize_t)
user.RegisterWindowMessageW.argtypes = (wintypes.LPCWSTR,)


def send(window, message, first=0, second=0):
    result = ctypes.c_size_t()
    assert user.SendMessageTimeoutW(window, message, first, second, 2, 10000, ctypes.byref(result)), (
        'Target stopped responding', ctypes.get_last_error())
    return result.value


def check(collector_path, target_path):
    target = subprocess.Popen([str(target_path)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        identity = json.loads(target.stdout.readline())
        window, child = (int(identity[key], 16) for key in ('window', 'child'))
        pid, tid = identity['pid'], identity['tid']
        with closing(Collector(collector_path)) as collector:
            # Real system snapshots retain parentage, disabled controls, process and thread identities.
            snapshot = collector.call('spySnapshot')
            windows = {int(item['window'], 16): item for item in snapshot['windows']}
            assert windows[window]['pid'] == pid and windows[window]['tid'] == tid
            assert (windows[window]['left'], windows[window]['top']) == (80, 80)
            assert int(windows[child]['parent'], 16) == window and not windows[child]['enabled']
            assert any(item['pid'] == pid for item in snapshot['processes'])
            assert any(item['tid'] == tid for item in snapshot['threads'])
            for fields in ({'pid': pid}, {'pid': pid, 'tid': tid}, {'pid': pid, 'window': hex(child)}):
                assert collector.call('spyProperties', **fields)
            collector.call('spyStart', expected=False, pid=0)
            collector.call('spyStart', expected=False, pid=-1)
            collector.call('spyStart', expected=False, pid=pid, tid=0xffffffff)
            collector.call('spyStart', expected=False, pid=pid, window=hex(0xffffffff))

            # Sent and returned records preserve native-width parameters, and posted records are distinct.
            collector.call('spyStart', pid=pid, window=hex(window), children=False)
            first = 0xFEDCBA9876543210 if identity['bits'] == 64 else 0xFEDCBA98
            second = 0x10203040
            expected = (first ^ second) & ((1 << identity['bits']) - 1)
            assert send(window, 0x8001, first, second) == expected
            send(window, 0x8002)
            registered = user.RegisterWindowMessageW('Detourist.WindowSpy.Test.Registered')
            send(window, registered, 9, 10)
            assert user.PostMessageW(window, 0x8004, 37, 41)
            time.sleep(.1)
            rows = collector.call('spyPoll')['messages']
            sent = next(row for row in rows if row['message'] == 0x8001 and row['kind'] == 0)
            returned = next(row for row in rows if row['message'] == 0x8001 and row['kind'] == 1)
            assert int(sent['wparam'], 16) == first and int(sent['lparam'], 16) == second
            assert int(returned['result'], 16) == expected
            assert sent['class'] == 'DetouristSpyFixture'
            assert any(row['message'] == 0x8004 and row['kind'] == 2 for row in rows)
            assert all(int(row['window'], 16) == window for row in rows)
            assert any(row['registered'] == 'Detourist.WindowSpy.Test.Registered' for row in rows)
            with closing(Collector(collector_path)) as other:
                error = other.call('spyStart', expected=False, pid=pid)
                assert 'already logging' in error
            assert not collector.call('spyStop')['running']

            # Restarting, descendant selection, new GUI threads and full buffers leave the target responsive.
            for _ in range(3):
                collector.call('spyStart', pid=pid, window=hex(window), children=True)
                send(window, 0x8002)
                rows = collector.call('spyStop')['messages']
                assert any(int(row['window'], 16) == child and row['message'] == 0xc for row in rows)
            collector.call('spyStart', pid=pid)
            worker = send(window, 0x8003)
            assert worker
            time.sleep(1.1)
            collector.call('spyPoll')
            send(worker, 0x8001, 3, 7)
            rows = collector.call('spyPoll')['messages']
            assert any(int(row['window'], 16) == worker and row['tid'] != tid for row in rows)
            with ThreadPoolExecutor(max_workers=2) as producers:
                def produce(destination):
                    for index in range(500):
                        assert send(destination, 0x8001, index, 7) == index ^ 7
                list(producers.map(produce, (window, worker)))
            concurrent = collector.call('spyPoll')
            observed = sum(row['message'] == 0x8001 for row in concurrent['messages'])
            assert observed + concurrent['dropped'] >= 2000
            started = time.monotonic()
            send(window, 0x8005)
            assert time.monotonic() - started < 10
            full = collector.call('spyPoll')
            assert full['dropped'] > 0 and len(full['messages']) <= 8192
            collector.call('spyStop')

            # Properties of a busy target are bounded, and dead window selections fail explicitly.
            assert user.PostMessageW(window, 0x8006, 0, 0)
            time.sleep(.1)
            started = time.monotonic()
            properties = collector.call('spyProperties', pid=pid, window=hex(window))
            assert time.monotonic() - started < 1
            assert any(item['name'] == 'Text' and 'Unavailable' in item['value'] for item in properties)
            time.sleep(1.5)
            collector.call('spyStart', pid=pid, window=hex(child))

            # Hold the shared buffer's writer lock so the window's destruction notifications are dropped.
            with mmap.mmap(-1, 40, tagname=f'Local\\Detourist.WindowSpy.{pid}.buffer') as buffer:
                assert buffer[8:12] == bytes(4), 'The idle message buffer is locked'
                buffer[8:12] = (1).to_bytes(4, 'little')
                try:
                    send(window, 0x8007)
                finally:
                    buffer[8:12] = bytes(4)
            state = collector.call('spyPoll')
            assert state['dropped'] > 0, 'The destruction notifications were not dropped'
            assert not state['running'], 'Logging remained active after its window was destroyed'
            collector.call('spyProperties', expected=False, pid=pid, window=hex(child))
            collector.call('spyStart', pid=pid, tid=tid)
            send(window, 0x8001, 3, 8)
            assert any(row['message'] == 0x8001 for row in collector.call('spyPoll')['messages'])
            collector.call('spyStop')

            # A killed collector must neither strand the application nor prevent a fresh logging session.
            failed = Collector(collector_path)
            failed.call('spyStart', pid=pid)
            send(window, 0x8001)
            failed.process.kill()
            failed.process.wait(timeout=5)
            for stream in (failed.process.stdin, failed.process.stdout, failed.process.stderr):
                stream.close()
            assert send(window, 0x8001, 4, 9) == 13
            collector.call('spyStart', pid=pid)

            # API capture and message hooks coexist in either start order without recording the logger's work.
            with TemporaryDirectory() as temp, closing(Collector(collector_path)) as capture:
                database = str(Path(temp) / 'messages.db')
                capture.call('attach', pid=pid, database=database, apiMask=capture.call('hello')['allApis'])
                capture.wait(lambda state: state['capturing'])
                send(window, 0x8004, 9, 7)
                collector.call('spyStop')
                collector.call('spyStart', pid=pid)
                send(window, 0x8004, 9, 7)
                assert any(row['message'] == 0x8004 for row in collector.call('spyPoll')['messages'])
                capture.call('stop')
                capture.wait(lambda state: state['finished'])
                _, calls = capture.view(database)
                assert any(call['name'] == 'DefWindowProcW' for call in calls)
                assert all(call['name'] != 'GetClassNameW' for call in calls)

            send(window, 0x10)
            target.wait(timeout=10)
            assert target.returncode == 0
            assert not collector.call('spyPoll')['running']
        print(f'PASS: {identity["bits"]}-bit window inspection, hooks, return values, queue messages, scopes, '
              'new threads, overflow, restart, bounded reads, API capture and collector/target shutdown.')
    finally:
        if target.poll() is None:
            target.kill()
            target.wait(timeout=5)
        target.stdout.close()
        target.stderr.close()


if __name__ == '__main__':
    check(Path(sys.argv[1]), Path(sys.argv[2]))
