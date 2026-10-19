import sys
sys.dont_write_bytecode = True

import argparse
import contextlib
import ctypes
import json
import pathlib
import queue
import sqlite3
import struct
import subprocess
import threading
import time

@contextlib.contextmanager
def open_trace(path, *, named=False):
    with contextlib.closing(sqlite3.connect(path)) as connection:
        if named:
            connection.row_factory = sqlite3.Row
        yield connection


class Collector:
    def __init__(self, executable, env=None):
        self.process = subprocess.Popen(
            [str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW, env=env)
        self.responses = queue.Queue()
        self.next_id = 0
        self.waiting = {}
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def __enter__(self):
        return self

    def __exit__(self, *error):
        self.close()

    def read(self):
        try:
            for line in self.process.stdout:
                self.responses.put(json.loads(line))
        except Exception as error:
            self.responses.put(RuntimeError(f"Invalid collector response {line!r}: {error}"))
        self.responses.put(RuntimeError("Collector pipe closed before responding"))

    def call(self, command, expected=True, **fields):
        return self.receive(self.send(command, **fields), expected)

    def send(self, command, **fields):
        if command == "launch":
            fields.setdefault("startMinimized", True)
        self.next_id += 1
        request = {"id": self.next_id, "command": command, **fields}
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        return self.next_id

    def receive(self, identifier, expected=True, timeout=25):
        deadline = time.monotonic() + timeout
        while identifier not in self.waiting:
            response = self.responses.get(timeout=max(0.001, deadline - time.monotonic()))
            if isinstance(response, Exception):
                raise response
            self.waiting[response['id']] = response
        response = self.waiting.pop(identifier)
        assert response["ok"] == expected, response
        return response["data"] if expected else response["error"]

    def wait(self, predicate, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.call("status")
            if predicate(status):
                return status
            time.sleep(0.02)
        raise AssertionError(f"Capture timed out: {status}")

    def capture(self, timeout=30, **fields):
        self.call("launch", **fields)
        return self.wait(lambda status: status["finished"], timeout)

    def require_exited(self, database):
        targets = self.call("page", database=str(database), limit=1)["targets"]
        assert targets and all(target["state"] == "Exited" for target in targets), targets

    def view(self, database, order="newest", **query):
        # Index a view in bounded slices, then read every row through position windows.
        state = self.call("view", database=database, order=order, **query)
        while not state["complete"]:
            state.update(self.call("view", view=state["view"], includeMetadata=False))
        return state, self.rows(state)

    def rows(self, state):
        rows = []
        while len(rows) < state["count"]:
            batch = self.call("rows", view=state["view"], index=len(rows), limit=400)["calls"]
            assert batch, (len(rows), state)
            rows.extend(batch)
        return rows

    def close(self):
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            code = self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise
        assert code == 0, self.process.stderr.read()


def snapshots(payload, parameter, kind):
    return [(flags, original, data) for index, value_kind, flags, original, data in values(payload)
            if index == parameter and value_kind == kind]


def check_limit(payloads, limit, *detail):
    for payload in payloads:
        for value in values(payload):
            assert len(value[4]) <= limit, (*detail, value[:4], limit)


def value_records(payload):
    return [{'parameter': parameter, 'kind': kind, 'flags': flags, 'total': total, 'bytes': data}
            for parameter, kind, flags, total, data in values(payload)]


def wait_file(path, process, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with path.open('rb'):
                return
        except (FileNotFoundError, PermissionError):
            assert process.poll() is None, f"Target exited before {path.name}: {process.returncode}"
            time.sleep(0.02)
    raise AssertionError(f"Target did not publish a readable {path.name}")


kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.GetExitCodeProcess.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
kernel32.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_ulong)
kernel32.TerminateProcess.argtypes = (ctypes.c_void_p, ctypes.c_uint)
kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)


def exit_code(process):
    code = ctypes.c_ulong()
    assert kernel32.GetExitCodeProcess(process, ctypes.byref(code))
    return code.value


def wait_for(path, process, timeout=25):
    deadline = time.monotonic() + timeout
    while not path.exists() and time.monotonic() < deadline:
        assert kernel32.WaitForSingleObject(process, 0) != 0, (
            f'Target exited before {path.name}: {exit_code(process):#x}')
        time.sleep(.02)
    assert path.exists(), f'Target did not produce {path.name}'


def values(payload):
    offset = 0
    result = []
    while payload and offset < len(payload):
        assert len(payload) - offset >= 24, ('Incomplete capture header', offset, len(payload))
        index, kind, flags, count, original = struct.unpack_from('<IIIIQ', payload, offset)
        offset += 24
        data = payload[offset:offset + count]
        assert len(data) == count, ('Incomplete captured value', index, count, len(data))
        result.append((index, kind, flags, original, data))
        offset += count
    return result


def run_scenarios(scenarios):
    parser = argparse.ArgumentParser(description='Run one isolated capability scenario.')
    parser.add_argument('scenario', choices=scenarios)
    selected = parser.parse_args(sys.argv[1:2]).scenario
    del sys.argv[1]
    scenarios[selected]()


def path_parser(*names):
    parser = argparse.ArgumentParser()
    for name in names:
        parser.add_argument(name, type=pathlib.Path)
    return parser


def run_paths(check, *names):
    options = path_parser(*names).parse_args()
    check(*(getattr(options, name).resolve() for name in names))
