import sys
sys.dont_write_bytecode = True

import base64
import json
import os
import pathlib
import signal
import sqlite3
import struct
import subprocess
import tempfile
import time
import winreg
from contextlib import closing, nullcontext
from pathlib import Path

from TestSupport import (Collector, check_limit, open_trace, exit_code, kernel32, run_paths, path_parser,
                         run_scenarios, snapshots, values, wait_file, wait_for)
from NativeImage import native_export


def check_launch(collector_path, target_path, instructions=False, host=None, runtime=None, strict_native_interop=False,
        require_native_ntdll=False):
    with tempfile.TemporaryDirectory(prefix="Detourist-Managed-") as directory:
        root = pathlib.Path(directory)
        database = str(root / "managed.db")
        result_path = root / "result.txt"
        collector = Collector(collector_path)
        try:
            hello = collector.call("hello")
            launch_arguments = f'"{result_path}"'
            if host:
                launch_arguments = f'"{runtime}" "{target_path}" {launch_arguments}'
            status = collector.capture(database=database, executable=str(host or target_path),
                                       arguments=launch_arguments, bufferLimit=64,
                                       apiMask=str(int(hello["managedMask"]) | (1 << 19) |
                               (((1 << 2) | (1 << 18) | (1 << 22) | (1 << 23)) if instructions else 0)),
                                       followChildren=False, instructionEngine=instructions, timeout=110)
            page = collector.call("page", database=database, limit=1)
            assert all(target["state"] == "Exited" for target in page["targets"]), page["targets"]
            assert result_path.is_file(), (status, page["targets"])
            assert result_path.read_text() == "managed-ok", status
            assert all(target["managedState"] == 1 and target["managedApis"] > 0
                       for target in page["targets"]), page["targets"]
            with open_trace(database) as connection:
                # Callback bookkeeping stays suppressed; DLL thread initialization can precede any managed callback.
                profiler_images = connection.execute('SELECT DISTINCT target,base,size FROM modules '
                    'WHERE path LIKE ? AND loaded=1', ('%\\DetouristProfiler.dll',)).fetchall()
                assert profiler_images, 'Profiler image was not recorded'
                error_calls = connection.execute('SELECT c.target,c.caller,a.name,c.parent FROM calls c JOIN apis a '
                    'ON a.id=c.api AND a.target IN (0,c.target) '
                    'WHERE a.name IN ("GetLastError","SetLastError")').fetchall()
                assert error_calls, 'Native error capture was not exercised'
                for target, caller, name, parent in error_calls:
                    if not parent or not any(target == owner and base <= caller < base + size
                                             for owner, base, size in profiler_images):
                        continue
                    source = connection.execute('SELECT api FROM calls WHERE target=? AND id=?',
                                                (target, parent)).fetchone()
                    assert source and not 0x40000000 <= source[0] < 0x50000000, \
                        ('Profiler recorded callback bookkeeping', name, caller)
                definitions = connection.execute(
                    "SELECT target,id,module,name FROM apis WHERE target<>0").fetchall()
                assert definitions and all(item[1] >= 0x40000000 for item in definitions), definitions[:5]
                assert not any("ManagedTarget" in item[2] or "ExerciseFramework" in item[3]
                               for item in definitions), definitions
                concat_ids = [item[1] for item in definitions if "System.String.Concat(" in item[3]]
                parse_ids = [item[1] for item in definitions if "System.Int32.Parse(" in item[3]]
                read_ids = [item[1] for item in definitions if
                            "System.IO.BufferedStream.Read(uint8[], int32, int32)" in item[3]]
                try_parse_parameters = {item[1]: 1 if "System.Int32.TryParse(string, int32&)" in item[3] else 3
                                        for item in definitions if "System.Int32.TryParse(string, int32&)" in item[3]
                                        or "System.Number.TryParseInt32(" in item[3]}
                assert concat_ids and parse_ids, definitions[:20]
                assert read_ids, definitions[:20]
                assert try_parse_parameters, definitions[:20]
                assert connection.execute("SELECT count(*) FROM calls WHERE flags & 4").fetchone()[0] > 0
                assert connection.execute("SELECT count(DISTINCT tid) FROM calls").fetchone()[0] >= 3
                if instructions:
                    assert connection.execute(
                        "SELECT count(*) FROM calls WHERE api=2 AND ended IS NOT NULL").fetchone()[0] > 0
                    if require_native_ntdll:
                        native_waits = connection.execute("SELECT count(*) FROM calls c JOIN apis a ON a.id=c.api "
                            "AND a.target=c.target WHERE a.module='ntdll.dll' "
                            "AND a.name='NtDelayExecution [syscall]' AND c.ended IS NOT NULL").fetchone()[0]
                        assert native_waits > 0, 'Native CLR execution bypassed the ntdll syscall observer.'
                        wait_calls, wait_sites = connection.execute(
                            "SELECT count(*),count(DISTINCT c.caller) FROM calls c JOIN apis a "
                            "ON a.id=c.api AND a.target=0 WHERE a.name='NtWaitForSingleObject' "
                            "AND c.ended IS NOT NULL").fetchone()
                        assert 20 <= wait_calls < 2000 and wait_sites >= 2, (wait_calls, wait_sites)
                        paired_waits = connection.execute(
                            "SELECT count(*) FROM calls s JOIN apis a ON a.id=s.api AND a.target=s.target "
                            "JOIN calls p ON p.target=s.target AND p.id=s.parent "
                            "JOIN apis b ON b.target=0 AND b.id=p.api "
                            "WHERE a.name='NtWaitForSingleObject [syscall]' "
                            "AND b.name='NtWaitForSingleObject' AND s.ended IS NOT NULL").fetchone()[0]
                        assert paired_waits > 0, 'Translated waits lost their syscall layer.'
                    time_calls = connection.execute("SELECT c.output FROM calls c JOIN apis a "
                        "ON a.id=c.api AND (a.target=0 OR a.target=c.target) "
                        "WHERE a.name IN ('NtQuerySystemTime','NtQuerySystemTime [syscall]') "
                        "AND c.ended IS NOT NULL").fetchall()
                    assert len(time_calls) >= 72, f"Missing native .NET interop calls: {len(time_calls)}"
                    keyboard_calls = connection.execute("SELECT a.name,c.flags,c.output FROM calls c JOIN apis a "
                        "ON a.id=c.api AND a.target=CASE WHEN c.api<1073741824 THEN 0 ELSE c.target END "
                        "WHERE a.name IN ('GetKeyboardState','NtUserGetKeyboardState',"
                        "'NtUserGetKeyboardState [syscall]') "
                        "AND c.ended IS NOT NULL").fetchall()
                    observed = {name for name, _, _ in keyboard_calls}
                    assert sum(name == 'GetKeyboardState' for name, _, _ in keyboard_calls) == 3, keyboard_calls
                    assert sum(name == 'NtUserGetKeyboardState' for name, _, _ in keyboard_calls) == 6, keyboard_calls
                    missing = {'NtUserGetKeyboardState', 'NtUserGetKeyboardState [syscall]'} - observed
                    if strict_native_interop:
                        assert not missing, f"Missing window-system .NET interop calls: {sorted(missing)}"
                        assert sum(name == 'NtUserGetKeyboardState [syscall]' for name, _, _ in keyboard_calls) == 6, \
                            keyboard_calls
                        sites = connection.execute("SELECT c.caller FROM calls c JOIN apis a ON a.id=c.api "
                            "AND a.target=c.target WHERE a.name='NtUserGetKeyboardState [syscall]' "
                            "AND c.ended IS NOT NULL").fetchall()
                        target_base = int(pathlib.Path(str(result_path) + ".native-site").read_text())
                        native_rva, native_code = native_export('win32u.dll', 'NtUserGetKeyboardState',
                            hello['pointerSize'])
                        native_entry = target_base + native_rva
                        assert len(sites) == 6 and len({site for site, in sites}) == 1, sites
                        assert all(native_entry <= site < native_entry + len(native_code) and
                            native_code[site - native_entry] in (0xC3, 0xC2) for site, in sites), \
                            (native_entry, native_code.hex(), sites)
                    elif missing:
                        print(f"GAP: CLR-native window-system layers absent: {', '.join(sorted(missing))}", flush=True)
                    for name, flags, output in keyboard_calls:
                        assert not flags & 256 and output, (name, flags, output)
                        parameter, kind, value_flags, captured, original = struct.unpack_from('<IIIIQ', output)
                        assert parameter == 0 and value_flags & 1 and captured == 64 and original == 256
                    observed_times = [struct.unpack('<q', data)[0] for payload, in time_calls
                                      for parameter, kind, flags, original, data in values(payload)
                                      if parameter == 0 and len(data) == 8 and not flags]
                    assert sum(value >= 132000000000000000 for value in observed_times) >= 72, observed_times
                    assert connection.execute("SELECT count(*) FROM calls c JOIN apis a "
                        "ON a.id=c.api AND a.target=0 WHERE a.name='WinHttpTimeToSystemTime' "
                        "AND c.ended IS NOT NULL AND c.result=1").fetchone()[0] == 36
                receiver_rows = connection.execute("SELECT a.parameters,c.input FROM calls c JOIN apis a "
                    "ON a.id=c.api AND a.target=c.target WHERE a.name LIKE 'System.Guid.ToByteArray(%' "
                    "AND c.ended IS NOT NULL").fetchall()
                assert len(receiver_rows) == 3 and all(
                    'this: System.Guid&' in row[0] for row in receiver_rows), receiver_rows
                expected = bytes.fromhex('33221100554477668899aabbccddeeff')
                for _, payload in receiver_rows:
                    assert (0, 16, expected) in snapshots(payload, 0, 0), snapshots(payload, 0, 0)
                layouts = connection.execute("SELECT l.layout FROM api_layouts l JOIN apis a "
                    "ON a.id=l.api AND a.target=l.target WHERE a.name LIKE 'System.Guid.ToByteArray(%'").fetchall()
                assert layouts, "Missing the loaded value-type receiver layout"
                for descriptor, in layouts:
                    layout = json.loads(descriptor)
                    if 'Types' in layout:
                        layout = layout['Types'][layout['Arguments'][0]]
                    assert layout["Name"] == "System.Guid" and layout["Size"] == 16, layout
                    fields = {field[0]: field[1:] for field in layout["Fields"]}
                    assert fields.get("_a") == ["int32", 0, 4] and fields.get("_b") == ["int16", 4, 2], fields
                    assert fields.get("_c") == ["int16", 6, 2] and len(fields) == 11, fields
                found_input = found_output = False
                mutated_outputs = 0
                parsed_outputs = {}
                for api, input_payload, output_payload in connection.execute(
                        "SELECT api,input,output FROM calls WHERE api>=0x40000000 AND api<0x50000000"):
                    for phase, payload in enumerate((input_payload, output_payload)):
                        for parameter, kind, flags, original, data in values(payload):
                            assert len(data) <= 64, (parameter, len(data))
                            if api in read_ids and phase == 1 and parameter == 1 and data == b"\x6b" * 64:
                                assert flags == 1 and original == 256, (flags, original)
                                mutated_outputs += 1
                            if (api in try_parse_parameters and phase == 1 and
                                    parameter == try_parse_parameters[api] and
                                    data == struct.pack("<i", 654321)):
                                assert not flags and original == 4, (flags, original)
                                parsed_outputs[api] = parsed_outputs.get(api, 0) + 1
                            if api in concat_ids and kind == 1 and data.startswith("dddd".encode("utf-16-le")):
                                assert flags & 1 and original >= 192, (flags, original)
                                if phase == 0:
                                    found_input = True
                                else:
                                    found_output = True
                assert found_input and found_output, (found_input, found_output)
                assert mutated_outputs == 36, f"Missing outputs across managed GC: {mutated_outputs}"
                assert 36 in parsed_outputs.values(), f"Missing by-reference scalar outputs: {parsed_outputs}"
            calls = collector.call("page", database=database, api="System.String.Concat", limit=10)["calls"]
            assert calls, status
            assert all(0 <= call["adjustedDurationUs"] <= call["durationUs"] for call in calls), calls
            detail = collector.call("details", database=database, target=calls[0]["target"], callId=calls[0]["id"])
            assert "System.String.Concat" in detail["name"] and "INPUT" in detail["text"]
        except Exception:
            # Release only this test's target when an observer failure prevents normal fixture exit.
            try:
                targets = collector.call("page", database=database, limit=1)["targets"]
                for target in targets:
                    if target["state"] == "Capturing":
                        os.kill(target["pid"], signal.SIGTERM)
            except (OSError, RuntimeError):
                pass
            raise
        finally:
            collector.close()
        profiler = result_path.with_suffix(".txt.profiler").read_text()
        assert profiler.startswith("{") and profiler.endswith("}"), profiler
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\Classes\\CLSID\\" + profiler,
                                access=winreg.KEY_READ | (
                                    winreg.KEY_WOW64_64KEY if hello['pointerSize'] == 8 else winreg.KEY_WOW64_32KEY)):
                raise AssertionError("Profiler activation was not released after capture")
        except FileNotFoundError:
            pass
        print(f"Managed capture passed: {target_path.name} ({status['calls']} calls)")


def verify_native_boundaries(connection, expected):
    rows = connection.execute("SELECT a.name,c.id,c.parent,c.arguments,c.output,c.flags FROM calls c "
        "JOIN apis a ON a.id=c.api AND a.target=CASE WHEN c.api<1073741824 THEN 0 ELSE c.target END "
        "WHERE a.name IN ('NtUserGetKeyboardState','NtUserGetKeyboardState [syscall]') "
        "AND c.ended IS NOT NULL").fetchall()
    native = [row for row in rows if row[0] == 'NtUserGetKeyboardState']
    syscalls = [row for row in rows if row[0] == 'NtUserGetKeyboardState [syscall]']
    assert len(native) == len(syscalls) == expected, rows
    for row in native:
        assert not row[5] & 256 and row[4], row
        parameter, kind, flags, captured, size = struct.unpack_from('<IIIIQ', row[4])
        assert (parameter, flags, captured, size) == (0, 1, 64, 256), row
        child = next(item for item in syscalls if item[2] == row[1])
        assert row[3:5] == child[3:5], (row, child)
    print(f'Cached native boundaries: {expected} typed API/syscall pairs passed.', flush=True)


def check_attach(collector_path, target_path, instructions=False, requires_launch=False, deferred=False,
        debugger=False, host=None, runtime=None, inspector=None, native_entries=False, native_boundaries=False):
    with tempfile.TemporaryDirectory(prefix="Detourist-Managed-Attach-") as directory:
        root = pathlib.Path(directory)
        result = root / "result.txt"
        database = str(root / "attached.db")
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("COR_", "CORECLR_"))}
        mode = "--attach-smoke" if debugger else "--attach"
        command = [str(target_path), str(result), mode]
        if host:
            command = [str(host), str(runtime), *command]
        target = subprocess.Popen(command, env=environment,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
        collector = Collector(collector_path)
        try:
            wait_file(result.with_suffix(".txt.ready"), target)
            hello = collector.call("hello")
            mask = int(hello["managedMask"]) | (((1 << 2) | (1 << 18)) if requires_launch else 0)
            if native_entries: mask |= (1 << 19) | (1 << 22)
            if native_boundaries: mask |= 1 << 22
            # Debugger attach stops at every method of each enabled category, so record only the asserted ones.
            categories = {item["name"]: int(item["mask"]) for item in hello["categories"]}
            scope = {"categoryMask": str(categories["Text"] | categories["Files and storage"] |
                                         categories["Data and collections"])} if debugger else {}
            collector.call("attach", database=database, pid=target.pid, bufferLimit=64,
                           apiMask=str(0 if deferred else mask), followChildren=False,
                           instructionEngine=instructions, **scope)
            initial = collector.wait(lambda value: value["capturing"] or value["finished"])
            assert initial["capturing"], initial
            if deferred:
                page = collector.call("page", database=database, limit=1)
                assert page["targets"][0]["managedState"] == 0, page
                collector.call("filters", apiMask=str(mask))
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                page = collector.call("page", database=database, limit=1)
                if page["targets"] and page["targets"][0]["managedState"] in (1, 2):
                    break
                assert target.poll() is None, (target.returncode, target.stderr.read().decode(errors="replace"))
                time.sleep(0.02)
            if requires_launch:
                assert page["targets"][0]["managedState"] == 2, page
                result.with_suffix(".txt.go").touch()
                wait_file(result, target)
                assert result.read_text() == "managed-ok", result.read_text()
                collector.call("stop")
                collector.wait(lambda value: value["finished"])
                assert target.poll() is None, "Stopping capture terminated the attached process"
                with open_trace(database) as connection:
                    diagnostics = connection.execute("SELECT message FROM diagnostics").fetchall()
                    assert any("requires tracing from launch" in message for message, in diagnostics), diagnostics
                    assert not connection.execute("SELECT count(*) FROM apis WHERE id>=0x40000000").fetchone()[0]
                    native_calls = connection.execute("SELECT count(*) FROM calls c JOIN apis a "
                        "ON a.id=c.api AND (a.target=0 OR a.target=c.target) "
                        "WHERE a.name IN ('NtQuerySystemTime','NtQuerySystemTime [syscall]') "
                        "AND c.ended IS NOT NULL").fetchone()[0]
                    assert native_calls >= 72, f"Managed attach failure interrupted native tracing: {native_calls}"
                result.with_suffix(".txt.release").touch()
                assert target.wait(timeout=30) == 0, target.stderr.read().decode(errors="replace")
                print(f"Managed attach limitation preserves native capture: {target_path.parent.name}")
                return
            if not page["targets"] or page["targets"][0]["managedState"] != 1:
                time.sleep(0.2)
                raise AssertionError(collector.call("page", database=database, limit=1))
            result.with_suffix(".txt.go").touch()
            wait_file(result, target, timeout=300 if debugger else 60)
            assert result.read_text() == "managed-ok", result.read_text()
            collector.call("stop")
            status = collector.wait(lambda value: value["finished"])
            assert target.poll() is None, "Stopping capture terminated the attached process"
            assert status["calls"] > 0, status
            page = collector.call("page", database=database, limit=1)
            with open_trace(database) as connection:
                if native_entries:
                    calls = connection.execute("SELECT a.name,c.flags,c.output FROM calls c JOIN apis a "
                        "ON a.id=c.api AND a.target=CASE WHEN c.api<1073741824 THEN 0 ELSE c.target END "
                        "WHERE a.name IN ('GetKeyboardState','NtUserGetKeyboardState') "
                        "AND c.ended IS NOT NULL").fetchall()
                    counts = {name: sum(call[0] == name for call in calls)
                        for name in ('GetKeyboardState', 'NtUserGetKeyboardState')}
                    for name, flags, payload in calls:
                        assert not flags & 256 and payload, (name, flags, payload)
                        parameter, kind, flags, captured, original = struct.unpack_from('<IIIIQ', payload)
                        assert parameter == 0 and flags & 1 and captured == 64 and original == 256, name
                    print('Cached native interop entries:', counts, flush=True)
                    assert counts == {'GetKeyboardState': 3, 'NtUserGetKeyboardState': 6}, counts
                if native_boundaries:
                    verify_native_boundaries(connection, 6)
                definitions = connection.execute("SELECT id,module,name FROM apis WHERE target<>0").fetchall()
                assert not any("ManagedTarget" in module for _, module, _ in definitions), definitions[:20]
                concat = {api for api, _, name in definitions if "System.String.Concat(" in name}
                read = {api for api, _, name in definitions if
                        "System.IO.BufferedStream.Read(uint8[], int32, int32)" in name}
                parse = {api: 3 if "System.Number.TryParseInt32(" in name else 1
                         for api, _, name in definitions if "System.Int32.TryParse(string, int32&)" in name or
                         (debugger and "System.Number.TryParseInt32(" in name)}
                resize = {api for api, _, name in definitions if "System.Array.Resize(!!0[]&, int32)" in name}
                encoding = {api for api, _, name in definitions if ".GetBytes(string)" in name}
                numbers = {api for api, _, name in definitions if
                           ("System.Number.ParseInt32(" in name if debugger else
                            "System.Int32.Parse(string, System.IFormatProvider)" in name)}
                vectors = {api for api, _, name in definitions if "System.Runtime.Intrinsics.Vector256.Add(" in name}
                assert concat and read and parse and resize and encoding and numbers, definitions[:20]
                assert connection.execute("SELECT count(DISTINCT tid) FROM calls").fetchone()[0] >= 3
                assert connection.execute("SELECT count(*) FROM calls WHERE flags & 4").fetchone()[0] > 0
                if not debugger:
                    receivers = connection.execute("SELECT l.layout,c.input FROM calls c JOIN apis a "
                        "ON a.id=c.api AND a.target=c.target LEFT JOIN api_layouts l "
                        "ON l.api=c.api AND l.target=c.target WHERE a.name LIKE 'System.Guid.ToByteArray(%' "
                        "AND c.ended IS NOT NULL").fetchall()
                    assert len(receivers) == 3, receivers
                    for descriptor, payload in receivers:
                        assert descriptor, "An attached receiver lost its runtime field layout"
                        layout = json.loads(descriptor)
                        if 'Types' in layout:
                            layout = layout['Types'][layout['Arguments'][0]]
                        assert layout["Name"] == "System.Guid" and layout["Size"] == 16, layout
                        assert len(layout["Fields"]) == 11, layout
                    registered = connection.execute("SELECT count(*) FROM apis WHERE target<>0 "
                        "AND id>=0x40000000 AND id<0x50000000").fetchone()[0]
                    assert page["targets"][0]["managedApis"] == registered, (page["targets"],registered)
                inputs = outputs = mutations = resized = moved_addresses = 0
                returned_buffers = {api: 0 for api in encoding}
                returned_numbers = {api: 0 for api in numbers}
                returned_vectors = {api: 0 for api in vectors}
                parsed = {api: 0 for api in parse}
                for api, entry, exit in connection.execute("SELECT api,input,output FROM calls"):
                    buffer_addresses = [None, None]
                    for phase, payload in enumerate((entry, exit)):
                        for parameter, kind, flags, original, data in values(payload):
                            if kind == 12:
                                stride, count = original >> 32, original & 0xFFFFFFFF
                                assert stride > 0 or count == 0, (stride, count)
                                original = stride * count
                            assert len(data) <= 64, len(data)
                            if debugger and not host and api in read and parameter == 1 and kind == 2:
                                assert not flags and original == len(data) == hello["pointerSize"], (
                                    flags, original, len(data))
                                buffer_addresses[phase] = int.from_bytes(data, "little")
                            if api in concat and kind == 1 and data.startswith("dddd".encode("utf-16-le")):
                                assert flags == 1 and original >= 192, (flags, original)
                                inputs += phase == 0
                                outputs += phase == 1
                            if api in read and phase == 1 and parameter == 1 and data == b"\x6b" * 64:
                                assert flags == 1 and original == 256, (flags, original)
                                mutations += 1
                            if api in parse and phase == 1 and parameter == parse[api] and \
                                    data == struct.pack("<i", 654321):
                                assert not flags and original == 4, (flags, original)
                                parsed[api] += 1
                            if api in resize and phase == 1 and parameter == 0 and data == b"\x37" * 64:
                                assert flags == 1 and original == 512, (flags, original)
                                resized += 1
                            if phase == 1 and parameter == 0xFFFFFFFF:
                                if api in encoding and kind in (0, 12) and data == b"d" * 64:
                                    assert flags == 1 and original == 104, (flags, original)
                                    returned_buffers[api] += 1
                                if api in numbers and kind == 2 and data == struct.pack("<i", 123456):
                                    assert not flags and original == 4, (flags, original)
                                    returned_numbers[api] += 1
                                if api in vectors and kind == 0 and len(data) == 32:
                                    vector = struct.unpack("<dddd", data)
                                    assert not flags and original == 32 and vector[1:] == (4.5, 5.75, 7.0), vector
                                    assert vector[0] in {3.25 + index for index in range(12)}, vector
                                    returned_vectors[api] += 1
                    if debugger and not host and api in read:
                        assert all(buffer_addresses), ("Missing retained buffer address", buffer_addresses)
                        moved_addresses += buffer_addresses[0] != buffer_addresses[1]
                assert inputs and outputs, (inputs, outputs)
                expected = 3 if debugger else 36
                assert mutations == expected, f"Attached output capture missed moved buffers: {mutations}"
                if debugger and not host:
                    assert moved_addresses > 0, "Retained array references did not follow garbage collection"
                captured_parses = {api: count for api, count in parsed.items() if count}
                assert captured_parses and all(count == expected for count in captured_parses.values()), \
                    f"Attached output capture missed by-reference scalars: {parsed}"
                assert resized == expected, f"Attached output capture missed replaced generic arrays: {resized}"
                assert expected in returned_buffers.values(), \
                    f"Attached array returns were not captured: {returned_buffers}"
                assert expected in returned_numbers.values(), \
                    f"Attached scalar returns were not captured: {returned_numbers}"
                if not debugger:
                    assert returned_vectors and all(count == expected for count in returned_vectors.values()), \
                        f"Attached generic value-type returns were not captured: {returned_vectors}"

            if inspector:
                patterns = {
                    "vector": "System.Runtime.Intrinsics.Vector256.Add(",
                    "scalar": "System.Int32.TryParse(string, int32&)",
                    "floating": "System.Double.Parse(string, System.IFormatProvider)",
                    "buffer": "System.Text.Encoding.GetBytes(string)",
                    "receiver": "System.Guid.ToByteArray("
                }
                details = {}
                with open_trace(database) as connection:
                    for key, pattern in patterns.items():
                        target_id, call_id = connection.execute(
                            "SELECT c.target,c.id FROM calls c JOIN apis a ON a.id=c.api AND a.target=c.target "
                            "WHERE a.name LIKE ? AND c.ended IS NOT NULL ORDER BY c.id LIMIT 1",
                            (pattern + "%",)).fetchone()
                        details[key] = collector.call("details", database=database, target=target_id, callId=call_id)
                details_path = root / "managed-details.json"
                details_path.write_text(json.dumps(details), encoding="utf-8")
                verified = subprocess.run(["dotnet", str(inspector), "--managed", str(details_path)],
                    capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                assert verified.returncode == 0, verified.stdout + verified.stderr
                receiver_path = root / "receiver-detail.json"
                receiver_path.write_text(json.dumps(details["receiver"]), encoding="utf-8")
                verified = subprocess.run(["dotnet", str(inspector), "--managed-layout", str(receiver_path)],
                    capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                assert verified.returncode == 0, verified.stdout + verified.stderr

            # A second session must become ready before releasing a fresh framework call.
            second = str(root / "reattached.db")
            collector.call("attach", database=second, pid=target.pid, bufferLimit=64,
                           apiMask=str(mask), followChildren=False,
                           instructionEngine=instructions, **scope)
            second_status = collector.wait(lambda value: value["capturing"] or value["finished"])
            assert second_status["capturing"], second_status
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                page = collector.call("page", database=second, limit=1)
                if page["targets"] and page["targets"][0]["managedState"] in (1, 2):
                    break
                assert target.poll() is None, target.returncode
                time.sleep(0.02)
            assert page["targets"][0]["managedState"] == 1, page
            result.with_suffix(".txt.release").touch()
            code = target.wait(timeout=300 if debugger else 30)
            assert code == 0, (code, target.stderr.read().decode(errors="replace"))
            collector.wait(lambda value: value["finished"])
            page = collector.call("page", database=second, limit=10)
            assert page["targets"][0]["managedState"] == 1 and page["targets"][0]["managedApis"] > 0, page
            assert any(call["api"] >= 0x40000000 for call in page["calls"]), page["calls"]
            if not debugger:
                with open_trace(second) as connection:
                    receiver = connection.execute("SELECT l.layout,c.target,c.id FROM calls c JOIN apis a "
                        "ON a.id=c.api AND a.target=c.target LEFT JOIN api_layouts l "
                        "ON l.api=c.api AND l.target=c.target WHERE a.name LIKE 'System.Guid.ToByteArray(%' "
                        "AND c.ended IS NOT NULL").fetchall()
                    if native_boundaries:
                        verify_native_boundaries(connection, 2)
                    assert len(receiver) == 1 and receiver[0][0], "Reattachment lost the receiver layout"
                    layout = json.loads(receiver[0][0])
                    if 'Types' in layout:
                        layout = layout['Types'][layout['Arguments'][0]]
                    assert layout["Size"] == 16, receiver
                    registered = connection.execute("SELECT count(*) FROM apis WHERE target<>0 "
                        "AND id>=0x40000000 AND id<0x50000000").fetchone()[0]
                    assert page["targets"][0]["managedApis"] == registered, (page["targets"],registered)
                if inspector:
                    detail = collector.call("details", database=second, target=receiver[0][1], callId=receiver[0][2])
                    receiver_path = root / "reattached-receiver-detail.json"
                    receiver_path.write_text(json.dumps(detail), encoding="utf-8")
                    verified = subprocess.run(["dotnet", str(inspector), "--managed-layout", str(receiver_path)],
                        capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    assert verified.returncode == 0, verified.stdout + verified.stderr
            print(f"Managed attach passed: {target_path.parent.name} ({status['calls']} calls)")
        except Exception:
            if pathlib.Path(database).exists():
                with open_trace(database) as connection:
                    print("Attach diagnostics:", connection.execute("SELECT message FROM diagnostics").fetchall())
            if target.poll() is None:
                target.kill()
                target.wait(timeout=10)
            print(target.stderr.read().decode(errors="replace"))
            raise
        finally:
            if target.poll() is None:
                target.kill()
                target.wait(timeout=10)
            collector.close()


def check_debugger_filters(collector_path, target_path):
    with tempfile.TemporaryDirectory(prefix='Detourist-Framework-Filter-') as temporary:
        result = pathlib.Path(temporary) / 'result.txt'
        database = pathlib.Path(temporary) / 'capture.db'
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('COR_', 'CORECLR_'))}
        target = subprocess.Popen([str(target_path), str(result), '--attach-smoke'], env=environment,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
        collector = Collector(collector_path)
        try:
            wait_file(result.with_suffix('.txt.ready'), target)
            hello = collector.call('hello')
            collector.call('attach', database=str(database), pid=target.pid, bufferLimit=64,
                           apiMask=str(hello['managedMask']), followChildren=False)
            collector.wait(lambda value: value['capturing'] or value['finished'])
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                page = collector.call('page', database=str(database), limit=1)
                if page['targets'] and page['targets'][0]['managedState'] == 1:
                    break
                time.sleep(0.05)
            assert page['targets'][0]['managedState'] == 1, page['targets']

            # Disabled recording must let an attached Framework process execute promptly.
            collector.call('filters', apiMask='0')
            result.with_suffix('.txt.go').touch()
            wait_file(result, target, timeout=40)
            assert result.read_text() == 'managed-ok'
            collector.call('stop')
            collector.wait(lambda value: value['finished'])
            with open_trace(database) as connection:
                assert connection.execute('SELECT count(*) FROM calls').fetchone()[0] == 0
            result.with_suffix('.txt.release').touch()
            assert target.wait(timeout=30) == 0, target.stderr.read().decode(errors='replace')
            print('PASS: disabled Framework capture bypasses breakpoint inspection and detaches cleanly.')
        finally:
            if target.poll() is None:
                result.with_suffix('.txt.release').touch()
                target.kill()
                target.wait()
            collector.close()


def service_numbers(collector_path, names):
    image = collector_path.read_bytes()
    header = struct.unpack_from('<I', image, 0x3C)[0]
    pointer_size = 4 if struct.unpack_from('<H', image, header + 4)[0] == 0x14C else 8
    result = []
    for name in names:
        _, code = native_export('ntdll.dll', name, pointer_size, 8)
        assert code[0] == 0xB8 if pointer_size == 4 else code[:4] == bytes.fromhex('4c8bd1b8'), code.hex()
        result.append(struct.unpack_from('<I', code, 1 if pointer_size == 4 else 4)[0])
    return result


def check_private_syscalls(collector_path, target_path, launch, lifecycle=False, artifact=None, legacy_gate=False):
    # Read service numbers before the collector can hook the target's ntdll exports.
    numbers = service_numbers(collector_path, ('NtDelayExecution', 'NtQueryVirtualMemory'))
    context = nullcontext(str(artifact)) if artifact else tempfile.TemporaryDirectory(
        prefix='Detourist-Managed-Private-Syscall-')
    with context as temporary:
        root = Path(temporary)
        root.mkdir(parents=True, exist_ok=True)
        result = root / 'result.txt'
        databases = [root / 'calls.db']
        mode = '--private-syscall-fs' if legacy_gate else '--private-syscall'
        arguments = f'"{result}" --private-gateways {numbers[0]} {numbers[1]}' if lifecycle else (
            f'"{result}" {mode} {numbers[0]}')
        command = [str(target_path), str(result), mode, str(numbers[0])]
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('COR_', 'CORECLR_'))}
        target = None if launch else subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
        collector = Collector(collector_path)
        process = None
        try:
            hello = collector.call('hello')
            options = dict(bufferLimit=64, apiMask=hello['syscallMask'], instructionEngine=True,
                followChildren=False)
            if launch:
                collector.call('launch', database=str(databases[0]), executable=str(target_path),
                    arguments=arguments, startMinimized=True, **options)
            else:
                process = kernel32.OpenProcess(0x101001, False, target.pid)
                assert process
                wait_for(Path(str(result) + '.ready'), process)
                collector.call('attach', database=str(databases[0]), pid=target.pid, **options)
            status = collector.wait(lambda value: value['capturing'] or value['finished'])
            assert status['capturing'], status
            pid = collector.call('page', database=str(databases[0]), limit=1)['targets'][0]['pid']
            if process is None:
                process = kernel32.OpenProcess(0x101001, False, pid)
                assert process
            wait_for(Path(str(result) + '.ready'), process)
            page = int(Path(str(result) + '.ready').read_text())
            if lifecycle:
                for phase in range(5):
                    if phase in (1, 3):
                        collector.call('stop')
                        collector.wait(lambda value: value['finished'])
                    elif phase in (2, 4):
                        databases.append(root / f'calls-{phase}.db')
                        collector.call('attach', database=str(databases[-1]), pid=pid, **options)
                        status = collector.wait(lambda value: value['capturing'] or value['finished'])
                        assert status['capturing'], status
                    Path(str(result) + f'.go{phase}').touch()
                    if phase == 4:
                        wait_for(Path(str(result) + '.busy'), process)
                        collector.call('stop')
                        collector.wait(lambda value: value['finished'])
                        Path(str(result) + '.finish').touch()
                    output = Path(str(result) + f'.phase{phase}')
                    wait_for(output, process)
                    expected = '0|True' if phase in (0, 2) else '0|False'
                    assert output.read_text() == expected, (phase, output.read_text())
            else:
                Path(str(result) + '.go').touch()
                wait_for(result, process)
                assert result.read_text() == '0', result.read_text()
                collector.call('stop')
                collector.wait(lambda value: value['finished'])
            Path(str(result) + '.release').touch()
            assert kernel32.WaitForSingleObject(process, 15000) == 0, 'Target did not exit after detach'
            assert exit_code(process) == 0, f'Target exit: {exit_code(process):#x}'
            for index, database in enumerate(databases):
                with open_trace(database) as connection:
                    observed = connection.execute('SELECT a.name,c.caller,c.result FROM calls c '
                        'JOIN apis a ON a.id=c.api AND (a.target=0 OR a.target=c.target) '
                        'WHERE c.caller>=? AND c.caller<? ORDER BY c.id', (page, page + 4096)).fetchall()
                expected_names = ('NtDelayExecution [syscall]', 'NtQueryVirtualMemory [syscall]') if lifecycle else (
                    'NtDelayExecution [syscall]',)
                assert all(name in expected_names and value == 0 for name, _, value in observed), observed
                counts = {name: sum(item[0] == name for item in observed) for name in expected_names}
                expected_count = 12 if lifecycle else 3
                assert all(value >= 4 if lifecycle and index == 2 else value == expected_count
                    for value in counts.values()), (database.name, counts)
        finally:
            if process:
                if kernel32.WaitForSingleObject(process, 0) != 0:
                    kernel32.TerminateProcess(process, 1)
                    kernel32.WaitForSingleObject(process, 5000)
                kernel32.CloseHandle(process)
            if target is not None:
                if target.poll() is None: target.kill()
                target.wait()
            collector.close()
    print(f'Managed private syscalls: {target_path.parent.name}, ' + (
        'cached delegates, stack arguments, callback identity and three capture sessions passed.' if lifecycle else
        'captured three direct calls.'))


def check_raw_native(collector_path, target_path, artifact=None, baseline=False,
        host=None, runtime=None, breakpoints=False):
    context = nullcontext(str(artifact)) if artifact else tempfile.TemporaryDirectory(prefix='Detourist-Raw-Native-')
    names = ('NtUserGetAsyncKeyState', 'NtUserGetKeyState', 'NtGdiGetBitmapBits',
             'IsWindowRedirectedForPrint')
    typed_names = names[:3]
    headerless_name = names[3]
    with context as directory:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        results = []
        with Collector(collector_path) as collector:
            hello = collector.call('hello')
            catalog = {item['name']: item for item in hello['catalog']}
            assert all(name in catalog and catalog[name]['argumentCount'] > 0 for name in typed_names)
            catalog_path = os.environ.get('DETOURIST_API_CATALOG', collector_path.parent / 'ApiCatalog.sqlite')
            with closing(sqlite3.connect(catalog_path)) as definitions:
                assert definitions.execute('SELECT 1 FROM functions f JOIN builtin_apis b ON b.function_id=f.id '
                    'WHERE f.module=? AND f.name=?', ('user32.dll', headerless_name)).fetchone()
            mask = str(int(hello['win32uMask']) | (1 << 19))
            # Runtime background threads can enter unbounded waits mid-capture, so record only the probed categories.
            categories = str(sum({int(hello['categories'][catalog[name]['category']]['mask']) for name in names}))
            for limit in (16, 64):
                output = root / f'raw-{limit}.txt'
                database = root / f'raw-{limit}.db'
                assert not database.exists()
                command = [str(target_path), str(output), '--raw-native']
                if host:
                    command = [str(host), str(runtime), *command]
                environment = {key: value for key, value in os.environ.items()
                               if not key.startswith(('COR_', 'CORECLR_'))}
                target = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
                try:
                    wait_file(Path(str(output) + '.ready'), target)
                    collector.call('attach', database=str(database), pid=target.pid, bufferLimit=limit,
                        apiMask=mask, categoryMask=categories, instructionEngine=True, followChildren=False)
                    state = collector.wait(lambda item: item['capturing'] or item['finished'])
                    assert state['capturing'], state
                    Path(str(output) + '.go').touch()
                    wait_file(Path(str(output) + '.first'), target)
                    # A layer-specific exclusion must preserve the export call in the next native invocation.
                    if breakpoints:
                        deadline = time.monotonic() + 15
                        while True:
                            page = collector.call('page', database=str(database), api=names[2], limit=10)
                            found = [call['api'] for call in page['calls'] if call['name'] == names[2]]
                            if found: break
                            assert time.monotonic() < deadline, page
                            time.sleep(0.02)
                        api = found[0]
                        collector.call('breakApi', entryApi=api, exitApi=-1)
                    collector.call('filters', apiMask='0' if breakpoints else mask, categoryMask=categories,
                                   excludedApis=[name + ' [syscall]' for name in typed_names])
                    time.sleep(0.1)
                    Path(str(output) + '.again').touch()
                    if breakpoints:
                        stopped = collector.wait(lambda item: item['breakpoint'] or item['finished'])
                        assert stopped['breakpoint'] and not stopped['leaving'], stopped
                        call = stopped['stoppedCall']
                        assert call['name'] == names[2] and call['api'] == api and len(call['arguments']) == 3, call
                        assert 'Capacity' in call['parameters'] and not call['flags'] & 256, call
                        collector.call('breakApi', entryApi=-1, exitApi=api)
                        collector.call('continue', callId=call['id'])
                        stopped = collector.wait(
                            lambda item: item['finished'] or item['breakpoint'] and item['leaving'])
                        assert (stopped['breakpoint'] and stopped['leaving'] and
                                stopped['stoppedCall']['id'] == call['id']), stopped
                        assert int(stopped['stoppedCall']['result'], 16) & 0xFFFFFFFF == 128, stopped
                        collector.call('breakApi', entryApi=-1, exitApi=-1)
                        collector.call('continue', callId=call['id'])
                    wait_file(Path(str(output) + '.second'), target)
                    collector.call('stop')
                    collector.wait(lambda item: item['finished'])
                    Path(str(output) + '.release').touch()
                    assert target.wait(timeout=15) == 0, target.stderr.read().decode(errors='replace')
                    with open_trace(database, named=True) as connection:
                        rows = connection.execute('SELECT c.*,coalesce(d.name,a.name) name, '
                            'coalesce(d.parameters,a.parameters) parameters,'
                            'coalesce(d.argument_count,a.argument_count) count '
                            'FROM calls c LEFT JOIN apis d ON d.id=c.api AND d.target=c.target '
                            'LEFT JOIN apis a ON a.id=c.api AND a.target=0 ORDER BY c.started').fetchall()
                        selected = {name: [row for row in rows if row['name'] == name] for name in names}
                        syscalls = {name: [row for row in rows if row['name'] == name + ' [syscall]']
                                    for name in typed_names}
                        evidence = {'limit': limit, 'native': {name: len(found) for name, found in selected.items()},
                                    'syscalls': {name: len(found) for name, found in syscalls.items()}}
                        results.append(evidence)
                        (root / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
                        if not baseline:
                            assert all(len(found) == (1 if breakpoints else 2)
                                       for found in selected.values()), evidence
                            assert all(len(found) == 1 for found in syscalls.values()), evidence
                            for name, found in selected.items():
                                assert all(row['ended'] and not row['flags'] & 256 and
                                           row['count'] == (3 if name == names[2] else 1) and
                                           'Raw' not in row['parameters'] for row in found), (name, found)
                                if name == headerless_name:
                                    assert all('hWnd' in row['parameters'] for row in found), found
                                for row in found:
                                    check_limit((row['input'], row['output']), limit)
                                if name.endswith('GetBitmapBits'):
                                    pattern = base64.b64decode(Path(str(output) + '.first').read_text().split('|')[2])
                                    assert snapshots(row['output'], 2, 0)[0][2] == pattern[:limit]
                            for name, found in syscalls.items():
                                assert found[0]['parent'] == selected[name][0]['id'], name
                        diagnostics = [row[0] for row in connection.execute('SELECT message FROM diagnostics')]
                        assert not diagnostics, diagnostics
                    print(f'Raw native boundaries: limit={limit}, native={evidence["native"]} passed.', flush=True)
                finally:
                    if target.poll() is None:
                        collector.call('stop')
                        target.kill()
                        target.wait(timeout=10)
                        collector.wait(lambda item: item['finished'])


def check_native_boundaries(collector_path, target_path, artifact=None, cases=None, host=None, runtime=None):
    context = (nullcontext(str(artifact)) if artifact else
               tempfile.TemporaryDirectory(prefix='Detourist-Native-Control-'))
    with context as directory:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        collector = Collector(collector_path)
        results = []
        sentinel = bytes([0xCD]) * 256
        try:
            hello = collector.call('hello')
            api = next(item for item in hello['catalog'] if item['name'] == 'NtUserGetKeyboardState')
            category = next(item for item in hello['categories'] if item['id'] == api['category'])
            modes = cases or ['normal', 'exclude-syscall', 'exclude-native', 'category-excluded',
                             'masked-break', 'excluded-break', 'argument-edit', 'return-edit', 'skip']
            for mode in modes:
                for limit in (16, 64):
                    result = root / f'{mode}-{limit}.txt'
                    database = root / f'{mode}-{limit}.db'
                    assert not result.exists() and not database.exists()
                    environment = {key: value for key, value in os.environ.items()
                                   if not key.startswith(('COR_', 'CORECLR_'))}
                    command = [str(target_path), str(result), '--native-boundary']
                    if host:
                        command = [str(host), str(runtime), *command]
                    target = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
                    try:
                        wait_file(Path(str(result) + '.ready'), target)
                        alternate = int(Path(str(result) + '.ready').read_text())
                        options = dict(apiMask='0' if mode == 'masked-break' else hello['win32uMask'],
                            categoryMask=str(int(hello['allCategories']) & ~int(category['mask']))
                                if mode == 'category-excluded' else hello['allCategories'],
                            excludedApis=['NtUserGetKeyboardState [syscall]'] if mode == 'exclude-syscall' else
                                [api['name']] if mode in ('exclude-native', 'excluded-break') else [],
                            entryApi=api['id'] if mode in (
                                'masked-break', 'excluded-break', 'argument-edit', 'skip') else -1,
                            exitApi=api['id'] if mode == 'return-edit' else -1)
                        collector.call('attach', database=str(database), pid=target.pid, bufferLimit=limit,
                            followChildren=False, instructionEngine=True, **options)
                        state = collector.wait(lambda item: item['capturing'] or item['finished'])
                        assert state['capturing'], (mode, state, target.poll(),
                            target.stderr.read().decode(errors='replace') if target.poll() is not None else '')
                        Path(str(result) + '.go').touch()
                        if options['entryApi'] >= 0 or options['exitApi'] >= 0:
                            stopped = collector.wait(
                                lambda item: item['breakpoint'] or item['finished'] or result.exists(), timeout=10)
                            assert stopped['breakpoint'], (mode, stopped)
                            call = stopped['stoppedCall']
                            assert call['name'] == api['name'] and call['api'] == api['id'], call
                            assert stopped['leaving'] == (mode == 'return-edit'), stopped
                            assert len(call['arguments']) == 1, call
                            collector.call('breakApi', entryApi=-1, exitApi=-1)
                            changed = {}
                            if mode == 'argument-edit':
                                changed['arguments'] = [str(alternate)]
                            elif mode == 'return-edit':
                                changed.update(result='0', error=0x1234)
                            elif mode == 'skip':
                                changed.update(skip=True, result='1', error=0x1234)
                            collector.call('continue', callId=call['id'], **changed)
                        wait_file(result, target, timeout=15)
                        returned, error, original, modified = result.read_text().split('|')
                        original, modified = base64.b64decode(original), base64.b64decode(modified)
                        assert returned == ('0' if mode == 'return-edit' else '1'), (mode, returned)
                        if mode in ('return-edit', 'skip'):
                            assert int(error) == 0x1234, (mode, error)
                        if mode in ('argument-edit', 'skip'):
                            assert original == sentinel, mode
                        else:
                            assert original != sentinel, mode
                        assert (modified != sentinel) == (mode == 'argument-edit'), mode
                        Path(str(result) + '.release').touch()
                        assert target.wait(timeout=15) == 0, target.stderr.read().decode(errors='replace')
                        collector.wait(lambda item: item['finished'])
                        if mode == 'normal':
                            page = collector.call('page', database=str(database), limit=100)
                            (root / f'menu-{limit}.json').write_text(
                                json.dumps(page['calls'], indent=2), encoding='utf-8')
                        with open_trace(database, named=True) as connection:
                            rows = connection.execute('SELECT c.*,coalesce(d.name,a.name) name FROM calls c '
                                'LEFT JOIN apis d ON d.id=c.api AND d.target=c.target '
                                'LEFT JOIN apis a ON a.id=c.api AND a.target=0 '
                                "WHERE coalesce(d.name,a.name) IN ('NtUserGetKeyboardState',"
                                "'NtUserGetKeyboardState [syscall]') ORDER BY c.started").fetchall()
                            native = [row for row in rows if row['name'] == api['name']]
                            syscalls = [row for row in rows if row['name'].endswith('[syscall]')]
                            expected_native = 0 if mode in ('exclude-native', 'excluded-break', 'masked-break',
                                                            'category-excluded') else 1
                            expected_syscalls = 0 if mode in ('exclude-syscall', 'exclude-native', 'excluded-break',
                                                               'masked-break', 'category-excluded', 'skip') else 1
                            assert len(native) == expected_native and len(syscalls) == expected_syscalls, (mode, rows)
                            assert all(row['ended'] and not row['flags'] & 256 for row in rows), mode
                            if native and mode in ('argument-edit', 'return-edit', 'skip'):
                                assert native[0]['flags'] & 16, 'The edited native call lost its edit marker.'
                            if native and mode == 'return-edit':
                                assert native[0]['result'] == 0 and native[0]['error'] == 0x1234, mode
                            if native and mode == 'skip':
                                assert native[0]['flags'] & 2, 'The native call lost its skip marker.'
                            if native and mode != 'return-edit':
                                wanted = modified if mode == 'argument-edit' else original
                                assert snapshots(native[0]['output'], 0, 2) == [(1, 256, wanted[:limit])], mode
                            if native and syscalls:
                                assert syscalls[0]['parent'] == native[0]['id'], mode
                            elif syscalls:
                                assert syscalls[0]['parent'] == 0, (
                                    'An omitted native call must not leave a phantom parent.')
                            assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
                            results.append({'mode': mode, 'limit': limit, 'native': len(native),
                                            'syscalls': len(syscalls), 'returned': int(returned), 'error': int(error)})
                        print(f'Native controls: {mode}, limit={limit} passed.', flush=True)
                    finally:
                        if target.poll() is None:
                            collector.call('stop')
                            target.kill()
                            target.wait(timeout=10)
                            collector.wait(lambda item: item['finished'])
            (root / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
        finally:
            collector.close()


def main_launch():
    parser = path_parser('collector', 'target')
    parser.add_argument("--instructions", action="store_true")
    parser.add_argument("--strict-native-interop", action="store_true")
    parser.add_argument("--require-native-ntdll", action="store_true")
    parser.add_argument("--host", type=pathlib.Path)
    parser.add_argument("--runtime", type=pathlib.Path)
    arguments = parser.parse_args()
    check_launch(arguments.collector.resolve(), arguments.target.resolve(), arguments.instructions,
        arguments.host.resolve() if arguments.host else None, arguments.runtime, arguments.strict_native_interop,
        arguments.require_native_ntdll)


def main_attach():
    parser = path_parser('collector', 'target')
    parser.add_argument("--instructions", action="store_true")
    parser.add_argument("--requires-launch", action="store_true")
    parser.add_argument("--deferred", action="store_true")
    parser.add_argument("--debugger", action="store_true")
    parser.add_argument("--host", type=pathlib.Path)
    parser.add_argument("--runtime", type=pathlib.Path)
    parser.add_argument("--inspector", type=pathlib.Path)
    parser.add_argument("--native-entries", action="store_true")
    parser.add_argument("--native-boundaries", action="store_true")
    arguments = parser.parse_args()
    check_attach(arguments.collector.resolve(), arguments.target.resolve(), arguments.instructions,
        arguments.requires_launch, arguments.deferred, arguments.debugger, arguments.host, arguments.runtime,
        arguments.inspector, arguments.native_entries, arguments.native_boundaries)


def main_debugger_filters():
    run_paths(check_debugger_filters, 'collector', 'target')


def main_private_syscalls():
    parser = path_parser('collector', 'target')
    parser.add_argument('--launch', action='store_true')
    parser.add_argument('--lifecycle', action='store_true')
    parser.add_argument('--legacy-gate', action='store_true')
    parser.add_argument('--artifact', type=Path)
    arguments = parser.parse_args()
    if arguments.lifecycle and not arguments.launch:
        parser.error('--lifecycle requires --launch')
    check_private_syscalls(arguments.collector.resolve(), arguments.target.resolve(),
        arguments.launch, arguments.lifecycle, arguments.artifact, arguments.legacy_gate)


def main_raw_native():
    parser = path_parser('collector', 'target', '--artifact')
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--breakpoints', action='store_true')
    parser.add_argument('--host', type=Path)
    parser.add_argument('--runtime', type=Path)
    options = parser.parse_args()
    check_raw_native(options.collector.resolve(), options.target.resolve(),
        options.artifact.resolve() if options.artifact else None, options.baseline,
        options.host, options.runtime, options.breakpoints)


def main_native_boundaries():
    parser = path_parser('collector', 'target', '--artifact')
    parser.add_argument('--case', action='append')
    parser.add_argument('--host', type=Path)
    parser.add_argument('--runtime', type=Path)
    options = parser.parse_args()
    check_native_boundaries(options.collector.resolve(), options.target.resolve(),
        options.artifact.resolve() if options.artifact else None, options.case, options.host, options.runtime)


if __name__ == '__main__':
    run_scenarios({
        'launch': main_launch,
        'attach': main_attach,
        'debugger_filters': main_debugger_filters,
        'private_syscalls': main_private_syscalls,
        'raw_native': main_raw_native,
        'native_boundaries': main_native_boundaries,
    })
