import sys
sys.dont_write_bytecode = True

import collections
import contextlib
import json
import os
import pathlib
import struct
import subprocess
import tempfile
import time

from TestSupport import (Collector, open_trace, path_parser, exit_code, kernel32, run_scenarios, values,
                         wait_file, wait_for)


def arrays(payload, parameter):
    return [(flags, original >> 32, original & 0xFFFFFFFF, data)
        for index, kind, flags, original, data in values(payload) if index == parameter and kind == 12]


def multidimensional(collector, connection, database, limit):
    details = []
    # System.Array parameters retain exact strides for multidimensional arrays with nonzero bounds.
    matched = []
    expected_data = b"".join(struct.pack("<iB", 100 * (index + 1), 7 + index * 2) for index in range(4))
    for target, call_id, before, after in connection.execute(
            "SELECT c.target,c.id,c.input,c.output FROM calls c JOIN apis a "
            "ON a.id=c.api AND a.target=c.target WHERE a.name LIKE 'System.Array.Copy(%' "
            "AND a.parameters="
            "'sourceArray: System.Array, destinationArray: System.Array, length: int32 -> void' "
            "AND c.ended IS NOT NULL AND c.flags&36=0"):
        source, destination = arrays(before, 0), arrays(after, 1)
        if not source or source[0][1:3] != (5, 4):
            continue
        assert source == destination and source[0][3] == expected_data[:limit], (source, destination)
        original = arrays(before, 1)
        assert len(original) == 1 and original[0][3] == bytes(min(20, limit)), original
        matched.append(call_id)
        details.append({"kind": "multidimensional", "type": "ManagedArrayPacked", "stride": 5,
            "limit": limit,
            "call": collector.call("details", database=database, target=target, callId=call_id)})
    assert len(matched) == 1, ("Missing multidimensional array copy", matched)
    return details


def runtime_arrays(collector, connection, database):
    details = []
    pointer_size = connection.execute('SELECT pointer_size FROM targets LIMIT 1').fetchone()[0]
    pointer_format = '<I' if pointer_size == 4 else '<Q'
    mixed_stride = pointer_size + 8
    observed = collections.Counter()
    for target, call_id, before, after in connection.execute(
            "SELECT c.target,c.id,c.input,c.output FROM calls c JOIN apis a "
            "ON a.id=c.api AND a.target=c.target "
            "WHERE a.name='System.Array.Copy(System.Array, System.Array, int32)' "
            "AND c.parent=0 AND c.ended IS NOT NULL AND c.flags&36=0"):
        source, destination = arrays(before, 0), arrays(after, 1)
        assert len(source) == len(destination) == 1, (source, destination)
        shape = source[0][1:3]
        observed[shape] += 1
        for flags, stride, count, data in source + destination:
            assert (stride, count) == shape and len(data) == min(stride * count, 16), (shape, stride, count, data)
            assert flags == int(stride * count > 16), (shape, flags)
            if shape == (5, 1):
                assert data == struct.pack("<iB", 0x11223344, 0x5A), data
            elif shape == (mixed_stride, 2):
                number_offset, reference_offset = (0, 8) if pointer_size == 4 else (8, 0)
                assert struct.unpack_from('<Q', data, number_offset)[0] == 0x1122334455667788, (shape, data)
                assert struct.unpack_from(pointer_format, data, reference_offset)[0] != 0, (shape, data)
            elif shape in ((pointer_size, 1), (pointer_size, 2)):
                assert struct.unpack_from(pointer_format, data)[0] != 0, (shape, data)
                if shape != (pointer_size, 1):
                    assert struct.unpack_from(pointer_format, data, pointer_size)[0] == 0, (shape, data)
        details.append({"kind": "attached-copy", "type": "System.Array", "stride": shape[0], "limit": 16,
            "call": collector.call("details", database=database, target=target, callId=call_id)})
    assert observed == {(5, 4): 1, (8, 0): 1, (4, 0): 1, (5, 1): 1,
        (pointer_size, 2): 1, (pointer_size, 1): 1, (mixed_stride, 2): 32}, observed

    # Runtime-shaped array returns carry their empty or initialized buffer independently of the scalar reference.
    returned = collections.Counter()
    for target, call_id, after in connection.execute(
            "SELECT c.target,c.id,c.output FROM calls c JOIN apis a ON a.id=c.api AND a.target=c.target "
            "WHERE a.name='System.Array.CreateInstance(System.Type, int32[], int32[])' "
            "AND c.parent=0 AND c.ended IS NOT NULL AND c.flags&36=0"):
        result = arrays(after, 0xFFFFFFFF)
        assert len(result) == 1, result
        flags, stride, count, data = result[0]
        assert flags == int(stride * count > 16) and data == bytes(min(stride * count, 16)), result
        returned[stride, count] += 1
        details.append({"kind": "attached-return", "type": "System.Array", "stride": stride, "limit": 16,
            "call": collector.call("details", database=database, target=target, callId=call_id)})
    assert returned == {(5, 4): 2, (4, 0): 2, (pointer_size, 1): 2}, returned

    # A different framework assembly must resolve the imported helpers against the loaded core library.
    imported = connection.execute(
        "SELECT c.target,c.id,c.input,c.output FROM calls c JOIN apis a ON a.id=c.api AND a.target=c.target "
        "WHERE a.module='System.Collections.dll' AND a.name LIKE '%SortedSet%CopyTo(System.Array, int32)' "
        "AND c.parent=0 AND c.ended IS NOT NULL AND c.flags&36=0").fetchall()
    assert len(imported) == 1, imported
    target, call_id, before, after = imported[0]
    assert arrays(before, 1) == [(0, 4, 3, bytes(12))], arrays(before, 1)
    assert arrays(after, 1) == [(0, 4, 3, struct.pack("<iii", 0, 0x11223344, 0x55667788))], arrays(after, 1)
    details.append({"kind": "attached-copy", "type": "System.Array", "stride": 4, "limit": 16,
        "call": collector.call("details", database=database, target=target, callId=call_id)})

    # Injected helper calls are suppressed; the application's successful and throwing calls remain visible.
    helper_calls = connection.execute(
        "SELECT a.name,c.flags,c.parent FROM calls c JOIN apis a ON a.id=c.api AND a.target=c.target "
        "WHERE a.name IN ('System.Array.get_LongLength()', "
        "'System.Runtime.InteropServices.Marshal.UnsafeAddrOfPinnedArrayElement(System.Array, int32)') "
        "AND c.ended IS NOT NULL").fetchall()
    assert len(helper_calls) == 3 and sum(bool(flags & 36) for _, flags, _ in helper_calls) == 1, helper_calls
    assert all(parent == 0 for _, _, parent in helper_calls), helper_calls
    return details


def attached(collector, executable, prefix, root, mask, strides, debugger, generic, copy_arrays):
    marker = root / "attached.txt"
    database = str(root / "attached.sqlite")
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("COR_", "CORECLR_"))}
    copying = debugger and (copy_arrays or bool(prefix) and not generic)
    mode = "--arrays-debugger-copy" if copying else "--arrays-debugger-generic" if generic else (
        "--arrays-debugger" if debugger else "--arrays-attach")
    target = subprocess.Popen([executable, *prefix, str(marker), mode], env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
    details = []
    try:
        wait_file(pathlib.Path(str(marker) + ".ready"), target)
        collector.call("attach", database=database, pid=target.pid, bufferLimit=16,
            apiMask=mask, followChildren=False, instructionEngine=False)
        status = collector.wait(lambda value: value["capturing"] or value["finished"])
        assert status["capturing"], status
        collector.wait(lambda value: collector.call("page", database=database, limit=1)["targets"][0]["managedState"]
            in (1, 2), timeout=60)
        page = collector.call("page", database=database, limit=1)
        assert page["targets"][0]["managedState"] == 1, page["targets"]
        pathlib.Path(str(marker) + ".go").touch()
        wait_file(marker, target, timeout=120 if debugger else 60)
        assert marker.read_text().startswith("arrays-ok"), marker.read_text()
        collector.call("stop")
        # Allow time for both debugger shutdown waits and the final trace drain.
        collector.wait(lambda value: value["finished"], timeout=60 if debugger else 30)
        observed = collections.Counter()
        empty_arrays = collections.Counter()
        method = "System.Array.Copy(%" if copying else "System.Array.Resize(%"
        parameter = 1 if copying else 0
        with open_trace(database) as connection:
            detach_errors = connection.execute(
                "SELECT message FROM diagnostics WHERE message LIKE 'Managed debugger detachment failed%'").fetchall()
            assert not detach_errors, detach_errors
            pointer_size = connection.execute('SELECT pointer_size FROM targets LIMIT 1').fetchone()[0]
            for target_id, call_id, before, after in connection.execute(
                    "SELECT c.target,c.id,c.input,c.output FROM calls c JOIN apis a "
                    "ON a.id=c.api AND a.target=c.target WHERE a.name LIKE ? "
                    "AND c.parent=0 AND c.ended IS NOT NULL AND c.flags&36=0", (method,)):
                inputs, outputs = arrays(before, parameter), arrays(after, parameter)
                assert len(outputs) == 1 and len(inputs) <= 1, (inputs, outputs)
                _, stride, count, _ = outputs[0]
                if copying and count == 0:
                    assert inputs == outputs == arrays(before, 0) == arrays(after, 0) == [(0, stride, 0, b"")], (
                        inputs, outputs, arrays(before, 0), arrays(after, 0))
                    empty_arrays[stride] += 1
                    details.append({"kind": "attached-copy", "type": "System.Array", "stride": stride, "limit": 16,
                        "call": collector.call("details", database=database, target=target_id, callId=call_id)})
                    continue
                references = generic and count in (5, 6)
                name = ("String" if count == 5 else "Object") if references else next(
                    name for name, expected in strides.items() if expected == stride)
                if references:
                    assert stride == pointer_size and len(inputs) == 1 and inputs[0][2] == 3, (inputs, outputs)
                if copying:
                    assert arrays(before, 0)[0][1:3] == (stride, 3), (name, arrays(before, 0))
                    assert count == 4 and len(inputs) == 1 and inputs[0][2] == 4, (name, inputs, outputs)
                    assert arrays(before, 0) == arrays(after, 0), (name, arrays(before, 0), arrays(after, 0))
                for phase, (flags, actual_stride, elements, data) in enumerate(inputs + outputs):
                    assert actual_stride == stride and len(data) == min(elements * stride, 16), (
                        name, actual_stride, elements, len(data))
                    assert bool(flags & 1) == (elements * stride > 16) and not flags & 6, flags
                    if references:
                        first, second = struct.unpack_from('<II' if pointer_size == 4 else '<QQ', data)
                        assert first > 65535 and (second > 65535 if name == "String" else second == 0), (name, data)
                        continue
                    populated = count == 4 and (not copying or phase == 1)
                    for index in range(elements):
                        offset = index * stride
                        if name == "ManagedArrayEmpty":
                            continue
                        number = (5 if index == 1 else 1) if name == "DayOfWeek" else (200 if index == 1 else 100)
                        if not populated or index >= 3:
                            number = 0
                        if offset + 4 <= len(data):
                            assert struct.unpack_from("<i", data, offset)[0] == number, (name, index, data)
                observed[stride, inputs[0][2] if inputs else None, count] += 1
                details.append({"kind": "attached-copy" if copying else "attached", "type": name,
                    "stride": stride, "limit": 16,
                    "call": collector.call("details", database=database, target=target_id, callId=call_id)})
            if not debugger:
                details.extend(multidimensional(collector, connection, database, 16))
                details.extend(runtime_arrays(collector, connection, database))
            if generic:
                copies = connection.execute(
                    "SELECT c.target,c.id,c.input,c.output FROM calls c JOIN apis a "
                    "ON a.id=c.api AND a.target=c.target "
                    "WHERE a.name LIKE 'System.Collections.Generic.List%CopyTo(int32, %, int32, int32)' "
                    "AND c.parent=0 AND c.ended IS NOT NULL AND c.flags&36=0 ORDER BY c.id").fetchall()
                assert len(copies) == 3, copies
                for (target_id, call_id, before, after), stride, name in zip(copies, (8, 5, pointer_size),
                        ("ManagedArrayPadded", "ManagedArrayPacked", "String")):
                    for parameter, number in ((1, 0), (3, 1), (4, 3)):
                        scalar = [(flags, data) for index, kind, flags, _, data in values(before)
                            if index == parameter and kind == 2]
                        assert scalar == [(0, struct.pack("<i", number))], (name, parameter, scalar)
                    assert arrays(before, 2) == [(1, stride, 5, bytes(16))], (name, arrays(before, 2))
                    output = arrays(after, 2)
                    assert len(output) == 1 and output[0][:3] == (1, stride, 5), (name, output)
                    data = output[0][3]
                    assert data[:stride] == bytes(stride), (name, data)
                    if name == "String":
                        assert struct.unpack_from('<I' if pointer_size == 4 else '<Q', data, stride)[0] > 65535, \
                            (name, data)
                    else:
                        assert struct.unpack_from("<iB", data, stride) == (100, 7), (name, data)
                    details.append({"kind": "attached-list-copy", "type": name, "stride": stride, "limit": 16,
                        "call": collector.call("details", database=database, target=target_id, callId=call_id)})
        shapes = ((4, 4),) if copying else ((3, 4),) if debugger else ((3, 4), (None, 2), (2, 0))
        expected = {(stride, before, after) for stride in strides.values() for before, after in shapes}
        if generic:
            expected.update(((pointer_size, 3, 5), (pointer_size, 3, 6)))
        assert observed == dict.fromkeys(expected, 1), (observed, expected)
        expected_empty = collections.Counter({8: 1, 5: 2, 32: 1, 1: 1, 4: 1, pointer_size + 8: 1})
        expected_empty[pointer_size] += 3
        assert empty_arrays == (expected_empty if copying else {}), empty_arrays
        pathlib.Path(str(marker) + ".release").touch()
        assert target.wait(timeout=30) == 0, target.stderr.read().decode(errors="replace")
        print("Attached managed array sizes and values passed.", flush=True)
        return details
    finally:
        if target.poll() is None:
            target.kill()
            target.wait()


def check_arrays(collector_path, target_path, inspector=None, host=None, runtime=None, artifacts=None, attach=False,
        debugger=False, generic=False, copy_arrays=False):
    context = contextlib.nullcontext(str(artifacts)) if artifacts else tempfile.TemporaryDirectory(
        prefix="Detourist-ManagedArrays-")
    with context as temporary:
        root = pathlib.Path(temporary).resolve()
        root.mkdir(parents=True, exist_ok=True)
        executable = str((host or target_path).resolve())
        prefix = [str(runtime.resolve()), str(target_path.resolve())] if host else []
        baseline = root / "baseline.txt"
        result = subprocess.run([executable, *prefix, str(baseline), "--arrays"],
            capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode == 0 and baseline.is_file(), result
        expected = baseline.read_text().splitlines()
        assert expected[0] == "arrays-ok", expected
        strides = {name: int(size) for name, size in (line.split("=") for line in expected[1:])}
        details = []
        with Collector(collector_path) as collector:
            mask = collector.call("hello")["managedMask"]
            for limit in (() if attach or debugger else (16, 64)):
                database = str(root / f"arrays-{limit}.sqlite")
                marker = root / f"result-{limit}.txt"
                status = collector.capture(database=database, executable=executable,
                    arguments=subprocess.list2cmdline([*prefix, str(marker), "--arrays"]), bufferLimit=limit,
                    apiMask=mask, followChildren=False, instructionEngine=False, timeout=90)
                assert marker.is_file() and marker.read_text().splitlines() == expected, status
                page = collector.call("page", database=database, limit=1)
                assert all(target["state"] == "Exited" and target["managedState"] == 1
                    for target in page["targets"]), page["targets"]
                with open_trace(database) as connection:
                    for name, stride in strides.items():
                        typename = "System.DayOfWeek" if name == "DayOfWeek" else name
                        patterns = {
                            "return": ("System.Collections.Generic.List%ToArray()", f"% -> {typename}[]", 0xFFFFFFFF),
                            "copy": ("System.Collections.Generic.List%CopyTo(%", f"%array: {typename}[], %", 1),
                            "resize": ("System.Array.Resize(%", f"%array: {typename}[]&,%", 0)}
                        for operation, (method, parameters, parameter) in patterns.items():
                            rows = connection.execute("SELECT c.target,c.id,c.input,c.output,l.layout FROM calls c "
                                "JOIN apis a ON a.id=c.api AND a.target=c.target "
                                "LEFT JOIN api_layouts l ON l.api=a.id AND l.target=a.target "
                                "WHERE a.name LIKE ? AND a.parameters LIKE ? "
                                "AND c.ended IS NOT NULL AND c.flags&36=0 ORDER BY c.id",
                                (method, parameters)).fetchall()
                            assert rows, (name, operation, "Missing managed array call")
                            shapes = set()
                            for target, call_id, before, after, descriptor in rows:
                                inputs, outputs = arrays(before, parameter), arrays(after, parameter)
                                assert len(outputs) == 1 and len(inputs) <= 1, (name, operation, inputs, outputs)
                                for flags, actual_stride, count, data in inputs + outputs:
                                    assert actual_stride == stride or count == 0 and actual_stride == 0, (
                                        name, operation, stride, actual_stride, count)
                                    assert len(data) == min(stride * count, limit), (name, operation, count, len(data))
                                    assert bool(flags & 1) == (stride * count > limit) and not flags & 6, flags
                                assert descriptor, (name, operation, "Missing the array element layout")
                                layout = json.loads(descriptor)
                                mapping = layout["Result"] if operation == "return" else layout["Arguments"][parameter]
                                assert isinstance(mapping, dict) and "Element" in mapping, (name, mapping)
                                element = layout["Types"][mapping["Element"]]
                                assert element["Name"] == typename, (name, element)
                                shapes.add((inputs[0][2] if inputs else None, outputs[0][2]))
                                details.append({"kind": operation, "type": name, "stride": stride, "limit": limit,
                                    "call": collector.call("details", database=database,
                                        target=target, callId=call_id)})
                            required = {"return": {(None, 3), (None, 0)}, "copy": {(3, 3)},
                                "resize": {(3, 4), (None, 2), (2, 0)}}[operation]
                            assert required <= shapes, (name, operation, shapes)

                    details.extend(multidimensional(collector, connection, database, limit))
                print(f"Managed arrays at {limit} bytes passed ({status['calls']} calls).", flush=True)
            if attach or debugger:
                details.extend(attached(collector, executable, prefix, root, mask, strides, debugger, generic,
                    copy_arrays))
        path = root / "details.json"
        path.write_text(json.dumps(details), encoding="utf-8")
        if inspector:
            result = subprocess.run(["dotnet", str(inspector), "--managed-array-values", str(path)],
                capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
            assert result.returncode == 0, result.stdout + result.stderr
            print(result.stdout.strip(), flush=True)


def lifecycle(collector, executable, prefix, root, mask, details):
    marker = root / "lifecycle.txt"
    database = str(root / "lifecycle-launch.sqlite")
    options = dict(bufferLimit=16, apiMask=mask, followChildren=False, instructionEngine=False)
    process = None
    try:
        collector.call("launch", database=database, executable=executable,
            arguments=subprocess.list2cmdline([*prefix, str(marker), "--layouts-lifecycle"]), **options)
        status = collector.wait(lambda value: value["capturing"] or value["finished"])
        assert status["capturing"], status
        pid = collector.call("page", database=database, limit=1)["targets"][0]["pid"]
        process = kernel32.OpenProcess(0x101001, False, pid)
        assert process, "Cannot observe the layout lifecycle fixture"
        wait_for(pathlib.Path(str(marker) + ".ready"), process, timeout=90)
        captured = []
        for phase in range(2):
            if phase:
                database = str(root / "lifecycle-reattach.sqlite")
                collector.call("attach", database=database, pid=pid, **options)
                status = collector.wait(lambda value: value["capturing"] or value["finished"])
                assert status["capturing"], status
                pathlib.Path(str(marker) + ".go").touch()
                wait_for(pathlib.Path(str(marker) + ".done"), process)
            collector.call("stop")
            collector.wait(lambda value: value["finished"])
            assert kernel32.WaitForSingleObject(process, 0) != 0, "Detach terminated the layout fixture"
            page = collector.call("page", database=database, limit=1)
            assert page["targets"][0]["managedState"] == 1, page["targets"]
            with open_trace(database) as connection:
                rows = connection.execute("SELECT c.target,c.id,c.input,c.output,l.layout FROM calls c "
                    "JOIN apis a ON a.target=c.target AND a.id=c.api "
                    "LEFT JOIN api_layouts l ON l.target=a.target AND l.api=a.id "
                    "WHERE a.name LIKE 'System.Collections.Generic.KeyValuePair%get_Value()' "
                    "AND a.parameters LIKE 'this: %<int32, LayoutTest.LargeValue>& -> LayoutTest.LargeValue' "
                    "AND c.ended IS NOT NULL AND c.flags&36=0 ORDER BY c.id LIMIT 1").fetchall()
                assert rows, (phase, "Missing the retained large-layout method")
                target, call_id, before, after, descriptor = rows[0]
                assert descriptor and len(descriptor.encode("utf-8")) > 8192, (phase, "Missing full layout")
                captured.append((descriptor, [value for value in values(before) if value[1] == 0], values(after)))
                details.append({"kind": "large", "limit": 16,
                    "call": collector.call("details", database=database, target=target, callId=call_id)})
        assert captured[0] == captured[1], "Reattachment changed the layout or bounded value snapshots"
        pathlib.Path(str(marker) + ".release").touch()
        assert kernel32.WaitForSingleObject(process, 15000) == 0, "Layout fixture did not exit after detach"
        assert exit_code(process) == 0 and marker.read_text() == "layouts-ok", marker.read_text()
        print("Large managed layouts survived detach and reattachment.", flush=True)
    finally:
        if process:
            if kernel32.WaitForSingleObject(process, 0) != 0:
                kernel32.TerminateProcess(process, 1)
                kernel32.WaitForSingleObject(process, 5000)
            kernel32.CloseHandle(process)


def check_layouts(collector_path, target_path, inspector=None, host=None, runtime=None, artifacts=None):
    directory = contextlib.nullcontext(str(artifacts)) if artifacts else \
        tempfile.TemporaryDirectory(prefix="Detourist-ManagedLayouts-")
    with directory as temporary:
        root = pathlib.Path(temporary).resolve()
        root.mkdir(parents=True, exist_ok=True)
        executable = str((host or target_path).resolve())
        prefix = [str(runtime.resolve()), str(target_path.resolve())] if host else []
        baseline = root / "baseline.txt"
        result = subprocess.run([executable, *prefix, str(baseline), "--layouts"],
            capture_output=True, text=True, timeout=45, creationflags=subprocess.CREATE_NO_WINDOW)
        observed = baseline.read_text() if baseline.is_file() else "<missing result>"
        assert result.returncode == 0 and observed == "layouts-ok", (result, observed)

        details = []
        with Collector(collector_path) as collector:
            hello = collector.call("hello")
            for limit in (16, 64):
                database = str(root / f"layouts-{limit}.sqlite")
                marker = root / f"result-{limit}.txt"
                arguments = subprocess.list2cmdline([*prefix, str(marker), "--layouts"])
                collector.call("launch", database=database, executable=executable, arguments=arguments,
                    bufferLimit=limit, apiMask=hello["managedMask"], followChildren=False, instructionEngine=False)
                status = collector.wait(lambda value: value["finished"], timeout=90)
                assert marker.is_file() and marker.read_text() == "layouts-ok", status
                page = collector.call("page", database=database, limit=1)
                assert all(target["state"] == "Exited" and target["managedState"] == 1
                    for target in page["targets"]), page["targets"]

                # Exercise actual CLR regions, including value arguments, generic receivers and scalar-sized returns.
                patterns = {
                    "date": ("System.DateTimeOffset.AddMinutes(float64)", "%"),
                    "decimal": ("System.Decimal.Add(System.Decimal, System.Decimal)", "%"),
                    "span": ("System.TimeSpan.%", "value: float64% -> System.TimeSpan"),
                    "small": ("System.TimeSpan.Add(System.TimeSpan)", "%"),
                    "external-date": ("System.Xml.XmlConvert.ToDateTimeOffset(string)", "%"),
                    "external-value": ("System.Xml.XmlConvert.ToString(System.DateTimeOffset)", "%"),
                    "external-span": ("System.Xml.XmlConvert.ToTimeSpan(string)", "%"),
                    "forwarded": ("System.Collections.Generic.KeyValuePair%get_Value()",
                        "this: %<int32, ManagedLayoutValue>& -> ManagedLayoutValue"),
                    "version32": ("System.Collections.Generic.KeyValuePair%get_Value()",
                        "this: %<int32, LayoutTest.Wrapper32>& -> LayoutTest.Wrapper32"),
                    "version64": ("System.Collections.Generic.KeyValuePair%get_Value()",
                        "this: %<int32, LayoutTest.Wrapper64>& -> LayoutTest.Wrapper64"),
                    "mixed": ("System.Collections.Generic.KeyValuePair%get_Value()",
                        "this: %<LayoutTest.Wrapper32, LayoutTest.Wrapper64>& -> LayoutTest.Wrapper64"),
                    "large": ("System.Collections.Generic.KeyValuePair%get_Value()",
                        "this: %<int32, LayoutTest.LargeValue>& -> LayoutTest.LargeValue"),
                    "pair": ("System.Collections.Generic.KeyValuePair%get_Value()",
                        "this: %KeyValuePair%<int32, System.Guid>& -> System.Guid"),
                    "nested": ("System.Collections.Generic.KeyValuePair%get_Value()",
                        "this: %KeyValuePair%<int32, System.Collections.Generic.KeyValuePair%"),
                    "arguments": ("System.Collections.Generic.%EqualityComparer%Equals(%",
                        "%x: System.Collections.Generic.KeyValuePair%<int32, System.Guid>%")
                }
                with open_trace(database) as connection:
                    # Shared reference instantiations retain an unresolved declaration instead of an invented type.
                    shared = connection.execute("SELECT a.parameters,l.layout,c.result FROM calls c "
                        "JOIN apis a ON a.target=c.target AND a.id=c.api "
                        "LEFT JOIN api_layouts l ON l.target=a.target AND l.api=a.id "
                        "WHERE a.name LIKE 'System.Collections.Generic.KeyValuePair%get_Value()' "
                        "AND a.parameters LIKE '% -> !1' AND c.ended IS NOT NULL AND c.flags&36=0").fetchall()
                    assert len(shared) >= 2 and all(not layout and result for _, layout, result in shared), shared
                    for kind, (name, parameters) in patterns.items():
                        rows = connection.execute("SELECT c.target,c.id,c.input,c.output,l.layout FROM calls c "
                            "JOIN apis a ON a.target=c.target AND a.id=c.api "
                            "LEFT JOIN api_layouts l ON l.target=a.target AND l.api=a.id "
                            "WHERE a.name LIKE ? AND a.parameters LIKE ? AND c.ended IS NOT NULL AND c.flags&36=0 "
                            "ORDER BY c.id LIMIT 1", (name, parameters)).fetchall()
                        assert rows, (kind, "Missing managed call", name, parameters)
                        target, call_id, before, after, descriptor = rows[0]
                        assert descriptor, (kind, "Missing loaded layout")
                        if kind == "large":
                            assert len(descriptor.encode("utf-8")) > 8192, "Layout did not span transport records"
                        layout = json.loads(descriptor)
                        types = layout["Types"]
                        inputs, outputs = values(before), values(after)
                        expected = {"date": ([0], True), "decimal": ([0, 1], True), "span": ([], True),
                            "small": ([0, 1], True),
                            "external-date": ([], True), "external-value": ([0], False),
                            "external-span": ([], True),
                            "forwarded": ([0], True),
                            "version32": ([0], True), "version64": ([0], True),
                            "mixed": ([0], True),
                            "large": ([0], True),
                            "pair": ([0], True), "nested": ([0], True), "arguments": ([1, 2], False)}[kind]
                        for index in expected[0]:
                            reference = layout["Arguments"][index]
                            assert reference is not None, (kind, index, layout)
                            size = types[reference]["Size"]
                            samples = [value for value in inputs if value[0] == index and
                                value[1] == (2 if kind == "small" and index == 1 else 0)]
                            assert len(samples) == 1, (kind, index, inputs)
                            _, _, flags, original, data = samples[0]
                            assert original >= size and len(data) == min(original, limit), (kind, samples, size)
                            assert bool(flags & 1) == (original > limit) and not flags & 6, (kind, samples)
                        if expected[1]:
                            reference = layout["Result"]
                            assert reference is not None, (kind, layout)
                            size = types[reference]["Size"]
                            samples = [value for value in outputs if value[0] == 0xFFFFFFFF]
                            assert len(samples) == 1, (kind, outputs)
                            _, _, flags, original, data = samples[0]
                            assert original >= size and len(data) == min(original, limit), (kind, samples, size)
                            assert bool(flags & 1) == (original > limit) and not flags & 6, (kind, samples)
                        details.append({"kind": kind, "limit": limit,
                            "call": collector.call("details", database=database, target=target, callId=call_id)})
                print(f"Managed layout capture at {limit} bytes passed ({status['calls']} calls).", flush=True)
            lifecycle(collector, executable, prefix, root, hello["managedMask"], details)

        path = root / "details.json"
        path.write_text(json.dumps(details), encoding="utf-8")
        if inspector:
            result = subprocess.run(["dotnet", str(inspector), "--managed-values", str(path)],
                capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
            assert result.returncode == 0, result.stdout + result.stderr
            print(result.stdout.strip(), flush=True)


def check_attached_layouts(collector_path, executable, inspector=None, artifacts=None):
    context = contextlib.nullcontext(str(artifacts)) if artifacts else tempfile.TemporaryDirectory(
        prefix="Detourist-ManagedLayoutAttach-")
    with context as temporary:
        root = pathlib.Path(temporary).resolve()
        root.mkdir(parents=True, exist_ok=True)
        marker = root / "result.txt"
        database = str(root / "attached.sqlite")
        environment = {key: value for key, value in os.environ.items() if not key.startswith(("COR_", "CORECLR_"))}
        target = subprocess.Popen([str(executable.resolve()), str(marker), "--layouts-attach"], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
        collector = Collector(collector_path)
        details = []
        try:
            wait_file(pathlib.Path(str(marker) + ".ready"), target)
            started = time.monotonic()
            collector.call("attach", database=database, pid=target.pid, bufferLimit=16,
                apiMask=collector.call("hello")["managedMask"], followChildren=False, instructionEngine=False)
            status = collector.wait(lambda value: value["capturing"] or value["finished"])
            assert status["capturing"], status
            collector.wait(lambda value:
                collector.call("page", database=database, limit=1)["targets"][0]["managedState"] in (1, 2), timeout=60)
            page = collector.call("page", database=database, limit=1)
            assert page["targets"][0]["managedState"] == 1, page["targets"]
            ready = time.monotonic() - started
            pathlib.Path(str(marker) + ".go").touch()
            wait_file(marker, target)
            assert marker.read_text() == "layouts-ok", marker.read_text()
            collector.call("stop")
            collector.wait(lambda value: value["finished"])

            # Precompiled methods must publish layouts for parameters and returns as well as receivers.
            patterns = {
                "date": ("System.DateTimeOffset.AddMinutes(float64)", "%", [0], True),
                "decimal": ("System.Decimal.Add(System.Decimal, System.Decimal)", "%", [0, 1], True),
                "span": ("System.TimeSpan.%", "value: float64% -> System.TimeSpan", [], True),
                "small": ("System.TimeSpan.Add(System.TimeSpan)", "%", [0, 1], True),
                "external-date": ("System.Xml.XmlConvert.ToDateTimeOffset(string)", "%", [], True),
                "external-value": ("System.Xml.XmlConvert.ToString(System.DateTimeOffset)", "%", [0], False),
                "external-span": ("System.Xml.XmlConvert.ToTimeSpan(string)", "%", [], True)}
            with open_trace(database) as connection:
                for kind, (name, parameters, inputs, result) in patterns.items():
                    rows = connection.execute("SELECT c.target,c.id,c.input,c.output,l.layout FROM calls c "
                        "JOIN apis a ON a.target=c.target AND a.id=c.api "
                        "LEFT JOIN api_layouts l ON l.target=a.target AND l.api=a.id "
                        "WHERE a.name LIKE ? AND a.parameters LIKE ? AND c.ended IS NOT NULL AND c.flags&36=0 "
                        "ORDER BY c.id LIMIT 1", (name, parameters)).fetchall()
                    assert rows, (kind, "Missing managed call")
                    target_id, call_id, before, after, descriptor = rows[0]
                    assert descriptor, (kind, "Missing attached layout")
                    layout = json.loads(descriptor)
                    for parameter in inputs + ([-1] if result else []):
                        reference = layout["Result"] if parameter == -1 else layout["Arguments"][parameter]
                        assert isinstance(reference, int), (kind, parameter, layout)
                        scalar = parameter == -1 and kind in ("span", "small", "external-span") or \
                            kind == "small" and parameter == 1
                        samples = [sample for sample in values(after if parameter == -1 else before)
                            if sample[0] == (0xFFFFFFFF if parameter == -1 else parameter) and
                            sample[1] == (2 if scalar else 0)]
                        assert len(samples) == 1, (kind, parameter, samples)
                        _, _, flags, original, data = samples[0]
                        assert original >= layout["Types"][reference]["Size"] and len(data) == min(original, 16), (
                            kind, parameter, samples)
                        assert bool(flags & 1) == (original > 16) and not flags & 6, (kind, parameter, samples)
                    details.append({"kind": kind, "limit": 16,
                        "call": collector.call("details", database=database, target=target_id, callId=call_id)})
            pathlib.Path(str(marker) + ".release").touch()
            assert target.wait(timeout=30) == 0, target.stderr.read().decode(errors="replace")
            print(f"Attached layout capture passed (ready in {ready:.2f}s).", flush=True)
        finally:
            collector.close()
            if target.poll() is None:
                target.kill()
                target.wait()
        path = root / "details.json"
        path.write_text(json.dumps(details), encoding="utf-8")
        if inspector:
            result = subprocess.run(["dotnet", str(inspector), "--managed-values", str(path)],
                capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
            assert result.returncode == 0, result.stdout + result.stderr
            print(result.stdout.strip(), flush=True)


def main_arrays():
    parser = path_parser('collector', 'target', '--inspector', '--host', '--runtime', '--artifacts')
    parser.add_argument("--attach", action="store_true")
    parser.add_argument("--debugger", action="store_true")
    parser.add_argument("--generic", action="store_true")
    parser.add_argument("--copy", action="store_true")
    args = parser.parse_args()
    check_arrays(args.collector, args.target, args.inspector, args.host, args.runtime, args.artifacts,
        args.attach, args.debugger, args.generic, args.copy)


def main_layouts():
    args = path_parser('collector', 'target', '--inspector', '--host', '--runtime', '--artifacts').parse_args()
    check_layouts(args.collector, args.target, args.inspector, args.host, args.runtime, args.artifacts)


def main_attached_layouts():
    args = path_parser('collector', 'target', '--inspector', '--artifacts').parse_args()
    check_attached_layouts(args.collector, args.target, args.inspector, args.artifacts)


if __name__ == '__main__':
    run_scenarios({
        'arrays': main_arrays,
        'layouts': main_layouts,
        'attached_layouts': main_attached_layouts,
    })
