import sys
sys.dont_write_bytecode = True

import ctypes
import json
import os
import pathlib
import signal
import struct
import subprocess
import tempfile
import time
import uuid
from contextlib import nullcontext
from ctypes import wintypes
from pathlib import Path

from TestSupport import (Collector, check_limit, open_trace, path_parser, run_scenarios, snapshots, value_records,
                         values, wait_file)


def check_interfaces(collector_path, target_path, instructions=False):
    with tempfile.TemporaryDirectory(prefix="Detourist-COM-") as temporary:
        database = str(pathlib.Path(temporary) / "com.db")
        collector = Collector(collector_path)
        try:
            hello = collector.call("hello")
            catalog = {entry["name"]: entry for entry in hello["catalog"]}
            status = collector.capture(database=database, executable=str(target_path),
                                       bufferLimit=64, apiMask=hello["comMask"], followChildren=False,
                                       instructionEngine=instructions, timeout=45)
            assert status["calls"] > 0, status
            page = collector.call("page", database=database, limit=1)
            assert all(target["state"] == "Exited" for target in page["targets"]), page["targets"]

            # Real COM automation and WinRT instances must expose calls through their returned vtables.
            required = ["CoCreateInstance", "CoCreateInstanceEx", "CoGetClassObject", "RoActivateInstance",
                        "RoGetActivationFactory", "IUnknown::QueryInterface", "IUnknown::AddRef",
                        "IUnknown::Release", "IClassFactory::CreateInstance", "IClassFactory::LockServer",
                        "IDispatch::GetTypeInfoCount", "IDispatch::GetTypeInfo", "IDispatch::GetIDsOfNames",
                        "IDispatch::Invoke", "IInspectable::GetIids", "IInspectable::GetRuntimeClassName",
                        "IInspectable::GetTrustLevel", "IActivationFactory::ActivateInstance"]
            for name in required:
                calls = collector.call("page", database=database, api=name, limit=10)["calls"]
                assert any(call["name"] == name for call in calls), f"Missing COM call: {name}"

            # HRESULT failure semantics must retain S_OK as success and expose failed dispatch as failure.
            failures = collector.call("page", database=database, api="IDispatch::Invoke",
                                      failuresOnly=True, limit=100)["calls"]
            assert len(failures) >= 33 and all(call["flags"] & 1 for call in failures), failures
            names = collector.call("page", database=database, api="IDispatch::GetIDsOfNames", limit=1)["calls"]
            detail = collector.call("details", database=database, target=names[0]["target"], callId=names[0]["id"])
            assert "Count" in detail["text"] or "Add" in detail["text"], detail
            classes = collector.call("page", database=database,
                                     api="IInspectable::GetRuntimeClassName", limit=1)["calls"]
            detail = collector.call("details", database=database, target=classes[0]["target"], callId=classes[0]["id"])
            assert "Windows.Foundation.Collections." in detail["text"] and "64 of 84" in detail["text"], detail

            # Each emitted buffer obeys the same cap, including nested automation data.
            with open_trace(database) as connection:
                assert connection.execute("SELECT count(*) FROM calls WHERE api=?",
                                          (catalog["IDispatch::Invoke"]["id"],)).fetchone()[0] >= 99
                for record in connection.execute("SELECT input,output FROM calls"):
                    check_limit(record, 64)

            if instructions:
                # SDK contracts preserve inherited slots, native floating values and actual output extents.
                with open_trace(database) as connection:
                    def observed(*names):
                        rows = connection.execute("SELECT c.arguments,c.input,c.output,c.result,c.flags,a.parameters,"
                            "a.category "
                            "FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api "
                            f"WHERE a.name IN ({','.join('?' for _ in names)}) AND c.ended IS NOT NULL",
                            names).fetchall()
                        assert rows and all(not row[4] & 256 for row in rows), (names, len(rows))
                        return rows

                    # Fixed SDK output interfaces expose every exercised allocator and stream method.
                    for name in ('IMalloc::Alloc', 'IMalloc::GetSize', 'IMalloc::DidAlloc', 'IMalloc::Free',
                                 'IStream::Commit', 'IShellLinkW::SetPath', 'IShellLinkW::GetPath'):
                        observed(name)
                    menus = [row for row in observed('IContextMenu::QueryContextMenu') if row[3] == 1]
                    assert len(menus) == 1 and len(menus[0][0]) == 48, menus
                    assert not snapshots(menus[0][1], 1, 0), 'An HMENU value must not be read as a buffer.'
                    assert any(row[3] == 1 for row in observed('IMalloc::DidAlloc'))

                    reads = [row for row in observed("IStream::Read")
                             if struct.unpack_from('<Q', row[0], 16)[0] in (13, 256) and
                             any(data in (bytes(range(13)), bytes(range(37)))
                                 for flags, original, data in snapshots(row[2], 1, 0))]
                    assert len(reads) == 2 and {struct.unpack_from('<Q', row[0], 16)[0]
                                               for row in reads} == {13, 256}, len(reads)
                    file_category = next(item['id'] for item in hello['categories'] if item['name'].startswith('File'))
                    assert all(row[6] == file_category for row in reads), "Stream calls lost their file category"
                    for row in reads:
                        length = 37 if struct.unpack_from('<Q', row[0], 16)[0] == 256 else 13
                        assert len(row[0]) == 32 and "ULONG cb" in row[5], row
                        assert snapshots(row[2], 1, 0) == [(0, length, bytes(range(length)))], row
                        assert snapshots(row[2], 3, 2) == [(0, 4, struct.pack('<I', length))], row
                        assert row[3] in (0, 1) and not row[4] & 1, row
                        assert not snapshots(row[1], 1, 0), "An output-only stream buffer was copied at entry"
                    writes = [row for row in observed("IStream::Write")
                              if snapshots(row[1], 1, 0) == [(1, 256, bytes(range(64)))]]
                    assert len(writes) == 1, len(writes)
                    write = writes[0]
                    assert snapshots(write[1], 1, 0) == [(1, 256, bytes(range(64)))], write
                    assert not snapshots(write[2], 1, 0), "An input-only stream buffer was copied at return"
                    observed("IStream::Clone")
                    observed("IStream::Seek")
                    status = observed("IStream::Stat")[0]
                    assert snapshots(status[2], 1, 0)[0][0:2] == (1, 80), status
                    attributes = observed("ITypeInfo::GetTypeAttr")[0]
                    assert snapshots(attributes[2], 1, 0)[0][0:2] == (1, 96), attributes
                    assert "TYPEATTR ** ppTypeAttr" in attributes[5], attributes
                    observed("ITypeInfo::ReleaseTypeAttr")
                    documents = observed("ITypeInfo::GetDocumentation")
                    assert any(snapshots(row[2], 2, 1) for row in documents), documents
                    opacity = observed("ID2D1Brush::SetOpacity")[0]
                    expected = struct.pack('<f', 0.375)
                    assert opacity[0][8:12] == expected and len(opacity[0]) == 16 and opacity[3] == 0, opacity
                    returned = observed("ID2D1Brush::GetOpacity")[0]
                    assert returned[3] == struct.unpack('<I', expected)[0] and len(returned[0]) == 8, returned
                    transform = observed("ID2D1Brush::GetTransform")[0]
                    assert snapshots(transform[2], 1, 0) == [(0, 24, struct.pack('<6f', 1, 2, 3, 4, 5, 6))], transform
                    graphics = next(item['id'] for item in hello['categories'] if item['name'].startswith('Graphics'))
                    assert transform[6] == graphics and returned[6] == graphics, (
                        "Graphics interfaces lost their category")

                    # SDK structure returns keep the receiver separate from their hidden return buffer.
                    color = observed("ID2D1SolidColorBrush::GetColor")[0]
                    assert len(color[0]) == 8 and color[3] != 0, (len(color[0]), color[3])
                    assert snapshots(color[2], 0xFFFFFFFF, 0) == [
                        (0, 16, struct.pack('<4f', 0.125, 0.25, 0.5, 1.0))], "Incorrect returned color"
                    size = observed("ID2D1Layer::GetSize")[0]
                    assert len(size[0]) == 8 and snapshots(size[2], 0xFFFFFFFF, 0) == [
                        (0, 8, struct.pack('<2f', 128.5, 257.25))], "Incorrect small structure return"
                    identifier = observed("ID3D12StateObjectProperties1::GetProgramIdentifier")[0]
                    identifier_bytes = struct.pack('<4Q', 0x3141592653589793, 0x2384626433832795,
                                                   0x0288419716939937, 0x5105820974944592)
                    assert len(identifier[0]) == 16 and snapshots(identifier[2], 0xFFFFFFFF, 0) == [
                        (0, 32, identifier_bytes)], "A structure return shifted the declared argument"
                    assert snapshots(identifier[1], 1, 1)[0][2].startswith(b'C\0'), "Incorrect name argument"

                    # Fixed array declarations decay to pointers and retain their full captured extent.
                    set_blend = observed(*(f"ID3D11DeviceContext{version}::OMSetBlendState"
                        for version in ("", "1", "2", "3", "4")))[0]
                    get_blend = observed(*(f"ID3D11DeviceContext{version}::OMGetBlendState"
                        for version in ("", "1", "2", "3", "4")))[0]
                    factors = struct.pack('<4f', 0.125, 0.25, 0.5, 1.0)
                    assert len(set_blend[0]) == 32 and snapshots(set_blend[1], 2, 0) == [(0, 16, factors)], \
                        "A fixed input array was read as a scalar"
                    assert snapshots(get_blend[2], 2, 0) == [(0, 16, factors)], "Incorrect returned array"
                    assert snapshots(get_blend[2], 3, 2) == [(0, 4, struct.pack('<I', 0xABCDEF01))], \
                        "Incorrect returned blend mask"

                    # Real text shaping writes both output buffers beyond the old argument boundary.
                    placements = observed("IDWriteTextAnalyzer::GetGdiCompatibleGlyphPlacements")[0]
                    assert len(placements[0]) == 22 * 8 and placements[3] == 0, \
                        (len(placements[0]), placements[3])
                    advances = snapshots(placements[2], 20, 0)
                    offsets = snapshots(placements[2], 21, 0)
                    assert len(advances) == 1 and advances[0][0:2] == (0, 4) and \
                        struct.unpack('<f', advances[0][2])[0] > 0, "Missing glyph advances"
                    assert len(offsets) == 1 and offsets[0][0:2] == (0, 8), "Missing glyph offsets"

                methods = collector.call("page", database=database, api="f2c7f242", limit=100)["calls"]
                assert any("slot 3" in call["name"] for call in methods), methods
                assert any("slot 4" in call["name"] for call in methods), methods
                with open_trace(database) as connection:
                    transform = connection.execute("SELECT c.input,c.output FROM calls c JOIN apis a "
                        "ON a.target=c.target AND a.id=c.api WHERE a.name LIKE '%F2C7F242%slot 3'").fetchone()
                    assert transform and transform[0] and transform[1], methods
                    assert bytes(range(64)) in transform[0], transform
                    assert bytes(value ^ 0x5A for value in range(64)) in transform[1], transform
                    generated = connection.execute("SELECT a.name,c.input,c.output,c.result FROM calls c JOIN apis a "
                        "ON a.target=c.target AND a.id=c.api WHERE a.module='COM' "
                        "AND a.name LIKE '%F2C7F242%' AND c.ended IS NOT NULL").fetchall()
                    assert any(name.endswith('slot 3') and bytes(range(64)) in input_payload and
                        bytes(value ^ 0x5A for value in range(64)) in output_payload
                        for name, input_payload, output_payload, result in generated), generated
                    assert any(name.endswith('slot 4') and result == (0x31415926 ^ 0xBAADF00D)
                        for name, input_payload, output_payload, result in generated), generated

                # Structure return snapshots obey the same global buffer limit as ordinary API buffers.
                database = str(pathlib.Path(temporary) / "bounded-returns.db")
                collector.call("launch", database=database, executable=str(target_path), arguments="--abi-only",
                               bufferLimit=16, apiMask=hello["comMask"], followChildren=False, instructionEngine=True)
                collector.wait(lambda value: value["finished"], timeout=45)
                with open_trace(database) as connection:
                    rows = connection.execute("SELECT a.name,c.output FROM calls c JOIN apis a "
                        "ON a.target=c.target AND a.id=c.api WHERE a.name IN "
                        "('ID2D1SolidColorBrush::GetColor','ID2D1Layer::GetSize',"
                        "'ID3D12StateObjectProperties1::GetProgramIdentifier') AND c.ended IS NOT NULL").fetchall()
                    assert len(rows) == 3, [name for name, payload in rows]
                    for name, payload in rows:
                        size = 16 if name.endswith('GetColor') else 8 if name.endswith('GetSize') else 32
                        value = snapshots(payload, 0xFFFFFFFF, 0)
                        assert len(value) == 1 and value[0][0:2] == (int(size > 16), size) and \
                            len(value[0][2]) == min(size, 16), (name, [(flags, original, len(data))
                                                     for flags, original, data in value])

                # Entry edits use the shifted register; return memory edits remain in the caller's original buffer.
                database = str(pathlib.Path(temporary) / "structure-breakpoints.db")
                gate_name = "Local\\Detourist-COM-" + uuid.uuid4().hex
                collector.call("launch", database=database, executable=str(target_path),
                               arguments=f"--abi-breakpoints {gate_name}", bufferLimit=64,
                               apiMask=hello["comMask"], entryMask=hello["comMask"],
                               followChildren=False, instructionEngine=True)
                name = "ID3D12StateObjectProperties1::GetProgramIdentifier"
                previous_call = -1
                for attempt in range(100):
                    stopped = collector.wait(lambda value: value["finished"] or value["breakpoint"] and
                        value["stoppedCall"]["id"] != previous_call and
                        value["stoppedCall"]["name"] not in ("Unknown API", "Discovered API"))
                    assert stopped["breakpoint"], stopped
                    if stopped["stoppedCall"]["name"] == name:
                        break
                    previous_call = stopped["stoppedCall"]["id"]
                    collector.call("continue")
                else:
                    raise AssertionError("The structure return method did not reach its entry breakpoint")
                first = stopped["stoppedCall"]
                shader = collector.call("page", database=database,
                    api="ID3D12StateObjectProperties1::GetShaderIdentifier", limit=1)["calls"][0]
                detail = collector.call("details", database=database, target=shader["target"], callId=shader["id"])
                alternate = detail["arguments"][1]
                collector.call("breaks", entryMask=0, exitMask=0)
                collector.call("breakApi", entryApi=first["api"], exitApi=first["api"])
                collector.call("continue")
                stopped = collector.wait(lambda value: value["finished"] or
                    value["breakpoint"] and value["leaving"])
                assert stopped["breakpoint"] and stopped["leaving"], stopped
                collector.call("continue")
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.OpenEventW.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
                kernel.OpenEventW.restype = ctypes.c_void_p
                kernel.SetEvent.argtypes = kernel.CloseHandle.argtypes = [ctypes.c_void_p]
                gate = kernel.OpenEventW(2, False, gate_name)
                assert gate, f"Could not open the fixture gate: {ctypes.get_last_error()}"
                try:
                    assert kernel.SetEvent(gate), ctypes.get_last_error()
                finally:
                    kernel.CloseHandle(gate)
                stopped = collector.wait(lambda value: value["finished"] or value["breakpoint"] and
                    not value["leaving"] and value["stoppedCall"]["id"] != first["id"])
                assert stopped["breakpoint"] and not stopped["leaving"], stopped
                call = stopped["stoppedCall"]
                assert len(call["arguments"]) == 2 and call["result"] != "0x0", call
                arguments = call["arguments"].copy()
                arguments[1] = alternate
                collector.call("continue", arguments=arguments)
                stopped = collector.wait(lambda value: value["finished"] or value["breakpoint"] and
                    value["leaving"] and value["stoppedCall"]["id"] == call["id"])
                assert stopped["breakpoint"] and stopped["leaving"], stopped
                call = stopped["stoppedCall"]
                memory = collector.call("readMemory", address=call["result"], length=32)
                assert bytes.fromhex(memory["bytes"]) == struct.pack('<4Q', 0xDEADBEEF, 2, 3, 4), \
                    "The declared argument edit overwrote the hidden return-buffer register"
                collector.call("writeMemory", address=call["result"], bytes=struct.pack('<Q', 0xFEEDFACE).hex())
                collector.call("breakApi", entryApi=-1, exitApi=-1)
                collector.call("continue")
                collector.wait(lambda value: value["finished"])
                with open_trace(database) as connection:
                    returned = connection.execute("SELECT c.output,c.flags FROM calls c JOIN apis a "
                        "ON a.target=c.target AND a.id=c.api WHERE a.name=? AND c.flags & 16", (name,)).fetchall()
                    assert len(returned) == 1 and snapshots(returned[0][0], 0xFFFFFFFF, 0) == [
                        (0, 32, struct.pack('<4Q', 0xFEEDFACE, 2, 3, 4))], "The edited return was not recorded"

            if instructions:
                # Image RTTI exposes private interface calls before any observed factory or interface query.
                database = str(pathlib.Path(temporary) / "private.db")
                collector.capture(database=database, executable=str(target_path), arguments="--private-only",
                    bufferLimit=64, apiMask=hello["comMask"], followChildren=False, instructionEngine=True)
                with open_trace(database) as connection:
                    rows = connection.execute("SELECT a.name,c.arguments,c.input,c.output,c.result,c.flags "
                        "FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api "
                        "WHERE a.name IN ('ISequentialStream::Read','ISequentialStream::Write') "
                        "AND c.ended IS NOT NULL ORDER BY c.started,c.id").fetchall()
                    assert len(rows) == 2 and all(row[4] == 0 and not row[5] & 257 for row in rows), rows
                    assert rows[0][0] == "ISequentialStream::Read" and len(rows[0][1]) == 32, rows
                    assert snapshots(rows[0][3], 1, 0) == [(0, 4, struct.pack('<I', 0x51A17E01))], rows[0]
                    assert snapshots(rows[0][3], 3, 2) == [(0, 4, struct.pack('<I', 4))], rows[0]
                    assert rows[1][0] == "ISequentialStream::Write" and \
                        snapshots(rows[1][2], 1, 0) == [(0, 4, struct.pack('<I', 0xDEADBEEF))], rows[1]

                # Virtual COM bases are matched to their receiver, including unrelated primary vtables and races.
                for argument, expected in (("--private-virtual", 1), ("--private-virtual-threaded", 32)):
                    database = str(pathlib.Path(temporary) / f"{argument[2:]}.db")
                    collector.capture(database=database, executable=str(target_path), arguments=argument,
                                      bufferLimit=64, apiMask=hello["comMask"], followChildren=False,
                                      instructionEngine=True)
                    with open_trace(database) as connection:
                        rows = connection.execute("SELECT a.name,c.arguments,c.input,c.output,c.result,c.flags "
                            "FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api "
                            "WHERE c.ended IS NOT NULL ORDER BY c.started,c.id").fetchall()
                        assert len(rows) == expected * 3 and all(row[4] == 0 and not row[5] & 257 for row in rows), rows
                        for name in ('ISequentialStream::Read', 'ISequentialStream::Write', 'IPersist::GetClassID'):
                            assert sum(row[0] == name for row in rows) == expected, rows
                        for row in rows:
                            if row[0] == 'ISequentialStream::Read':
                                assert len(row[1]) == 32 and snapshots(row[3], 1, 0) == [
                                    (0, 4, struct.pack('<I', 0x73A17E02))], row
                                assert snapshots(row[3], 3, 2) == [(0, 4, struct.pack('<I', 4))], row
                            elif row[0] == 'ISequentialStream::Write':
                                assert snapshots(row[2], 1, 0) == [(0, 4, struct.pack('<I', 0xC0FFEE12))], row
                            else:
                                assert len(row[1]) == 16 and snapshots(row[3], 1, 0) == [
                                    (0, 16, bytes.fromhex('303a730c1c2ace11ade500aa0044773d'))], row

                # Private contracts without metadata retain bounded raw snapshots and their inferred type identity.
                database = str(pathlib.Path(temporary) / "private-unknown.db")
                collector.capture(database=database, executable=str(target_path), arguments="--private-unknown",
                    bufferLimit=64, apiMask=hello["comMask"], followChildren=False, instructionEngine=True)
                with open_trace(database) as connection:
                    rows = connection.execute("SELECT a.name,c.arguments,c.input,c.output,c.result,c.flags,a.category "
                        "FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api "
                        "WHERE a.name LIKE '%::slot %' AND c.ended IS NOT NULL ORDER BY c.started,c.id").fetchall()
                    assert len(rows) == 3 and all(row[5] & 256 for row in rows), rows
                    assert rows[0][0] == 'PrivateInterfaces::Probe [RTTI]::slot 3' and rows[0][4] == 0, rows[0]
                    assert snapshots(rows[0][2], 1, 0) == [(0, 64, bytes(range(64)))], rows[0]
                    assert snapshots(rows[0][3], 3, 0) == [
                        (0, 64, bytes(value ^ 0xA5 for value in range(64)))], rows[0]
                    assert rows[1][0] == 'PrivateInterfaces::Probe [RTTI]::slot 4' and \
                        rows[1][4] == (0x113322557799BBDD ^ 0x0123456789ABCDEF), rows[1]
                    assert rows[2][0] == '{7e381203-9f22-4bcd-8270-946930041327}::slot 4' and \
                        rows[2][4] == (0x2233445566778899 ^ 0x0123456789ABCDEF), rows[2]
                    unclassified = next(item['id'] for item in hello['categories'] if item['name'] == 'Unclassified')
                    assert all(row[6] == unclassified for row in rows), rows

                # Virtual private contracts retain raw calls until an observed query supplies their real IID.
                database = str(pathlib.Path(temporary) / "private-virtual-unknown.db")
                collector.capture(database=database, executable=str(target_path),
                    arguments="--private-virtual-unknown",
                    bufferLimit=64, apiMask=hello["comMask"], followChildren=False, instructionEngine=True)
                with open_trace(database) as connection:
                    rows = connection.execute("SELECT a.name,c.arguments,c.input,c.output,c.result,c.flags,a.category "
                        "FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api "
                        "WHERE a.name LIKE '%::slot %' AND c.ended IS NOT NULL ORDER BY c.started,c.id").fetchall()
                    assert len(rows) == 3 and all(row[5] & 256 for row in rows), rows
                    assert rows[0][0] == 'PrivateInterfaces::VirtualProbe [RTTI]::slot 3' and rows[0][4] == 0, rows[0]
                    assert snapshots(rows[0][2], 1, 0) == [(0, 64, bytes(range(64)))], rows[0]
                    assert snapshots(rows[0][3], 3, 0) == [
                        (0, 64, bytes(value ^ 0xA5 for value in range(64)))], rows[0]
                    assert rows[1][0] == 'PrivateInterfaces::VirtualProbe [RTTI]::slot 4' and \
                        rows[1][4] == (0x113322557799BBDD ^ 0x0123456789ABCDEF), rows[1]
                    assert rows[2][0] == '{7e381203-9f22-4bcd-8270-946930041327}::slot 4' and \
                        rows[2][4] == (0x2233445566778899 ^ 0x0123456789ABCDEF), rows[2]
                    unclassified = next(item['id'] for item in hello['categories'] if item['name'] == 'Unclassified')
                    assert all(row[6] == unclassified for row in rows), rows

                # Qualified SDK names select a typed plan instead of falling back to raw virtual slots.
                database = str(pathlib.Path(temporary) / "private-winrt.db")
                collector.capture(database=database, executable=str(target_path),
                    arguments="--private-stringable",
                    bufferLimit=64, apiMask=hello["comMask"], followChildren=False, instructionEngine=True)
                with open_trace(database) as connection:
                    rows = connection.execute("SELECT c.output,c.result,c.flags,length(c.arguments) "
                        "FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api "
                        "WHERE a.name='ABI::Windows::Foundation::IStringable::ToString' "
                        "AND c.ended IS NOT NULL").fetchall()
                    assert len(rows) == 1 and rows[0][1] == 0 and not rows[0][2] & 257 and rows[0][3] == 16, rows
                    text = 'Private namespaced WinRT capture'.encode('utf-16-le')
                    assert snapshots(rows[0][0], 1, 1) == [(0, len(text), text)], rows[0]

                # Local C++/WinRT projections expose their first ABI call and typed bounded output without queries.
                for limit in (16, 64):
                    database = str(pathlib.Path(temporary) / f"private-projected-{limit}.db")
                    collector.capture(database=database, executable=str(target_path),
                                      arguments="--private-projected", bufferLimit=limit,
                                      apiMask=hello["comMask"], followChildren=False, instructionEngine=True)
                    collector.require_exited(database)
                    with open_trace(database) as connection:
                        rows = connection.execute("SELECT c.output,c.result,c.flags,length(c.arguments),a.parameters "
                            "FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api "
                            "WHERE a.name='ABI::Windows::Foundation::IStringable::ToString' "
                            "AND c.ended IS NOT NULL").fetchall()
                        assert len(rows) == 1 and rows[0][1] == 0 and not rows[0][2] & 257 and rows[0][3] == 16, rows
                        assert 'HSTRING * value' in rows[0][4], rows[0]
                        text = 'Private projected WinRT capture'.encode('utf-16-le')
                        assert snapshots(rows[0][0], 1, 1) == [
                            (int(len(text) > limit), len(text), text[:limit])], rows[0]
                        names = connection.execute("SELECT a.name FROM calls c JOIN apis a "
                            "ON a.target=c.target AND a.id=c.api").fetchall()
                        assert all(name == 'ABI::Windows::Foundation::IStringable::ToString' or
                            name.startswith(('IUnknown::', 'IInspectable::')) for name, in names), names

                # Inferred raw methods support exact entry/return stops and edits through the ordinary IPC path.
                database = str(pathlib.Path(temporary) / "private-edits.db")
                collector.call("launch", database=database, executable=str(target_path), arguments="--private-edit",
                               bufferLimit=64, apiMask=hello["comMask"], followChildren=False, instructionEngine=True,
                               entryMask=hello["comMask"])
                stopped = collector.wait(lambda value: value["finished"] or value["breakpoint"] and
                    value["stoppedCall"]["name"] == 'PrivateInterfaces::Probe [RTTI]::slot 3')
                assert stopped["breakpoint"] and stopped["stoppedCall"]["name"].endswith("::slot 3"), stopped
                previous_call = stopped["stoppedCall"]["id"]
                collector.call("continue")
                stopped = collector.wait(lambda value: value["finished"] or value["breakpoint"] and
                    value["stoppedCall"]["id"] != previous_call and
                    value["stoppedCall"]["name"] == 'PrivateInterfaces::Probe [RTTI]::slot 4')
                call = stopped["stoppedCall"]
                assert stopped["breakpoint"] and call["name"] == 'PrivateInterfaces::Probe [RTTI]::slot 4', stopped
                collector.call("breaks", entryMask=0, exitMask=0)
                collector.call("breakApi", entryApi=-1, exitApi=call["api"])
                arguments = call["arguments"].copy()
                arguments[1] = '0x2233445566778899'
                collector.call("continue", arguments=arguments)
                stopped = collector.wait(lambda value: value["finished"] or value["breakpoint"] and
                    value["leaving"] and value["stoppedCall"]["id"] == call["id"])
                assert stopped["breakpoint"] and stopped["leaving"] and \
                    int(stopped["stoppedCall"]["result"], 16) == (0x2233445566778899 ^ 0x0123456789ABCDEF), stopped
                collector.call("breakApi", entryApi=-1, exitApi=-1)
                collector.call("continue", result='0x1122334455667788')
                collector.wait(lambda value: value["finished"])
                collector.require_exited(database)
                with open_trace(database) as connection:
                    row = connection.execute("SELECT arguments,result,flags FROM calls WHERE api=?",
                                             (call["api"],)).fetchone()
                    assert struct.unpack_from('<Q', row[0], 8)[0] == 0x2233445566778899 and \
                        row[1] == 0x1122334455667788 and row[2] & 16, row

            # A discovered interface method supports the same exact entry and return breakpoints as exports.
            database = str(pathlib.Path(temporary) / "breakpoints.db")
            invoke_id = catalog["IDispatch::Invoke"]["id"]
            collector.call("launch", database=database, executable=str(target_path), bufferLimit=64,
                           apiMask=hello["comMask"], followChildren=False, entryApi=invoke_id, exitApi=invoke_id,
                           instructionEngine=instructions)
            stopped = collector.wait(lambda value: value["breakpoint"] or value["finished"])
            assert stopped["breakpoint"] and not stopped["leaving"], stopped
            assert len(stopped["stoppedCall"]["arguments"]) == 9, stopped
            collector.call("breakApi", entryApi=-1, exitApi=invoke_id)
            collector.call("continue")
            stopped = collector.wait(lambda value: (value["breakpoint"] and value["leaving"]) or value["finished"])
            assert stopped["breakpoint"] and stopped["leaving"], stopped
            collector.call("breakApi", entryApi=-1, exitApi=-1)
            collector.call("continue")
            collector.wait(lambda value: value["finished"])
            page = collector.call("page", database=database, limit=1)
            assert all(target["state"] == "Exited" for target in page["targets"]), page["targets"]
        except Exception:
            # A failed observer must not leave this test's owned fixture consuming resources after IPC disconnects.
            try:
                targets = collector.call("page", database=database, limit=1)["targets"]
                for target in targets:
                    if target["state"] == "Capturing":
                        os.kill(target["pid"], signal.SIGTERM)
            except (AssertionError, OSError, RuntimeError):
                pass
            raise
        finally:
            collector.close()


def check_parameterized(collector_path, target_path, root):
    with Collector(collector_path) as collector:
        hello = collector.call('hello')
        for limit in (16, 64):
            database = str(root / f'parameterized-{limit}.sqlite')
            collector.call('launch', database=database, executable=str(target_path), arguments='--private-generic',
                           bufferLimit=limit, apiMask=hello['comMask'], followChildren=False, instructionEngine=True)
            collector.wait(lambda value: value['finished'], timeout=45)
            collector.require_exited(database)
            with open_trace(database) as connection:
                def observed(name):
                    rows = connection.execute('SELECT c.input,c.output,c.flags,c.result,a.parameters,c.arguments '
                        'FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api '
                        'WHERE a.name=? AND c.ended IS NOT NULL', (name,)).fetchall()
                    assert rows and all(not row[2] & 257 and row[3] == 0 for row in rows), (name, rows)
                    return rows

                foundation = 'ABI::Windows::Foundation::'
                integer = observed(foundation + 'IReference<int32_t>::get_Value')[0]
                assert snapshots(integer[1], 1, 2) == [(0, 4, struct.pack('<I', 0x51A17E01))], integer
                text = observed(foundation + 'IReference<HSTRING>::get_Value')[0]
                expected = 'Parameterized WinRT capture'.encode('utf-16-le')
                assert snapshots(text[1], 1, 1) == [(int(len(expected) > limit), len(expected), expected[:limit])], text
                guid = observed(foundation + 'IReference<GUID>::get_Value')[0]
                expected_guid = struct.pack('<IHH8B', 0x12345678, 0x4321, 0xABCD, 1, 2, 3, 4, 5, 6, 7, 8)
                assert snapshots(guid[1], 1, 0) == [(0, 16, expected_guid)], guid
                vector = foundation + 'Collections::IVectorView<int32_t>::'
                at = observed(vector + 'GetAt')[0]
                assert len(at[5]) == 24 and snapshots(at[1], 2, 2) == [(0, 4, struct.pack('<I', 0x31415903))], at
                observed(vector + 'get_Size')
                index = observed(vector + 'IndexOf')[0]
                assert snapshots(index[1], 2, 2) == [(0, 4, struct.pack('<I', 7))], index
                assert snapshots(index[1], 3, 2) == [(0, 1, b'\1')], index
                many = observed(vector + 'GetMany')[0]
                expected_array = struct.pack('<32I', *range(0x31415900, 0x31415920))
                assert not snapshots(many[0], 3, 0), many
                assert snapshots(many[1], 3, 0) == [(1, 128, expected_array[:limit])], many
                assert snapshots(many[1], 4, 2) == [(0, 4, struct.pack('<I', 32))], many
                assert 'capacity' in many[4] and 'actual' in many[4], many[4]
                assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
                assert not connection.execute(
                    "SELECT count(*) FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api "
                    "WHERE a.name LIKE '%::QueryInterface'").fetchone()[0]
            if limit == 64:
                details = {}
                for key, name in [('integer', foundation + 'IReference<int32_t>::get_Value'),
                                  ('text', foundation + 'IReference<HSTRING>::get_Value'),
                                  ('guid', foundation + 'IReference<GUID>::get_Value'),
                                  ('many', vector + 'GetMany')]:
                    call = collector.call('page', database=database, api=name, limit=1)['calls'][0]
                    details[key] = collector.call('details', database=database,
                        target=call['target'], callId=call['id'])
                (root / 'details.json').write_text(json.dumps(details), encoding='utf-8')
            print(f'Parameterized WinRT capture passed with {limit}-byte buffers.', flush=True)

        # A private closed interface reaches entry and return breakpoints on its first call.
        database = str(root / 'parameterized-breakpoints.sqlite')
        collector.call('launch', database=database, executable=str(target_path), arguments='--private-generic',
                       bufferLimit=64, apiMask=hello['comMask'], entryMask=hello['comMask'],
                       followChildren=False, instructionEngine=True)
        stopped = collector.wait(lambda value: value['finished'] or value['breakpoint'])
        name = 'ABI::Windows::Foundation::IReference<int32_t>::get_Value'
        assert stopped['breakpoint'] and not stopped['leaving'] and stopped['stoppedCall']['name'] == name, stopped
        call = stopped['stoppedCall']
        assert len(call['arguments']) == 2, call
        collector.call('breaks', entryMask=0, exitMask=0)
        collector.call('breakApi', entryApi=-1, exitApi=call['api'])
        collector.call('continue')
        stopped = collector.wait(lambda value: value['finished'] or value['breakpoint'] and
                                value['leaving'] and value['stoppedCall']['id'] == call['id'])
        assert stopped['breakpoint'] and stopped['leaving'] and int(stopped['stoppedCall']['result'], 16) == 0, stopped
        collector.call('breakApi', entryApi=-1, exitApi=-1)
        collector.call('continue')
        collector.wait(lambda value: value['finished'])
        collector.require_exited(database)
        print('Parameterized WinRT first-call entry and return breakpoints passed.', flush=True)

        for limit in (16, 64):
            database = str(root / f'collections-{limit}.sqlite')
            collector.call('launch', database=database, executable=str(target_path), arguments='--generic-collections',
                           bufferLimit=limit, apiMask=hello['comMask'], followChildren=False, instructionEngine=True)
            collector.wait(lambda value: value['finished'], timeout=45)
            collector.require_exited(database)
            with open_trace(database) as connection:
                def observed(name):
                    rows = connection.execute('SELECT c.arguments,c.input,c.output,c.flags,c.result,a.parameters '
                        'FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api '
                        'WHERE a.name=? AND c.ended IS NOT NULL', (name,)).fetchall()
                    assert rows and all(not row[3] & 257 and row[4] == 0 for row in rows), (name, rows)
                    return rows

                prefix = 'ABI::Windows::Foundation::Collections::'
                vector = prefix + 'IVector<float>::'
                for method in ('Append', 'InsertAt', 'SetAt', 'get_Size', 'IndexOf', 'GetView', 'GetAt',
                               'RemoveAt', 'RemoveAtEnd', 'Clear', 'GetMany', 'ReplaceAll'):
                    observed(vector + method)
                append = observed(vector + 'Append')
                assert {row[0][8:12] for row in append} == {struct.pack('<f', 1.25), struct.pack('<f', 2.5)}, append
                index = observed(vector + 'IndexOf')[0]
                assert index[0][8:12] == struct.pack('<f', 3.75), index
                assert snapshots(index[2], 2, 2) == [(0, 4, struct.pack('<I', 1))], index
                assert snapshots(index[2], 3, 2) == [(0, 1, b'\1')], index
                observed(prefix + 'IVectorView<float>::GetAt')
                first = observed(prefix + 'IIterable<float>::First')[0]
                assert 'IIterator<float> ** iterator' in first[5], first[5]
                for method in ('get_HasCurrent', 'get_Current', 'MoveNext', 'GetMany'):
                    observed(prefix + 'IIterator<float>::' + method)
                iterator = observed(prefix + 'IIterator<float>::GetMany')[0]
                assert snapshots(iterator[2], 2, 0) == [(0, 8, struct.pack('<2f', 3.75, 2.5))], iterator
                many = observed(vector + 'GetMany')[0]
                assert snapshots(many[2], 3, 0) == [(0, 12, struct.pack('<3f', 0.625, 3.75, 2.5))], many
                replace = observed(vector + 'ReplaceAll')[0]
                data = struct.pack('<6f', 0.125, 0.25, 0.5, 1.0, 2.0, 4.0)
                assert snapshots(replace[1], 2, 0) == [(int(len(data) > limit), len(data), data[:limit])], replace
                assert not snapshots(replace[2], 2, 0), replace
                assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
            print(f'Parameterized collections and floating inputs passed with {limit}-byte buffers.', flush=True)

        for limit in (16, 64):
            database = str(root / f'reference-arrays-{limit}.sqlite')
            collector.call('launch', database=database, executable=str(target_path), arguments='--reference-arrays',
                           bufferLimit=limit, apiMask=hello['comMask'], followChildren=False, instructionEngine=True)
            collector.wait(lambda value: value['finished'], timeout=45)
            collector.require_exited(database)
            with open_trace(database) as connection:
                for value, expected in [('int32_t', struct.pack('<32I', *range(0x41525200, 0x41525220))),
                    ('GUID', b''.join(struct.pack('<IHH8B', 0x12345678 + index, 0x4321, 0xABCD,
                        1, 2, 3, 4, 5, 6, 7, 8) for index in range(9)))]:
                    name = 'ABI::Windows::Foundation::IReferenceArray<' + value + '>::get_Value'
                    rows = connection.execute('SELECT c.input,c.output,c.flags,c.result,a.parameters,c.arguments '
                        'FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api '
                        'WHERE a.name=? AND c.ended IS NOT NULL', (name,)).fetchall()
                    assert len(rows) == 1 and not rows[0][2] & 257 and rows[0][3] == 0, (name, rows)
                    before, after, _, _, parameters, arguments = rows[0]
                    count = 32 if value == 'int32_t' else 9
                    assert len(arguments) == 24 and 'count' in parameters and 'items' in parameters, rows[0]
                    assert not snapshots(before, 2, 0), rows[0]
                    assert snapshots(after, 1, 2) == [(0, 4, struct.pack('<I', count))], rows[0]
                    assert snapshots(after, 2, 0) == [(1, len(expected), expected[:limit])], rows[0]
                    pointer = snapshots(after, 2, 2)
                    assert len(pointer) == 1 and struct.unpack('<Q', pointer[0][2])[0], pointer
                assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
                assert not connection.execute("SELECT count(*) FROM calls c JOIN apis a ON a.target=c.target "
                    "AND a.id=c.api WHERE a.name LIKE '%::QueryInterface'").fetchone()[0]
            if limit == 64:
                details = {}
                for value in ('int32_t', 'GUID'):
                    name = 'ABI::Windows::Foundation::IReferenceArray<' + value + '>::get_Value'
                    call = collector.call('page', database=database, api=name, limit=1)['calls'][0]
                    details[value] = collector.call('details', database=database,
                        target=call['target'], callId=call['id'])
                (root / 'array-details.json').write_text(json.dumps(details), encoding='utf-8')
            print(f'Returned reference arrays passed with {limit}-byte buffers.', flush=True)

            database = str(root / f'maps-{limit}.sqlite')
            collector.call('launch', database=database, executable=str(target_path), arguments='--generic-maps',
                           bufferLimit=limit, apiMask=hello['comMask'], followChildren=False, instructionEngine=True)
            collector.wait(lambda value: value['finished'], timeout=45)
            collector.require_exited(database)
            with open_trace(database) as connection:
                def observed(name, failures=False):
                    rows = connection.execute('SELECT c.arguments,c.input,c.output,c.flags,c.result,a.parameters '
                        'FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api '
                        'WHERE a.name=? AND c.ended IS NOT NULL', (name,)).fetchall()
                    assert rows and all(not row[3] & 256 for row in rows), (name, rows)
                    assert failures or all(not row[3] & 1 and row[4] == 0 for row in rows), (name, rows)
                    return rows
                prefix = 'ABI::Windows::Foundation::Collections::'
                mapping = prefix + 'IMap<HSTRING, double>::'
                for method in ('Insert', 'Lookup', 'get_Size', 'HasKey', 'GetView', 'Remove', 'Clear'):
                    observed(mapping + method)
                inserts = observed(mapping + 'Insert')
                assert {row[0][16:24] for row in inserts} == {struct.pack('<d', value)
                    for value in (3.125, 6.25, 12.5)}, inserts
                key = b'K\0' * 96
                assert any(snapshots(row[1], 1, 1) == [(1, 192, key[:limit])] for row in inserts), inserts
                assert {snapshots(row[2], 3, 2)[0][2] for row in inserts} == {b'\0', b'\1'}, inserts
                view = prefix + 'IMapView<HSTRING, double>::'
                observed(view + 'get_Size')
                observed(view + 'HasKey')
                observed(view + 'Split')
                lookups = observed(view + 'Lookup', failures=True)
                assert any(row[3] & 1 and row[4] == 0x8000000B and not row[2] for row in lookups), lookups
                pair_type = prefix + 'IKeyValuePair<HSTRING, double>'
                iterator = prefix + 'IIterator<' + pair_type + '>::'
                iterable = prefix + 'IIterable<' + pair_type + '>::'
                observed(iterable + 'First')
                for method in ('get_Current', 'get_HasCurrent', 'MoveNext', 'GetMany'):
                    observed(iterator + method)
                many = observed(iterator + 'GetMany')[0]
                pointers = snapshots(many[2], 2, 0)
                assert len(pointers) == 1 and pointers[0][0:2] == (0, 16) and len(pointers[0][2]) == 16, many
                assert all(struct.unpack_from('<Q', pointers[0][2], offset)[0] for offset in (0, 8)), many
                observed(pair_type + '::get_Key')
                observed(pair_type + '::get_Value')
                guid_map = prefix + 'IMap<GUID, HSTRING>::'
                guid = struct.pack('<IHH8B', 0x12345678, 0x4321, 0xABCD, 1, 2, 3, 4, 5, 6, 7, 8)
                inserted = observed(guid_map + 'Insert')[0]
                assert snapshots(inserted[1], 1, 0) == [(0, 16, guid)], inserted
                assert snapshots(inserted[1], 2, 1) == [(1, 192, b'V\0' * (limit // 2))], inserted
                looked_up = observed(guid_map + 'Lookup')[0]
                assert snapshots(looked_up[2], 2, 1) == [(1, 192, b'V\0' * (limit // 2))], looked_up
                observed(guid_map + 'HasKey')
                assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
            print(f'Map contracts, nested iterator outputs and HRESULT failures passed at {limit} bytes.', flush=True)

        database = str(root / 'reference-array-breakpoints.sqlite')
        collector.call('launch', database=database, executable=str(target_path), arguments='--reference-arrays',
                       bufferLimit=64, apiMask=hello['comMask'], entryMask=hello['comMask'],
                       followChildren=False, instructionEngine=True)
        stopped = collector.wait(lambda value: value['finished'] or value['breakpoint'])
        name = 'ABI::Windows::Foundation::IReferenceArray<int32_t>::get_Value'
        assert stopped['breakpoint'] and not stopped['leaving'] and stopped['stoppedCall']['name'] == name, stopped
        call = stopped['stoppedCall']
        assert len(call['arguments']) == 3, call
        collector.call('breaks', entryMask=0, exitMask=0)
        collector.call('breakApi', entryApi=-1, exitApi=call['api'])
        collector.call('continue')
        stopped = collector.wait(lambda value: value['finished'] or value['breakpoint'] and
                                value['leaving'] and value['stoppedCall']['id'] == call['id'])
        assert stopped['breakpoint'] and stopped['leaving'] and int(stopped['stoppedCall']['result'], 16) == 0, stopped
        collector.call('breakApi', entryApi=-1, exitApi=-1)
        collector.call('continue')
        collector.wait(lambda value: value['finished'])
        collector.require_exited(database)
        print('Reference-array first-call entry and return breakpoints passed.', flush=True)


def check_winrt_structures(collector_path, target_path, root, catalog=None):
    baseline = subprocess.run([str(target_path), '--generic-structures'], capture_output=True,
                              timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
    assert baseline.returncode == 0, (baseline.returncode, baseline.stdout, baseline.stderr)
    if catalog:
        import os
        environment = dict(os.environ, DETOURIST_API_CATALOG=str(catalog))
    else:
        environment = None
    collector = Collector(collector_path, env=environment)
    details = []
    foundation = 'ABI::Windows::Foundation::'
    structures = {
        foundation + 'Point': struct.pack('<2f', 1.25, -2.5),
        foundation + 'Rect': struct.pack('<4f', 1.25, -2.5, 32, 64),
        foundation + 'DateTime': struct.pack('<q', 11223344556677),
        foundation + 'TimeSpan': struct.pack('<q', -11223344556677),
        foundation + 'Numerics::Vector3': struct.pack('<3f', 1.25, -2.5, 3.75),
        foundation + 'Numerics::Matrix4x4': struct.pack('<16f', *range(1, 17)),
    }
    try:
        hello = collector.call('hello')
        for limit in (16, 64):
            database = root / f'structures-{limit}.db'
            assert not database.exists(), database
            status = collector.capture(database=str(database), executable=str(target_path),
                arguments='--generic-structures', bufferLimit=limit, apiMask=hello['comMask'],
                followChildren=False, instructionEngine=True, timeout=45)
            targets = collector.call('page', database=str(database), limit=1)['targets']
            assert targets and all(item['state'] == 'Exited' for item in targets), (status, targets)
            with open_trace(database, named=True) as connection:

                def observed(name):
                    rows = connection.execute('SELECT c.*,a.name,a.parameters,a.argument_count FROM calls c '
                        'JOIN apis a ON a.target=c.target AND a.id=c.api '
                        'WHERE a.name=? AND c.ended IS NOT NULL', (name,)).fetchall()
                    assert rows and all(not row['flags'] & 257 and row['result'] == 0 for row in rows), name
                    return rows[0]

                # Check exact target-owned structures, including a partially captured matrix.
                for typ, expected in structures.items():
                    row = observed(foundation + 'IReference<' + typ + '>::get_Value')
                    assert row['argument_count'] == 2 and 'value' in row['parameters'], row['parameters']
                    assert snapshots(row['output'], 1, 0) == [
                        (int(len(expected) > limit), len(expected), expected[:limit])], (typ, limit)
                    details.append({'type': typ, 'limit': limit, 'call': collector.call('details',
                        database=str(database), target=row['target'], callId=row['id'])})
                rectangles = observed(foundation + 'IReferenceArray<' + foundation + 'Rect>::get_Value')
                expected = b''.join(struct.pack('<4f', index + 0.25, -2.5, 32, 64) for index in range(8))
                assert snapshots(rectangles['output'], 1, 2) == [(0, 4, struct.pack('<I', 8))]
                assert snapshots(rectangles['output'], 2, 0) == [(1, len(expected), expected[:limit])]
                details.append({'type': 'Rect[]', 'limit': limit, 'call': collector.call('details',
                    database=str(database), target=rectangles['target'], callId=rectangles['id'])})

                # Nested collection boundaries must retain the interface identity and completed element count.
                inner = foundation + 'Collections::IVectorView<int32_t>'
                outer = foundation + 'Collections::IVector<' + inner + '>::'
                for method in ('Append', 'get_Size', 'GetAt', 'GetMany'):
                    observed(outer + method)
                iterable = foundation + 'Collections::IIterable<' + inner + '>::'
                iterator = foundation + 'Collections::IIterator<' + inner + '>::'
                observed(iterable + 'First')
                observed(iterator + 'get_HasCurrent')
                observed(iterator + 'get_Current')
                many = observed(outer + 'GetMany')
                assert snapshots(many['output'], 4, 2) == [(0, 4, struct.pack('<I', 1))]
                pointers = snapshots(many['output'], 3, 0)
                assert len(pointers) == 1 and pointers[0][:2] == (0, 8) and len(pointers[0][2]) == 8, pointers
                assert int.from_bytes(pointers[0][2], 'little')
                observed(inner + '::GetAt')
                assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
            print(f'WinRT structures, allocated arrays and nested interface outputs passed at {limit} bytes.',
                  flush=True)

        # The first closed structure interface call supports exact entry and return breakpoints.
        database = root / 'breakpoint.db'
        collector.call('launch', database=str(database), executable=str(target_path),
            arguments='--generic-structures', bufferLimit=64, apiMask=hello['comMask'],
            entryMask=hello['comMask'], followChildren=False, instructionEngine=True)
        stopped = collector.wait(lambda value: value['finished'] or value['breakpoint'])
        name = foundation + 'IReference<' + foundation + 'Point>::get_Value'
        assert stopped['breakpoint'] and not stopped['leaving'] and stopped['stoppedCall']['name'] == name, stopped
        call = stopped['stoppedCall']
        collector.call('breaks', entryMask=0, exitMask=0)
        collector.call('breakApi', entryApi=-1, exitApi=call['api'])
        collector.call('continue')
        stopped = collector.wait(lambda value: value['finished'] or value['breakpoint'] and value['leaving'])
        assert stopped['breakpoint'] and stopped['stoppedCall']['id'] == call['id'], stopped
        collector.call('breakApi', entryApi=-1, exitApi=-1)
        collector.call('continue')
        collector.wait(lambda value: value['finished'])
        collector.require_exited(database)
        (root / 'details.json').write_text(json.dumps(details), encoding='utf-8')
        print('Closed structure interface first-call entry and return breakpoints passed.', flush=True)
    finally:
        collector.close()


def check_adsi_structures(collector_path, target_path, artifact=None, catalog=None):
    context = nullcontext(str(artifact)) if artifact else tempfile.TemporaryDirectory(prefix='Detourist-ADSI-Fields-')
    with context as directory:
        root = pathlib.Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        assert not list(root.glob('*.db'))
        baseline = subprocess.run([str(target_path), '--structures', str(root / 'baseline.txt')],
            capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
        assert baseline.returncode == 0, (baseline.returncode, baseline.stderr)
        environment = dict(os.environ, DETOURIST_API_CATALOG=str(catalog)) if catalog else None
        details = []
        with Collector(collector_path, env=environment) as collector:
            hello = collector.call('hello')
            for limit in (16, 64):
                database = root / f'structures-{limit}.db'
                report = root / f'structures-{limit}.txt'
                stopped = collector.capture(database=str(database), executable=str(target_path),
                    arguments=f'--structures "{report}"', apiMask=hello['comMask'], bufferLimit=limit,
                    followChildren=False, instructionEngine=True)
                targets = collector.call('page', database=str(database), limit=1)['targets']
                assert targets and all(target['state'] == 'Exited' for target in targets), (stopped, targets)
                expected = {name: bytes.fromhex(data) for name, data in
                            (line.split(',') for line in report.read_text().splitlines())}
                with open_trace(database, named=True) as connection:
                    rows = connection.execute('SELECT c.*,a.name,a.parameters FROM calls c '
                        'JOIN apis a ON a.target=c.target AND a.id=c.api ORDER BY c.id').fetchall()
                    contracts = [('information', 'IDirectoryObject::GetObjectInformation', 'output', 40),
                        ('attribute', 'IDirectoryObject::SetObjectAttributes', 'input', 32),
                        ('preference', 'IDirectorySearch::SetSearchPreference', 'input', 40)]

                    # Returned pointers and embedded structures match the target's actual bounded bytes.
                    for kind, name, phase, size in contracts:
                        matching = [row for row in rows if row['name'] == name]
                        assert len(matching) == 1, (name, [row['name'] for row in rows])
                        row = matching[0]
                        assert row['ended'] and row['result'] == 0 and not row['flags'] & 257, dict(row)
                        wanted = expected[kind]
                        assert len(wanted) == size
                        assert snapshots(row[phase], 1, 0) == [(int(limit < size), size, wanted[:limit])]
                        if kind == 'information':
                            pointer = snapshots(row['output'], 1, 2)
                            assert len(pointer) == 1 and pointer[0][:2] == (0, 8)
                            assert struct.unpack('<Q', pointer[0][2])[0]
                            assert not row['input']
                        elif kind == 'attribute':
                            assert snapshots(row['output'], 3, 2) == [(0, 4, struct.pack('<I', 1))]
                        else:
                            assert not row['output']
                        detail = collector.call('details', database=str(database),
                            target=row['target'], callId=row['id'])
                        details.append(dict(kind=kind, limit=limit, bytes=wanted.hex(), call=detail))
                    assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
                print(f'ADSI structures: pointer outputs, attributes and nested preferences passed at {limit} bytes.',
                      flush=True)
            (root / 'details.json').write_text(json.dumps(details), encoding='utf-8')


def check_adsi_arrays(collector_path, target_path, artifact=None, baseline=False):
    context = nullcontext(str(artifact)) if artifact else tempfile.TemporaryDirectory(prefix='Detourist-TypedArrays-')
    with context as directory:
        root = pathlib.Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        assert not list(root.glob('*.db'))
        arguments = '--arrays'
        checked = subprocess.run([str(target_path), arguments], capture_output=True, timeout=15,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        assert checked.returncode == 0, (checked.returncode, checked.stderr)
        collector = Collector(collector_path)
        details, reports = [], []
        expected = ['Detourist\0ADSI directory object'.encode('utf-16le'), 'tail\0'.encode('utf-16le'), b'']
        try:
            hello = collector.call('hello')
            for limit in (16, 56, 64):
                database = root / f'arrays-{limit}.db'
                stopped = collector.capture(database=str(database), executable=str(target_path), arguments=arguments,
                    instructionEngine=True, apiMask=hello['comMask'], bufferLimit=limit, followChildren=False)
                targets = collector.call('page', database=str(database), limit=1)['targets']
                assert targets and all(target['state'] == 'Exited' for target in targets), (stopped, targets)
                with open_trace(database, named=True) as connection:
                    calls = connection.execute('SELECT c.*,a.name FROM calls c JOIN apis a '
                        'ON a.target=c.target AND a.id=c.api ORDER BY c.id').fetchall()
                    inputs = [row for row in calls if row['name'] == 'IADs::GetInfoEx']
                    outputs = [row for row in calls if row['name'] == 'IADs::GetEx']
                    assert len(inputs) == 5 and len(outputs) == 3, [row['name'] for row in calls]
                    missing = 0

                    # Typed input and output variants expose the same descriptors, bounded elements and strings.
                    for index, row in enumerate(inputs[:4] + outputs[:1]):
                        output = index == 4
                        parameter, phase = (2, 'output') if output else (1, 'input')
                        variant_array = index >= 2
                        tag, size = (12, 72) if variant_array else (8, 24)
                        regions = [region for region in value_records(row[phase])
                                   if region['parameter'] & 255 == parameter]
                        descriptor = [region for region in regions if region['kind'] == 8]
                        assert row['ended'] and row['result'] == 0 and not row['flags'] & 257
                        if baseline:
                            missing += not bool(descriptor)
                            continue
                        data = [region for region in regions if region['kind'] == 9]
                        strings = [region for region in regions if region['flags'] & 32]
                        assert len(descriptor) == len(data) == 1, (index, regions)
                        assert descriptor[0]['total'] == 32 and len(descriptor[0]['bytes']) == min(limit, 32)
                        assert data[0]['total'] == size and len(data[0]['bytes']) == min(limit, size)
                        assert data[0]['flags'] == (tag << 16) | int(limit < size)
                        if limit >= 32:
                            assert struct.unpack_from('<Ii', descriptor[0]['bytes'], 24) == (3, -5)
                        count = (1 if limit == 16 else 2 if limit == 56 else 3) if variant_array else (
                            2 if limit == 16 else 3)
                        assert len(strings) == count, (index, limit, strings)
                        for element, region in enumerate(strings):
                            assert region['kind'] == 1 and region['flags'] >> 16 == element
                            assert region['flags'] & 3 == int(limit < len(expected[element]))
                            assert region['total'] == len(expected[element]) and \
                                region['bytes'] == expected[element][:limit]
                        assert not [region for region in value_records(row['input' if output else 'output'])
                                    if region['kind'] in (8, 9)]
                        details.append(dict(index=index, limit=limit, parameter=parameter, output=output,
                            variantArray=variant_array, call=collector.call('details', database=str(database),
                                target=row['target'], callId=row['id'])))
                    assert not [region for region in value_records(inputs[4]['input']) if region['kind'] in (8, 9)]
                    assert outputs[1]['flags'] & 1 and outputs[1]['result'] == 0x80004005
                    assert not outputs[1]['output'], 'A failed method captured unchanged output bytes.'
                    assert not outputs[2]['flags'] & 257 and outputs[2]['result'] == 0
                    assert not [region for region in value_records(outputs[2]['output']) if region['kind'] in (8, 9)], (
                        'An unreadable array pointer fabricated descriptors or elements.')
                    for row in calls:
                        for phase in ('input', 'output'):
                            assert all(len(region['bytes']) <= limit for region in value_records(row[phase]))
                    assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
                    reports.append(dict(limit=limit, missingArrayCaptures=missing))
                print(f'Typed VARIANT arrays: cap={limit}, missing={missing}.', flush=True)
            (root / 'details.json').write_text(json.dumps(details), encoding='utf-8')
            (root / 'results.json').write_text(json.dumps(reports, indent=2), encoding='utf-8')
        finally:
            collector.close()


def check_base_tails(collector_path, target_path, artifact=None, baseline=False):
    context = nullcontext(str(artifact)) if artifact else tempfile.TemporaryDirectory(prefix='Detourist-COM-Tails-')
    with context as directory:
        root = pathlib.Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        checked = subprocess.run([str(target_path), 'base-tail'], capture_output=True, timeout=15,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        assert checked.returncode == 0, (checked.returncode, checked.stderr)
        results = []
        with Collector(collector_path) as collector:
            hello = collector.call('hello')
            name = '{00000000-0000-0000-c000-000000000046}::slot '
            cases = [(16, []), (64, []), (16, ['IDispatch::Invoke']), (64, [name + '3'])]
            for index, (limit, excluded) in enumerate(cases):
                database = root / f'tails-{index}.db'
                assert not database.exists(), database
                started = time.perf_counter()
                collector.capture(database=str(database), executable=str(target_path), arguments='base-tail',
                    apiMask=hello['comMask'], bufferLimit=limit, followChildren=False, instructionEngine=True,
                    excludedApis=excluded, timeout=45)
                collector.require_exited(database)
                with open_trace(database, named=True) as connection:
                    rows = connection.execute('SELECT c.*,coalesce(d.name,a.name) name FROM calls c '
                        'LEFT JOIN apis d ON d.id=c.api AND d.target=c.target '
                        'LEFT JOIN apis a ON a.id=c.api AND a.target=0 ORDER BY c.started').fetchall()
                    counts = [row for row in rows if row['name'] == name + '3']
                    invokes = [row for row in rows if row['name'] == name + '6']
                    typed = [row for row in rows if row['name'] == 'IDispatch::GetTypeInfoCount']
                    result = dict(limit=limit, excluded=excluded, rawCountCalls=len(counts),
                                  rawInvokeCalls=len(invokes), typedCountCalls=len(typed),
                                  elapsedSeconds=round(time.perf_counter() - started, 3))
                    results.append(result)
                    if baseline:
                        continue
                    assert len(counts) == (0 if index == 3 else 3) and len(invokes) == 3, result
                    assert not typed, 'An observed base interface cannot establish its derived signature.'
                    assert all(row['ended'] and row['flags'] & 256 and len(row['arguments']) == 160
                               for row in counts + invokes), result
                    assert len({row['arguments'][:8] for row in invokes}) == 3, result
                    assert all(row['result'] == 0 for row in counts + invokes), result
                    assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
                    assert all(not row['name'].endswith('slot 7') for row in rows), result
                    for row in rows:
                        check_limit((row['input'], row['output']), limit, result)
                print(f'COM base-interface tails: {result} passed.', flush=True)
            if not baseline:
                # A raw tail remains available at the first method breakpoint after its base pointer is returned.
                database = root / 'first-tail-breakpoint.db'
                collector.call('launch', database=str(database), executable=str(target_path), arguments='base-tail',
                    apiMask=hello['comMask'], bufferLimit=16, followChildren=False, instructionEngine=True,
                    entryMask=hello['comMask'])
                previous = -1
                for attempt in range(50):
                    stopped = collector.wait(lambda item: item['finished'] or item['breakpoint'] and
                        item['stoppedCall']['id'] != previous and
                        item['stoppedCall']['name'] not in ('Unknown API', 'Discovered API'), timeout=30)
                    assert stopped['breakpoint'], stopped
                    call = stopped['stoppedCall']
                    if call['name'] == name + '3':
                        assert len(call['arguments']) == 20 and not stopped['leaving'], stopped
                        break
                    previous = call['id']
                    collector.call('continue')
                else:
                    raise AssertionError('The first derived method was not available at an entry breakpoint.')
                collector.call('breaks', entryMask=0, exitMask=0)
                collector.call('continue')
                collector.wait(lambda item: item['finished'], timeout=45)
                collector.require_exited(database)
                print('COM base-interface tails: first raw method entry breakpoint passed.', flush=True)
            # IInspectable contributes six declared slots; its next slot must not acquire a factory signature.
            for limit in (16, 64):
                database = root / f'inspectable-{limit}.db'
                collector.call('launch', database=str(database), executable=str(target_path), arguments='inspect-tail',
                    apiMask=hello['comMask'], bufferLimit=limit, followChildren=False, instructionEngine=True)
                collector.wait(lambda item: item['finished'], timeout=45)
                collector.require_exited(database)
                with open_trace(database) as connection:
                    rows = connection.execute('SELECT coalesce(d.name,a.name),c.arguments,c.result,c.flags,c.ended '
                        'FROM calls c LEFT JOIN apis d ON d.id=c.api AND d.target=c.target '
                        'LEFT JOIN apis a ON a.id=c.api AND a.target=0').fetchall()
                    calls = [row for row in rows if row[0].endswith('::slot 6')]
                    results.append(dict(interface='IInspectable', limit=limit, rawDerivedCalls=len(calls)))
                    if baseline:
                        continue
                    assert len(calls) == 1, rows
                    name, arguments, result, flags, ended = calls[0]
                    assert len(arguments) == 160 and result == 0x1122334455667789 and flags & 256 and ended, calls
                    assert struct.unpack_from('<Q', arguments, 8)[0] == 0x1122334455667788, calls
                    assert sum(row[0] == 'IInspectable::GetIids' for row in rows) == 1, rows
                    assert not any(row[0] == 'IActivationFactory::ActivateInstance' for row in rows), rows
                    assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
                print(f'COM base-interface tails: IInspectable cap={limit}, raw result and signature passed.',
                      flush=True)
            if not baseline:
                database = root / 'changing-tail.db'
                collector.capture(database=str(database), executable=str(target_path), arguments='changing-tail',
                    apiMask=hello['comMask'], bufferLimit=16, followChildren=False, instructionEngine=True, timeout=45)
                collector.require_exited(database)
                with open_trace(database) as connection:
                    rows = connection.execute('SELECT a.name,c.result,c.flags,c.ended,c.api FROM calls c JOIN apis a '
                        "ON a.id=c.api AND a.target=c.target WHERE a.name LIKE '%::slot 6'").fetchall()
                    assert len(rows) == 3 and len({row[4] for row in rows}) == 3 and {row[1] for row in rows} == {
                        0x1122334455667789, 0x112233445566778A}, rows
                    assert all(row[2] & 256 and row[3] for row in rows), rows
                    assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
                results.append(dict(interface='IInspectable', changingTable=True, rawDerivedCalls=3))
                print('COM base-interface tails: changed methods, stale bindings and reconfirmation passed.',
                      flush=True)
            if not baseline:
                database = root / 'concurrent-tail.db'
                collector.capture(database=str(database), executable=str(target_path),
                    arguments='concurrent-tail', apiMask=hello['comMask'], bufferLimit=16,
                    followChildren=False, instructionEngine=True, timeout=45)
                collector.require_exited(database)
                with open_trace(database) as connection:
                    rows = connection.execute('SELECT c.tid,c.result,c.ended FROM calls c JOIN apis a '
                        "ON a.id=c.api AND a.target=c.target WHERE a.name LIKE '%::slot 6'").fetchall()
                    assert len(rows) == 8 and len({row[0] for row in rows}) == 8, rows
                    assert all(row[1] == (0x1122334455667788 ^ 55) and row[2] for row in rows), rows
                    assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
                results.append(dict(interface='IInspectable', concurrentFirstCalls=8, rawDerivedCalls=8))
                print('COM base-interface tails: concurrent first calls on all eight threads passed.', flush=True)
            (root / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')


def check_attach(collector_path, target_path, artifact=None):
    context = nullcontext(str(artifact)) if artifact else tempfile.TemporaryDirectory(prefix='Detourist-COM-Attach-')
    with context as directory:
        root = pathlib.Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        target = subprocess.Popen([str(target_path), 'attach-tail', str(root)], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
        collector = Collector(collector_path)
        results = []
        try:
            hello = collector.call('hello')
            for phase in range(3):
                wait_file(root / f'{phase}.ready', target, timeout=20)
                database = root / f'{phase}.db'
                collector.call('attach', pid=target.pid, database=str(database), apiMask=hello['comMask'],
                    bufferLimit=16, followChildren=False, instructionEngine=True)
                state = collector.wait(lambda item: item['capturing'] or item['finished'], timeout=30)
                assert state['capturing'], state
                (root / f'{phase}.go').touch()
                wait_file(root / f'{phase}.done', target, timeout=30)
                collector.call('stop')
                stopped = collector.wait(lambda item: item['finished'], timeout=45)
                code = target.poll()
                assert code is None, (phase, code, stopped, target.stderr.read().decode(errors='replace'))
                with open_trace(database) as connection:
                    rows = connection.execute('SELECT a.name,c.arguments,c.result,c.flags,c.ended FROM calls c '
                        'JOIN apis a ON a.id=c.api AND a.target=c.target '
                        "WHERE a.name LIKE '%::slot 6'").fetchall()
                    assert len(rows) == 1 and rows[0][2] == 0x1122334455667789, rows
                    assert rows[0][3] & 256 and rows[0][4] and len(rows[0][1]) == 160, rows
                    assert struct.unpack_from('<Q', rows[0][1], 8)[0] == 0x1122334455667788, rows
                    diagnostics = connection.execute('SELECT message FROM diagnostics').fetchall()
                    assert not any('failed' in message.casefold() for message, in diagnostics), diagnostics
                results.append(dict(phase=phase, rawCalls=1, processSurvivedDetach=True))
                (root / f'{phase}.release').touch()
                print(f'COM attach: phase {phase}, first derived call and clean detach passed.', flush=True)
            assert target.wait(timeout=20) == 0, target.stderr.read().decode(errors='replace')
            (root / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
        finally:
            if target.poll() is None:
                target.kill()
                target.wait(timeout=10)
            collector.close()


def check_variant_discovery(collector_path, target_path, artifact=None, baseline=False, modes=None):
    context = nullcontext(str(artifact)) if artifact else tempfile.TemporaryDirectory(prefix='Detourist-Discovery-')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    with context as directory:
        root = pathlib.Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        reports = []
        for mode in modes or ('unreadable', 'prefix', 'nested', 'property', 'deep'):
            checked = subprocess.run([str(target_path), '--target', str(root / f'{mode}-plain.result'), mode],
                capture_output=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            assert checked.returncode == 0, (mode, checked.returncode, checked.stderr)
            assert (root / f'{mode}-plain.result').read_bytes() == b'complete'
            collector = Collector(collector_path)
            process = None
            try:
                hello = collector.call('hello')
                database, result = root / f'{mode}.db', root / f'{mode}.result'
                assert not database.exists()
                started = time.monotonic()
                collector.call('launch', database=str(database), executable=str(target_path),
                    arguments=f'--target "{result}" {mode}', instructionEngine=True, apiMask=hello['comMask'],
                    bufferLimit=16, followChildren=False)
                collector.wait(lambda item: item['capturing'] or item['finished'], timeout=15)
                targets = collector.call('page', database=str(database), limit=1)['targets']
                assert len(targets) == 1 and pathlib.Path(targets[0]['image']) == target_path, targets
                process = kernel.OpenProcess(0x100001, False, targets[0]['pid'])
                timed_out = False
                try:
                    collector.wait(lambda item: item['finished'], timeout=5 if baseline else 10)
                except AssertionError as error:
                    if not baseline or not str(error).startswith('Capture timed out:'):
                        raise
                    timed_out = True
                elapsed = time.monotonic() - started
                if timed_out:
                    assert process and kernel.TerminateProcess(process, 99)
                    assert kernel.WaitForSingleObject(process, 5000) == 0
                    collector.wait(lambda item: item['finished'], timeout=10)
                report = dict(mode=mode, seconds=round(elapsed, 3), timedOut=timed_out,
                              completed=result.exists() and result.read_bytes() == b'complete')
                reports.append(report)
                print(f'Variant discovery: {report}', flush=True)
                if baseline:
                    continue
                assert report['completed'], report

                # An invalid nested reference cannot hide a later readable sibling before the inaccessible page.
                with open_trace(database) as db:
                    calls = db.execute('SELECT c.output FROM calls c LEFT JOIN apis d ON d.id=c.api '
                        'AND d.target=c.target LEFT JOIN apis a ON a.id=c.api AND a.target=0 '
                        'WHERE coalesce(d.name,a.name)=? ORDER BY c.started',
                        ('IDispatch::GetTypeInfoCount',)).fetchall()
                    identifiers = [struct.unpack('<I', region['bytes'])[0] for row in calls
                        for region in value_records(row[0]) if region['parameter'] == 1]
                    assert identifiers == ([31, 32] if mode in ('unreadable', 'deep') else [31, 32, 33]), identifiers
                    assert not db.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
            finally:
                if process:
                    if kernel.WaitForSingleObject(process, 0) == 258:
                        kernel.TerminateProcess(process, 99)
                        kernel.WaitForSingleObject(process, 5000)
                    kernel.CloseHandle(process)
                collector.close()
        (root / 'results.json').write_text(json.dumps(reports, indent=2), encoding='utf-8')


def check_property_vectors(collector_path, target, artifact=None, inspector=None):
    context = (nullcontext(str(artifact)) if artifact else
               tempfile.TemporaryDirectory(prefix='Detourist-PropertyVectors-'))
    with context as directory:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        assert not list(root.glob('*.db')), 'Use a fresh capture directory.'
        collector = Collector(collector_path)
        checks, details = [], []
        expected = {'integer-vector': (3, struct.pack('<6i', -7, 0, 42, -(1 << 31), (1 << 31) - 1, 123456)),
            'float-vector': (5, struct.pack('<3d', -3.25, 0.5, 1.125)),
            'bool-vector': (11, struct.pack('<4h', -1, 0, -1, 0)),
            'guid-vector': (72, struct.pack('<IHH8BIHH8B', 0x11223344, 0x5566, 0x7788, 1, 2, 3, 4, 5, 6, 7, 8,
                0x99AABBCC, 0xDDEE, 0xFF00, 8, 7, 6, 5, 4, 3, 2, 1))}
        try:
            hello = collector.call('hello')
            for mode in (*expected, 'vector', 'nested', 'empty-vector', 'invalid-vector', 'cycle', 'failed',
                    'wide-string-vector', 'ansi-string-vector', 'bstr-string-vector'):
                baseline = subprocess.run([str(target), '--target', mode], capture_output=True, timeout=15,
                                          creationflags=subprocess.CREATE_NO_WINDOW)
                assert baseline.returncode == 0, (mode, baseline.stdout, baseline.stderr)
                for limit in ((16, 20, 64) if mode.endswith('-string-vector') else (16, 56, 64)):
                    database = root / f'{mode}-{limit}.db'
                    collector.capture(database=str(database), executable=str(target),
                        arguments=f'--target {mode}', instructionEngine=True, apiMask=hello['comMask'],
                        bufferLimit=limit, followChildren=False)
                    with open_trace(database, named=True) as db:
                        rows = db.execute('SELECT c.*,coalesce(d.name,a.name) name FROM calls c '
                            'LEFT JOIN apis d ON d.id=c.api AND d.target=c.target '
                            'LEFT JOIN apis a ON a.id=c.api AND a.target=0').fetchall()
                    producer = next(row for row in rows if row['name'] == 'IPropertyStore::GetValue')
                    assert producer['ended'] and not producer['flags'] & 256, dict(producer)
                    snapshots = values(producer['output'])
                    descriptors = [value for value in snapshots if value[0] & 255 == 2 and value[1] == 10]
                    data = [value for value in snapshots if value[0] & 255 == 2 and value[1] == 11]
                    if mode in ('cycle', 'failed'):
                        assert not descriptors and not data, (mode, snapshots)
                        checks.append(dict(mode=mode, limit=limit, capturedBytes=0, descriptors=0))
                        continue
                    assert len(descriptors) == len(data) == 1, (mode, snapshots)
                    descriptor, captured = descriptors[0], data[0]
                    assert descriptor[0] == captured[0] and descriptor[3] == 16 and len(descriptor[4]) == 16
                    if mode in expected:
                        kind, wanted = expected[mode]
                        assert captured[2] >> 16 == kind and captured[3] == len(wanted) and \
                            captured[4] == wanted[:limit] and bool(captured[2] & 1) == (len(wanted) > limit), captured
                    elif mode.endswith('-string-vector'):
                        kind = 8 if mode.startswith('bstr') else 30 if mode.startswith('ansi') else 31
                        assert captured[2] >> 16 == kind and captured[3] == 32 and len(captured[4]) == min(32, limit)
                        strings = [value for value in snapshots if value[2] & 32]
                        assert len(strings) == min(4, limit // 8), strings
                        for index, value in enumerate(strings):
                            assert value[0] == descriptor[0] and value[2] >> 16 == index, value
                            if index == 1:
                                assert value[3] == 0 and not value[4] and not value[2] & 2, value
                            elif index == 2:
                                assert value[2] & 2 and not value[4], value
                            else:
                                text = 'counted\0vector text' if kind == 8 else \
                                    ('vector property text' if index == 0 else 'last vector text') + '\0'
                                wanted = text.encode('ascii' if kind == 30 else 'utf-16le')
                                original = len(wanted) if kind == 8 or len(wanted) <= limit else 0
                                assert value[1] == (0 if kind == 30 else 1) and \
                                    value[3:] == (original, wanted[:limit]), value
                    elif mode == 'empty-vector':
                        assert captured[3] == 0 and not captured[4], captured
                    elif mode == 'invalid-vector':
                        assert captured[3] == 72 and captured[2] & 2 and not captured[4], captured
                    else:
                        assert captured[2] >> 16 == 12 and captured[3] == 72 and len(captured[4]) == limit, captured
                        assert struct.unpack_from('<H', captured[4])[0] == 9
                        if limit >= 26: assert struct.unpack_from('<H', captured[4], 24)[0] == 0x4009
                        if limit >= 50: assert struct.unpack_from('<H', captured[4], 48)[0] == 9
                    for row in rows:
                        assert all(len(value[4]) <= limit for value in values(row['input']) + values(row['output']))
                    detail = collector.call('details', database=str(database), target=producer['target'],
                                            callId=producer['id'])
                    vector = next(value for value in detail['output'] if value['kind'] == 10)
                    contents = next(value for value in detail['output'] if value['kind'] == 11)
                    assert vector['parameter'] == contents['parameter'] == 2 and (
                        vector['arrayIndex'] == contents['arrayIndex'])
                    details.append(dict(mode=mode, limit=limit, call=detail))
                    checks.append(dict(mode=mode, limit=limit, capturedBytes=len(captured[4]),
                                       originalBytes=captured[3], kind=captured[2] >> 16))
            (root / 'audit.json').write_text(json.dumps(checks, indent=2), encoding='utf-8')
            (root / 'details.json').write_text(json.dumps(details), encoding='utf-8')
        finally:
            collector.close()
        if inspector:
            inspected = subprocess.run(['dotnet', str(inspector), '--property-vectors', str(root / 'details.json')],
                capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
            (root / 'inspector.log').write_text(inspected.stdout + inspected.stderr, encoding='utf-8')
            assert inspected.returncode == 0, inspected.stdout + inspected.stderr
    print('Property vectors: SDK descriptors, paired payloads, typed contents, failures and global byte bounds passed.')


def main_interfaces():
    parser = path_parser('collector', 'target')
    parser.add_argument("--instructions", action="store_true")
    options = parser.parse_args()
    check_interfaces(options.collector.resolve(), options.target.resolve(), options.instructions)
    print("COM and WinRT integration passed")


def main_parameterized():
    args = path_parser('collector', 'target', '--artifact').parse_args()
    if args.artifact:
        args.artifact.mkdir(parents=True, exist_ok=True)
        check_parameterized(args.collector.resolve(), args.target.resolve(), args.artifact.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix='Detourist-Parameterized-COM-') as temporary:
            check_parameterized(args.collector.resolve(), args.target.resolve(), pathlib.Path(temporary))


def main_winrt_structures():
    options = path_parser('collector', 'target', '--artifact', '--catalog').parse_args()
    if options.artifact:
        options.artifact.mkdir(parents=True, exist_ok=True)
        check_winrt_structures(options.collector.resolve(), options.target.resolve(),
            options.artifact.resolve(), options.catalog)
    else:
        with tempfile.TemporaryDirectory(prefix='Detourist-WinRT-Structures-') as directory:
            check_winrt_structures(options.collector.resolve(), options.target.resolve(),
                pathlib.Path(directory), options.catalog)


def main_adsi_structures():
    arguments = path_parser('collector', 'target', '--artifact', '--catalog').parse_args()
    check_adsi_structures(arguments.collector.resolve(), arguments.target.resolve(),
        arguments.artifact, arguments.catalog)


def main_adsi_arrays():
    parser = path_parser('collector', 'target', '--artifact')
    parser.add_argument('--baseline', action='store_true')
    arguments = parser.parse_args()
    check_adsi_arrays(arguments.collector.resolve(), arguments.target.resolve(), arguments.artifact, arguments.baseline)


def main_base_tails():
    parser = path_parser('collector', 'target', '--artifact')
    parser.add_argument('--baseline', action='store_true')
    options = parser.parse_args()
    check_base_tails(options.collector.resolve(), options.target.resolve(),
        options.artifact.resolve() if options.artifact else None, options.baseline)


def main_attach():
    args = path_parser('collector', 'target', '--artifact').parse_args()
    check_attach(args.collector.resolve(), args.target.resolve(), args.artifact.resolve() if args.artifact else None)


def main_variant_discovery():
    parser = path_parser('collector', 'target', '--artifact')
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--mode', action='append', choices=('unreadable', 'prefix', 'nested', 'property', 'deep'))
    args = parser.parse_args()
    check_variant_discovery(args.collector.resolve(), args.target.resolve(),
        args.artifact.resolve() if args.artifact else None,
        args.baseline, args.mode)


def main_property_vectors():
    options = path_parser('collector', 'target', '--artifacts', '--inspector').parse_args()
    check_property_vectors(options.collector.resolve(), options.target.resolve(),
        options.artifacts.resolve() if options.artifacts else None,
        options.inspector.resolve() if options.inspector else None)


if __name__ == '__main__':
    run_scenarios({
        'interfaces': main_interfaces,
        'parameterized': main_parameterized,
        'winrt_structures': main_winrt_structures,
        'adsi_structures': main_adsi_structures,
        'adsi_arrays': main_adsi_arrays,
        'base_tails': main_base_tails,
        'attach': main_attach,
        'variant_discovery': main_variant_discovery,
        'property_vectors': main_property_vectors,
    })
