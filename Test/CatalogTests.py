import sys
sys.dont_write_bytecode = True

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from TestSupport import run_paths, run_scenarios


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'Build/Scripts'))
from GenerateBuiltinCatalogs import select_architecture

# Rows that plans, rules and interface slots name must exist in the same architecture's view.
REFERENCES = (('plans', 'function_id', 'functions', 'id'), ('builtin_apis', 'function_id', 'functions', 'id'),
    ('builtin_hook_policies', 'function_id', 'functions', 'id'), ('function_rules', 'function_id', 'functions', 'id'),
    ('function_rules', 'source', 'sources', 'id'), ('pending_rules', 'source', 'sources', 'id'),
    ('interface_methods', 'interface_id', 'interfaces', 'id'),
    ('interface_methods', 'function_id', 'plans', 'function_id'),
    ('capture_members', 'function_id', 'plans', 'function_id'),
    ('capture_member_extents', 'function_id,ordinal', 'capture_members', 'function_id,ordinal'),
    ('capture_parameter_extents', 'function_id', 'plans', 'function_id'),
    ('result_captures', 'function_id', 'plans', 'function_id'),
    ('result_success_values', 'function_id', 'plans', 'function_id'),
    ('variadic_prefixes', 'function_id', 'plans', 'function_id'),
    ('function_abis', 'function_id', 'plans', 'function_id'), ('capture_rules', 'kind', 'capture_kinds', 'id'),
    ('sdk_aliases', 'module,name', 'functions', 'module,name'),
    ('sdk_aliases', 'source_module,source_name', 'functions', 'module,name'),
    ('ordinal_exports', 'module,name', 'functions', 'module,name'))


def check_architecture_rows(catalog):
    with closing(sqlite3.connect(catalog.as_uri() + '?mode=ro', uri=True)) as connection:
        assert connection.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        assert not connection.execute('PRAGMA foreign_key_check').fetchall()
        # A row both architectures store identically is kept once, and a key is either shared or specific.
        tables = [name for name, in connection.execute("SELECT name FROM sqlite_schema WHERE type='table' AND "
            "sql LIKE '%architecture IN (0,4,8)%'")]
        assert len(tables) > 20, tables
        for table in tables:
            columns = [name for name, in connection.execute(f"SELECT name FROM pragma_table_xinfo('{table}') "
                "WHERE hidden NOT IN (2,3) AND name<>'architecture'")]
            key = ' AND '.join(f'b."{name}"=a."{name}"' for name, in connection.execute(
                f"SELECT name FROM pragma_table_xinfo('{table}') WHERE pk AND name<>'architecture'"))
            same = ' AND '.join(f'b."{name}" IS a."{name}" COLLATE BINARY' for name in columns)
            overlapping, duplicated = connection.execute('SELECT count(*) FILTER (WHERE a.architecture=0 AND '
                f'b.architecture<>0),count(*) FILTER (WHERE a.architecture=4 AND b.architecture=8 AND {same}) '
                f'FROM "{table}" a JOIN "{table}" b ON {key}').fetchone()
            assert not overlapping and not duplicated, (table, overlapping, duplicated)
    for pointer_size in (4, 8):
        with closing(sqlite3.connect(catalog.as_uri() + '?mode=ro', uri=True)) as connection:
            select_architecture(connection, pointer_size)
            # The inspector resolves Windows SDK aliases and uses published sizes for opaque vendor types.
            layouts = {name: json.loads(layout) for name, layout in connection.execute('SELECT name,layout FROM types')}
            for name, layout in layouts.items():
                assert isinstance(layout.get('size'), int) and layout['size'] >= 0, (pointer_size, name, layout)
                if layout['kind'] == 'Alias':
                    target = layouts.get(layout['element'])
                    if target is not None:
                        assert layout['size'] == target['size'], (pointer_size, name, layout, target)
                    else:
                        assert not name.startswith('ABI::Windows::'), (pointer_size, name, layout)
            version = layouts['ABI::Windows::ApplicationModel::PackageVersion']
            assert [(field['name'], field['offset']) for field in version['fields']] == [
                ('Major', 0), ('Minor', 16), ('Build', 32), ('Revision', 48)], (pointer_size, version)
            for bits in (8, 16, 32, 64):
                for prefix in ('int', 'uint'):
                    assert layouts[f'{prefix}{bits}_t']['size'] == bits // 8, (pointer_size, prefix, bits)
            invalid = connection.execute('SELECT p.function_id,e.key FROM plans p,json_each(p.capture_rules) e '
                'LEFT JOIN capture_rules r ON r.id=e.value WHERE r.id IS NULL LIMIT 1').fetchone()
            assert invalid is None, ('Missing capture rule', pointer_size, invalid)
            # Array parameters decay to pointers, including aliases whose arrays fit in a scalar register.
            for name, signature, count, widths in connection.execute(
                    'SELECT f.name,f.signature,p.argument_count,p.argument_bytes '
                    'FROM functions f JOIN plans p ON p.function_id=f.id'):
                parameters = signature.splitlines()
                fixed_count = len(parameters) - (parameters[-1:] == ['...\t...'])
                assert len(widths) == count == fixed_count, (pointer_size, name, count, widths, parameters)
                for ordinal, parameter in enumerate(parameters):
                    declared = parameter.split('\t', 1)[0]
                    visited = set()
                    while declared in layouts and declared not in visited:
                        visited.add(declared)
                        layout = layouts[declared]
                        if layout['kind'] == 'Array':
                            assert ordinal < len(widths) and widths[ordinal] == pointer_size, \
                                (pointer_size, name, ordinal, declared, widths)
                        if layout['kind'] != 'Alias':
                            break
                        declared = layout['element']
            invalid = connection.execute('SELECT f.name,p.ordinal,p.multiplier FROM capture_parameters p '
                'JOIN functions f ON f.id=p.function_id WHERE p.interface_index<>0 AND (p.flags&64)<>0 '
                'AND p.extent_index<>-1 AND p.multiplier<>?', (pointer_size,)).fetchall()
            assert not invalid, ('Interface pointer array stride differs', pointer_size, invalid)
            for child, columns, parent, keys in REFERENCES:
                match = ' AND '.join(f'p.{key}=c.{column}' for column, key in zip(columns.split(','), keys.split(',')))
                missing = connection.execute(f'SELECT count(*) FROM {child} c WHERE NOT EXISTS '
                    f'(SELECT 1 FROM {parent} p WHERE {match})').fetchone()[0]
                assert not missing, (pointer_size, child, parent, missing)
    print('SQLite integrity, shared rows, references and type layouts passed for x86 and x64.')


def check_x86_metadata(catalog):
    with closing(sqlite3.connect(catalog)) as connection:
        select_architecture(connection, 4)
        # Exact aliases share the canonical contract without hiding distinct DLL layouts.
        assert dict(connection.execute('SELECT alias,module FROM module_aliases')) == {
            'libcrypto-3-x64.dll': 'libcrypto-3.dll', 'libcrypto-1_1-x64.dll': 'libcrypto-1_1.dll',
            'libssl-3-x64.dll': 'libssl-3.dll', 'libssl-1_1-x64.dll': 'libssl-1_1.dll'}
        assert not connection.execute("SELECT 1 FROM functions WHERE module='libcrypto-3-x64.dll' "
            "AND name='CRYPTO_memcmp'").fetchone()
        assert connection.execute('SELECT count(*) FROM function_abis a LEFT JOIN plans p ON p.function_id=a.function_id '
            'WHERE p.function_id IS NULL').fetchone()[0] == 0
        for module in ('x3daudio1_0.dll', 'x3daudio1_*.dll'):
            assert connection.execute('SELECT p.supported FROM functions f JOIN plans p ON p.function_id=f.id '
                "WHERE f.module=? AND f.name='X3DAudioCalculate'", (module,)).fetchone() == (0,)

        # ESENT stack widths follow the x86 SDK, including by-value 64-bit transaction and record counts.
        for name, widths in (('JetBeginSessionW', b'\x04' * 4), ('JetBeginTransaction3', b'\x04\x08\x04'),
                ('JetIndexRecordCount2', b'\x04\x04\x04\x08'), ('JetOSSnapshotAbort', b'\x04\x04')):
            row = connection.execute('SELECT p.argument_bytes,p.supported,a.convention '
                'FROM functions f JOIN plans p ON p.function_id=f.id JOIN function_abis a ON a.function_id=f.id '
                "WHERE f.module='esent.dll' AND f.name=?", (name,)).fetchone()
            assert row == (widths, 1, 2), (name, row)

        # Media buffers use the native record layout, including its pointer-sized fields.
        media = json.loads(connection.execute("SELECT layout FROM types WHERE name='AM_MEDIA_TYPE'").fetchone()[0])
        assert media['size'] == 72 and len(media['fields']) == 9, media
        for name in ('IAMMediaTypeStream::GetFormat', 'IAMMediaTypeStream::SetFormat',
                'IAMMediaTypeSample::GetMediaType', 'IAMMediaTypeSample::SetMediaType'):
            row = connection.execute('SELECT p.bytes FROM capture_parameters p JOIN functions f '
                'ON f.id=p.function_id WHERE f.name=? AND p.ordinal=1', (name,)).fetchone()
            assert row == (72,), (name, row)

        # Each overloaded declaration owns its stack layout, even when another overload has the same name.
        for name in ('IITResultSet::Add', 'IITResultSet::Set', 'IITResultSet::GetColumn',
                'IITPropList::Set', 'IITPropList::SetPersist', 'IITWordWheel::Lookup'):
            rows = connection.execute('SELECT p.argument_count,p.argument_bytes,p.supported,a.convention '
                'FROM functions f JOIN plans p ON p.function_id=f.id '
                'LEFT JOIN function_abis a ON a.function_id=f.id WHERE f.module=\'COM\' AND f.name=?',
                (name,)).fetchall()
            assert len(rows) > 1, (name, rows)
            assert all(widths == bytes([4] * count) and supported == 1 and convention == 2
                for count, widths, supported, convention in rows), (name, rows)

        # COM record returns pass a hidden buffer after the receiver, including small records.
        for name in ('IIndependentFlipFramePresentStatistics::GetOutputAdapterLUID',
                'IIndependentFlipFramePresentStatistics::GetDisplayedTime',
                'IIndependentFlipFramePresentStatistics::GetPresentDuration'):
            rows = connection.execute('SELECT p.supported,p.result_bytes,p.return_buffer_bytes '
                'FROM functions f JOIN plans p ON p.function_id=f.id '
                'WHERE f.module=\'COM\' AND f.name=?', (name,)).fetchall()
            assert rows and all(row == (1, 4, 8) for row in rows), (name, rows)

        # A variadic method has no fixed stack contract.
        for name in ('IAudioProcessingObjectLoggingService::ApoLog', 'ICallFrame::Invoke'):
            rows = connection.execute('SELECT p.supported FROM functions f '
                'JOIN plans p ON p.function_id=f.id WHERE f.module=\'COM\' AND f.name=?', (name,)).fetchall()
            assert rows and all(row == (0,) for row in rows), (name, rows)

        # SDK contracts and export decorations resolve inconsistent imaging proxy reference signatures.
        for name, count in (('IEnumString_Next_WIC_Proxy', 4), ('IEnumString_Reset_WIC_Proxy', 1),
                ('WICCreateColorContext_Proxy', 2)):
            row = connection.execute('SELECT p.argument_count,p.argument_bytes,p.supported,a.convention '
                'FROM functions f JOIN plans p ON p.function_id=f.id '
                'JOIN function_abis a ON a.function_id=f.id WHERE f.module=\'windowscodecs.dll\' AND f.name=?',
                (name,)).fetchone()
            assert row == (count, bytes([4] * count), 1, 2), (name, row)

        # Archived Microsoft declarations name these reserved slots without changing their native widths.
        for name, ordinal, expected in (("IDDVideoPortContainer::CreateVideoPort", 4, "pUnkOuter"),
                ("IDDVideoPortContainer::EnumVideoPorts", 1, "dwFlags")):
            signature, = connection.execute("SELECT signature FROM functions WHERE module='COM' AND name=?",
                (name,)).fetchone()
            assert signature.splitlines()[ordinal].split("\t", 1)[1] == expected, (name, signature)

        # Returned buffers retain x86 pointer sizes, record strides and failure-only capture rules.
        for name, ordinal, expected in (
                ('EapHostPeerInvokeConfigUI', 7, (80, -1, 0, 1, 2, 'FailureEapError')),
                ('SxsLookupClrGuid', 5, (4, -1, 0, 1, 2, 'RequiredSizeLastError')),
                ('MrmPeekResourceIndexerMessages', 1, (0, 2, 4, 12, 34, 'Utf16StringArray')),
                ('IndexFilePath', 4, (0, 3, 4, 8, 34, 'Utf16StringPairs')),
                ('IMediaParamInfo::GetParamText', 2, (0xFFFFFFFF, -1, 0, 1, 42, 'Utf16MultiString')),
                ('IEnumPortableDeviceObjectIDs::Next', 2, (0, 1, 0, 4, 2, 'Utf16StringArray')),
                ('IPortableDeviceManager::GetDevices', 1, (0, 2, 4, 4, 2, 'Utf16StringArray')),
                ('RtmGetFirstRoute', 2, (2, 0, 0, 1, 3, 'RtmBuffer')),
                ('RtmIsRoute', 1, (1, 0, 0, 1, 1, 'RtmBuffer')),
                ('RtmIsRoute', 2, (3, 0, 0, 1, 2, 'RtmBuffer')),
                ('RtmAddRoute', 1, (4, -1, 0, 1, 1, 'RtmBuffer')),
                ('RtmAddRoute', 4, (7, 3, 0, 1, 2, 'RtmBuffer')),
                ('RtmAddRoute', 5, (8, 3, 0, 1, 2, 'RtmBuffer')),
                ('RtmDeleteRoute', 1, (5, -1, 0, 1, 1, 'RtmBuffer')),
                ('RtmDeleteRoute', 3, (9, 2, 0, 1, 2, 'RtmBuffer')),
                ('RtmBlockDeleteRoutes', 2, (6, 1, 0, 1, 1, 'RtmBuffer')),
                ('RtmDequeueRouteChangeMessage', 2, (10, 1, 0, 1, 2, 'RtmBuffer')),
                ('RtmDequeueRouteChangeMessage', 3, (11, 1, 0, 1, 2, 'RtmBuffer')),
                ('RtmEnumerateGetNextRoute', 1, (12, -1, 0, 1, 2, 'RtmBuffer')),
                ('IPrintOemUI::DriverEvent', 3, (0, 2, 0, 1, 1, 'PrinterPayload')),
                ('IPrintOemUI2::DriverEvent', 3, (0, 2, 0, 1, 1, 'PrinterPayload')),
                ('IPrintOemUI2::QueryJobAttributes', 4, (1, 3, 0, 1, 3, 'PrinterPayload')),
                ('ReplyPrinterChangeNotification', 3, (2, -1, 0, 1, 1, 'PrinterPayload')),
                ('GetTenantRestrictionsHostnames', 0, (0, 1, 4, 4, 34, 'Utf16StringArray'))):
            row = connection.execute('SELECT p.bytes,p.extent_index,p.indirect_bytes,p.multiplier,p.flags,p.kind '
                'FROM capture_parameters p JOIN functions f ON f.id=p.function_id '
                'WHERE f.name=? AND p.ordinal=?', (name, ordinal)).fetchone()
            assert row == (*expected[:-1], connection.execute('SELECT id FROM capture_kinds WHERE name=?', (expected[-1],)).fetchone()[0]), (name, row)
        member = connection.execute('SELECT m.pointer_offset,m.flags,e.condition_index,e.condition_mask '
            'FROM capture_members m JOIN functions f ON f.id=m.function_id '
            'JOIN capture_member_extents e ON e.function_id=m.function_id AND e.ordinal=m.ordinal '
            "WHERE f.name='MrmLoadStringOrEmbeddedResource' AND m.parameter=6").fetchone()
        assert member == (4, 162, 5, 3), member
        member = connection.execute('SELECT m.pointer_offset,m.flags FROM capture_members m '
            'JOIN functions f ON f.id=m.function_id '
            "WHERE f.name='SslDeserializeCertificateStore' AND m.parameter=0").fetchone()
        assert member == (4, 5), member
    print('x86 overloads, hidden record results and corrected imaging proxies retain their calling contracts.')


if __name__ == '__main__':
    run_scenarios({'x86_metadata': lambda: run_paths(check_x86_metadata, 'catalog'),
        'architecture_rows': lambda: run_paths(check_architecture_rows, 'catalog')})
