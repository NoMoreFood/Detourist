import sys
sys.dont_write_bytecode = True

import json
import pathlib
import struct
import subprocess
import tempfile
from contextlib import nullcontext

from TestSupport import Collector, path_parser, check_limit, open_trace, run_scenarios, snapshots, value_records


def check_interfaces(collector_path, target_path, artifact=None, baseline=False):
    context = nullcontext(str(artifact)) if artifact else tempfile.TemporaryDirectory(prefix='Detourist-Automation-')
    with context as directory:
        root = pathlib.Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        assert not list(root.glob('*.db')), 'Use a fresh capture directory.'
        results = []
        with Collector(collector_path) as collector:
            hello = collector.call('hello')
            identifiers = {api['name']: api['id'] for api in hello['catalog']}
            cases = [(mode, True) for mode in ('array', 'byref-array', 'nested', 'byref', 'cycle', 'failed', 'unknown')]
            cases += [('input', True), ('input', False)]
            for mode, instructions in cases:
                checked = subprocess.run([str(target_path), mode], capture_output=True, timeout=15,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
                assert checked.returncode == 0, (mode, checked.returncode, checked.stderr)
                for limit in ((16,) if baseline else (16, 64)):
                    database = root / f'{mode}-{int(instructions)}-{limit}.db'
                    collector.capture(database=str(database), executable=str(target_path), arguments=mode,
                        apiMask=hello['comMask'], bufferLimit=limit, followChildren=False,
                        instructionEngine=instructions, timeout=45)
                    collector.require_exited(database)
                    with open_trace(database, named=True) as connection:
                        rows = connection.execute('SELECT c.*,coalesce(d.name,a.name) name FROM calls c '
                            'LEFT JOIN apis d ON d.id=c.api AND d.target=c.target '
                            'LEFT JOIN apis a ON a.id=c.api AND a.target=0 ORDER BY c.started').fetchall()
                        counts = [row for row in rows if row['name'] == 'IDispatch::GetTypeInfoCount']
                        results.append({'mode': mode, 'instructions': instructions, 'limit': limit,
                                        'leafCalls': len(counts)})
                        if baseline:
                            continue
                        expected = 0 if mode in ('cycle', 'failed') else 1 if mode == 'byref' else 3
                        assert len(counts) == expected, (results[-1], rows)
                        assert all(row['ended'] for row in counts), [dict(row) for row in counts]
                        assert all(not row['flags'] & 256 for row in counts), [dict(row) for row in counts]
                        for row in counts:
                            assert snapshots(row['output'], 1, 2) == [(0, 4, bytes(4))], row
                        receivers = {row['arguments'][:8] for row in counts}
                        invokes = [row for row in rows if row['name'] == 'IDispatch::Invoke' and
                                   row['arguments'][:8] in receivers]
                        assert len(invokes) == expected, (mode, invokes)
                        assert all(row['ended'] and not row['flags'] & 256 for row in invokes), invokes
                        for identity, row in enumerate(invokes, 1):
                            values = snapshots(row['output'], 6, 0)
                            assert len(values) == 1 and values[0][:2] == (int(limit < 24), 24), values
                            assert struct.unpack_from('<H', values[0][2])[0] == 19, values
                            assert struct.unpack_from('<I', values[0][2], 8)[0] == identity, values
                        if mode == 'unknown':
                            queries = [row for row in rows if row['name'] == 'IUnknown::QueryInterface' and
                                       row['arguments'][:8] in receivers]
                            assert len(queries) == 3, queries
                            before_query = min(row['started'] for row in queries)
                            references = [row for row in rows if row['name'] == 'IUnknown::AddRef' and
                                row['arguments'][:8] in receivers and row['started'] < before_query]
                            assert len(references) == 3, references
                        assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
                        for row in rows:
                            check_limit((row['input'], row['output']), limit, mode)
                    print(f'Automation interfaces: {mode}, instructions={instructions}, cap={limit} passed.',
                          flush=True)
            if not baseline:
                # Filtering the parent still discovers returned interfaces before their first calls.
                database = root / 'filtered.db'
                collector.capture(database=str(database), executable=str(target_path), arguments='array',
                    apiMask=hello['comMask'], bufferLimit=16, followChildren=False, instructionEngine=True,
                    excludedApis=['IDispatch::Invoke'], timeout=45)
                with open_trace(database) as connection:
                    counts = dict(connection.execute('SELECT a.name,count(*) FROM calls c JOIN apis a '
                        'ON a.id=c.api AND a.target=CASE WHEN c.api<1073741824 THEN 0 ELSE c.target END '
                        'WHERE c.ended IS NOT NULL GROUP BY a.name'))
                    assert 'IDispatch::Invoke' not in counts and counts.get('IDispatch::GetTypeInfoCount') == 3, counts
                print('Automation interfaces: discovery through filtered Invoke passed.', flush=True)

                # The return breakpoint precedes discovery, and the next private method must already be typed.
                database = root / 'breakpoints.db'
                collector.call('launch', database=str(database), executable=str(target_path), arguments='array',
                    apiMask=hello['comMask'], bufferLimit=16, followChildren=False, instructionEngine=True,
                    entryApi=identifiers['IDispatch::Invoke'])
                stopped = collector.wait(lambda item: item['breakpoint'] or item['finished'], timeout=30)
                call = stopped['stoppedCall']
                assert stopped['breakpoint'] and not stopped['leaving'] and call['name'] == 'IDispatch::Invoke', stopped
                collector.call('breakApi', entryApi=-1, exitApi=call['api'])
                collector.call('continue')
                stopped = collector.wait(lambda item: item['finished'] or item['breakpoint'] and
                    item['leaving'] and item['stoppedCall']['id'] == call['id'], timeout=30)
                assert stopped['breakpoint'] and stopped['leaving'], stopped
                collector.call('breakApi', entryApi=identifiers['IDispatch::GetTypeInfoCount'], exitApi=-1)
                collector.call('continue')
                stopped = collector.wait(lambda item: item['finished'] or item['breakpoint'] and
                    not item['leaving'] and item['stoppedCall']['name'] == 'IDispatch::GetTypeInfoCount', timeout=30)
                assert stopped['breakpoint'] and len(stopped['stoppedCall']['arguments']) == 2, stopped
                collector.call('breakApi', entryApi=-1, exitApi=-1)
                collector.call('continue')
                collector.wait(lambda item: item['finished'], timeout=45)
                collector.require_exited(database)
                print('Automation interfaces: return and first method entry breakpoints passed.', flush=True)
            (root / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')


def check_arrays(collector_path, target_path, inspector=None, artifact=None, baseline=False):
    context = nullcontext(str(artifact)) if artifact else tempfile.TemporaryDirectory(prefix='Detourist-ArrayValues-')
    with context as directory:
        root = pathlib.Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        assert not list(root.glob('*.db')), 'Use a fresh capture directory.'
        expected = {3: struct.pack('<6i', -7, 0, 42, -(1 << 31), (1 << 31) - 1, 123456),
                    5: struct.pack('<3d', -3.25, 0.5, 1.125), 11: struct.pack('<4h', -1, 0, -1, 0),
                    12: struct.pack('<H6xi12x', 3, -99) + struct.pack('<H6xd8x', 5, 3.5) +
                        struct.pack('<H6xI12x', 19, 0xDEADBEEF)}
        results, details = [], []
        with Collector(collector_path) as collector:
            hello = collector.call('hello')
            invoke = next(api['id'] for api in hello['catalog'] if api['name'] == 'IDispatch::Invoke')
            for byref in (False, True):
                mode = 'byref-values' if byref else 'values'
                checked = subprocess.run([str(target_path), mode], capture_output=True, timeout=15,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
                assert checked.returncode == 0, (mode, checked.returncode, checked.stderr)
                for instructions in (False, True):
                    for limit in (16, 56, 64):
                        database = root / f'{mode}-{int(instructions)}-{limit}.db'
                        status = collector.capture(database=str(database), executable=str(target_path), arguments=mode,
                            apiMask=hello['comMask'], bufferLimit=limit, followChildren=False,
                            instructionEngine=instructions, timeout=45)
                        collector.require_exited(database)
                        with open_trace(database, named=True) as db:
                            rows = db.execute('SELECT * FROM calls WHERE api=? AND ended IS NOT NULL ORDER BY started',
                                              (invoke,)).fetchall()
                            returns = [row for row in rows if struct.unpack_from('<q', row['arguments'], 8)[0] == 0]
                            headers = sum(len(snapshots(row['output'], 6, 8)) for row in returns)
                            results.append({'byref': byref, 'instructions': instructions, 'limit': limit,
                                            'returnedArrays': headers, 'calls': status['calls']})
                            if baseline:
                                continue
                            assert len(returns) == 5 and headers == 5, (results[-1], len(returns))
                            for index, row in enumerate(returns):
                                descriptor = snapshots(row['output'], 6, 8)
                                data = snapshots(row['output'], 6, 9)
                                kind = (descriptor[0][0] >> 16) & 0xFFF
                                payload = expected[kind] if index < 4 else b''
                                assert len(descriptor) == len(data) == 1, (index, descriptor, data)
                                assert descriptor[0][1] == (40 if index == 0 else 32), descriptor
                                assert len(descriptor[0][2]) == min(limit, descriptor[0][1]), descriptor
                                assert data[0] == (
                                    (kind << 16) | int(limit < len(payload)), len(payload), payload[:limit]), data
                                if index == 0 and limit >= 40:
                                    bounds = [struct.unpack_from('<Ii', descriptor[0][2], offset)
                                              for offset in (24, 32)]
                                    assert set(bounds) == {(3, -4), (2, 5)}, bounds
                                details.append({'limit': limit, 'index': index, 'instructions': instructions,
                                    'byref': byref, 'call': collector.call('details', database=str(database),
                                        target=row['target'], callId=row['id'])})
                            inputs = [item for row in rows for item in snapshots(row['input'], 5, 9)]
                            assert len(inputs) == 5, (mode, instructions, limit, inputs)
                            for row in db.execute('SELECT input,output FROM calls'):
                                check_limit(row, limit)
                            assert db.execute('SELECT count(*) FROM diagnostics').fetchone()[0] == 0
                        print(f'Automation arrays: {mode}, instructions={instructions}, cap={limit} passed.',
                              flush=True)
            (root / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
            details_path = root / 'details.json'
            details_path.write_text(json.dumps(details, indent=2), encoding='utf-8')
            if inspector and not baseline:
                checked = subprocess.run(['dotnet', str(inspector), '--automation-arrays', str(details_path)],
                    capture_output=True, encoding='utf-8', timeout=45, creationflags=subprocess.CREATE_NO_WINDOW)
                assert checked.returncode == 0, checked.stdout + checked.stderr
                print(checked.stdout, end='', flush=True)


def check_strings(collector, target, inspector=None, artifact=None, baseline=False):
    context = nullcontext(str(artifact)) if artifact else tempfile.TemporaryDirectory(prefix='Detourist-ArrayStrings-')
    with context as directory:
        root = pathlib.Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        assert not list(root.glob('*.db')), 'Use a fresh capture directory.'
        first = 'alpha\0omega'.encode('utf-16-le')
        second = 'tail\0'.encode('utf-16-le')
        rows, details = [], []
        with Collector(collector) as server:
            hello = server.call('hello')
            invoke = next(api['id'] for api in hello['catalog'] if api['name'] == 'IDispatch::Invoke')
            for byref in (False, True):
                mode = 'byref-strings' if byref else 'strings'
                checked = subprocess.run([str(target), mode], capture_output=True, timeout=15,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
                assert checked.returncode == 0, (mode, checked.returncode, checked.stderr)
                for instructions in (False, True):
                    for limit in (16, 56, 64):
                        database = root / f'{mode}-{int(instructions)}-{limit}.db'
                        server.capture(database=str(database), executable=str(target), arguments=mode,
                            bufferLimit=limit, apiMask=hello['comMask'], followChildren=False,
                            instructionEngine=instructions, timeout=45)
                        server.require_exited(database)
                        with open_trace(database, named=True) as db:
                            invokes = db.execute(
                                'SELECT * FROM calls WHERE api=? AND ended IS NOT NULL ORDER BY started',
                                                 (invoke,)).fetchall()
                            outputs = [row for row in invokes if struct.unpack_from('<q', row['arguments'], 8)[0] == 0]
                            assert len(outputs) == 2, (mode, instructions, limit, len(outputs))
                            captured = 0
                            for index, row in enumerate(outputs):
                                regions = [value for value in value_records(row['output']) if value['flags'] & 32]
                                captured += len(regions)
                                if not baseline:
                                    expected = (first, second, b'' if index == 0 else second)
                                    count = ((2 if limit == 16 else 3) if index == 0 else
                                             (1 if limit == 16 else 2 if limit == 56 else 3))
                                    assert len(regions) == count, (mode, instructions, limit, index, regions)
                                    for element, value in enumerate(regions):
                                        assert value['parameter'] & 255 == 6 and value['parameter'] >> 8 == 0, value
                                        assert value['kind'] == 1 and value['flags'] >> 16 == element, value
                                        assert value['flags'] & 3 == int(limit < len(expected[element])), value
                                        assert value['total'] == len(expected[element]), value
                                        assert value['bytes'] == expected[element][:limit], value
                                    details.append({'limit':limit, 'index':index, 'byref':byref,
                                        'instructions': instructions,
                                        'call': server.call('details', database=str(database),
                                            target=row['target'], callId=row['id'])})
                            rows.append({'byref':byref, 'instructions':instructions, 'limit':limit,
                                         'capturedStrings':captured})
                            if not baseline:
                                for row in db.execute('SELECT input,output FROM calls'):
                                    for payload in row:
                                        assert all(len(value['bytes']) <= limit for value in value_records(payload))
                                assert db.execute('SELECT count(*) FROM diagnostics').fetchone()[0] == 0
                        print(f'Array strings: {mode}, instructions={instructions}, cap={limit} passed.', flush=True)
            (root / 'results.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')
            path = root / 'details.json'
            path.write_text(json.dumps(details, indent=2), encoding='utf-8')
            if inspector and not baseline:
                checked = subprocess.run(['dotnet', str(inspector), '--automation-strings', str(path)],
                    capture_output=True, encoding='utf-8', timeout=45, creationflags=subprocess.CREATE_NO_WINDOW)
                assert checked.returncode == 0, checked.stdout + checked.stderr
                print(checked.stdout, end='', flush=True)


def check_enumeration(collector_path, target_path, artifact=None, baseline=False):
    context = nullcontext(str(artifact)) if artifact else tempfile.TemporaryDirectory(prefix='Detourist-Enum-')
    with context as directory:
        root = pathlib.Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        checked = subprocess.run([str(target_path), 'enumerate'], capture_output=True, timeout=15,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        assert checked.returncode == 0, (checked.returncode, checked.stderr)
        results = []
        with Collector(collector_path) as collector:
            hello = collector.call('hello')
            identifiers = {api['name']: api['id'] for api in hello['catalog']}
            cases = [(instructions, limit, filtered) for instructions in (True, False)
                     for limit in (16, 64) for filtered in (False, True)]
            for instructions, limit, filtered in cases:
                database = root / f'enum-{int(instructions)}-{limit}-{int(filtered)}.db'
                assert not database.exists(), database
                collector.capture(database=str(database), executable=str(target_path), arguments='enumerate',
                    apiMask=hello['comMask'], bufferLimit=limit, followChildren=False, instructionEngine=instructions,
                    excludedApis=['IEnumVARIANT::Next'] if filtered else [], timeout=45)
                collector.require_exited(database)
                with open_trace(database, named=True) as connection:
                    rows = connection.execute('SELECT c.*,coalesce(d.name,a.name) name FROM calls c '
                        'LEFT JOIN apis d ON d.id=c.api AND d.target=c.target '
                        'LEFT JOIN apis a ON a.id=c.api AND a.target=0 ORDER BY c.started').fetchall()
                    counts = [row for row in rows if row['name'] == 'IDispatch::GetTypeInfoCount']
                    next_calls = [row for row in rows if row['name'] == 'IEnumVARIANT::Next']
                    result = dict(instructions=instructions, limit=limit, filtered=filtered,
                                  leafCalls=len(counts), nextCalls=len(next_calls))
                    results.append(result)
                    if baseline:
                        continue
                    assert len(counts) == 7, result
                    assert len({row['arguments'][:8] for row in counts}) == 3, result
                    assert all(row['ended'] and not row['flags'] & 256 for row in counts), result
                    assert len(next_calls) == (0 if filtered else 5), result
                    for name in ('IEnumVARIANT::Skip', 'IEnumVARIANT::Reset', 'IEnumVARIANT::Clone'):
                        selected = [row for row in rows if row['name'] == name]
                        assert len(selected) == 1 and selected[0]['ended'], (result, name, len(selected))
                    if not filtered:
                        first, empty, failed, single, cloned = next_calls
                        assert first['result'] == 1 and not first['flags'] & 256, dict(first)
                        captured = snapshots(first['output'], 2, 0)
                        assert len(captured) == 1 and captured[0][1] == 72 and len(captured[0][2]) == limit, captured
                        assert struct.unpack_from('<H', captured[0][2])[0] == 9, captured
                        assert snapshots(first['output'], 3, 2) == [(0, 4, struct.pack('<I', 3))]
                        assert empty['result'] == 1 and not empty['flags'] & 256, dict(empty)
                        assert snapshots(empty['output'], 3, 2) == [(0, 4, bytes(4))]
                        assert all(item[1] == 0 for item in snapshots(empty['output'], 2, 0)), dict(empty)
                        assert failed['flags'] & 1 and not failed['output'], dict(failed)
                        assert snapshots(single['output'], 2, 0)[0][1] == 24, dict(single)
                        assert snapshots(cloned['output'], 2, 0)[0][1] == 72, dict(cloned)
                    assert not connection.execute('SELECT count(*) FROM diagnostics').fetchone()[0]
                    for row in rows:
                        check_limit((row['input'], row['output']), limit, result)
                print(f'Automation enumeration: {result} passed.', flush=True)
            if not baseline:
                # Discovery must complete before the first returned object's method-entry breakpoint.
                database = root / 'first-method-breakpoint.db'
                collector.call('launch', database=str(database), executable=str(target_path), arguments='enumerate',
                    apiMask=hello['comMask'], bufferLimit=16, followChildren=False, instructionEngine=True,
                    entryApi=identifiers['IDispatch::GetTypeInfoCount'])
                stopped = collector.wait(lambda item: item['breakpoint'] or item['finished'], timeout=30)
                assert stopped['breakpoint'] and not stopped['leaving'], stopped
                assert stopped['stoppedCall']['name'] == 'IDispatch::GetTypeInfoCount', stopped
                assert len(stopped['stoppedCall']['arguments']) == 2, stopped
                collector.call('breakApi', entryApi=-1, exitApi=-1)
                collector.call('continue')
                collector.wait(lambda item: item['finished'], timeout=45)
                collector.require_exited(database)
                print('Automation enumeration: first returned method breakpoint passed.', flush=True)
            (root / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')


def check_records(collector_path, target_path, artifact=None):
    context = nullcontext(str(artifact)) if artifact else tempfile.TemporaryDirectory(prefix='Detourist-Records-')
    with context as directory:
        root = pathlib.Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        assert not list(root.glob('*.db')), root
        checked = []
        with Collector(collector_path) as collector:
            hello = collector.call('hello')
            cases = [(mode, limit, False) for mode in ('record', 'record-byref', 'record-nested', 'record-input',
                     'record-array', 'record-array-byref', 'record-array-nested') for limit in (16, 64)] + [
                     ('record-failed', 16, False), ('record-array-failed', 16, False),
                     ('record-array-invalid', 16, False),
                     ('record', 16, True), ('record-input', 16, True), ('record-array', 16, True)]
            for mode, limit, filtered in cases:
                baseline = subprocess.run([str(target_path), mode], capture_output=True, timeout=15,
                                          creationflags=subprocess.CREATE_NO_WINDOW)
                assert baseline.returncode == 0 and b'record_queries=0 guid_calls=1 field_calls=2' in baseline.stdout, \
                    (mode, baseline.returncode, baseline.stdout, baseline.stderr)
                database = root / f'{mode}-{limit}-{int(filtered)}.db'
                collector.capture(database=str(database), executable=str(target_path), arguments=mode,
                    apiMask=hello['comMask'], bufferLimit=limit, instructionEngine=True, followChildren=False,
                    excludedApis=['IDispatch::Invoke', 'IRecordInfo::GetField'] if filtered else [])
                page = collector.call('page', database=str(database), limit=1)
                assert all(target['state'] == 'Exited' for target in page['targets']), page
                with open_trace(database, named=True) as connection:
                    rows = connection.execute('SELECT c.*,coalesce(d.name,a.name) name FROM calls c '
                        'LEFT JOIN apis d ON d.id=c.api AND d.target=c.target '
                        'LEFT JOIN apis a ON a.id=c.api AND a.target=0 ORDER BY c.started').fetchall()
                guides = [row for row in rows if row['name'] == 'IRecordInfo::GetGuid']
                fields = [row for row in rows if row['name'] == 'IRecordInfo::GetField']
                leaves = [row for row in rows if row['name'] == 'IDispatch::GetTypeInfoCount']
                wanted = 0 if mode in ('record-failed', 'record-array-failed', 'record-array-invalid') else 1
                assert len(guides) == wanted and len(leaves) == wanted, \
                    (mode, limit, filtered, len(guides), len(leaves))
                assert len(fields) == (0 if filtered or not wanted else 2), (mode, len(fields))
                for row in guides:
                    assert row['ended'] and not row['flags'] & 256 and len(row['arguments']) == 16, dict(row)
                    assert snapshots(row['output'], 1, 0) == [(0, 16,
                        struct.pack('<IHH8B', 0x12345678, 0x9ABC, 0xDEF0, 1, 2, 3, 4, 5, 6, 7, 8))]
                for row in leaves:
                    assert row['ended'] and not row['flags'] & 256 and snapshots(row['output'], 1, 2) == \
                        [(0, 4, struct.pack('<I', 0))], dict(row)
                if fields:
                    success, failed = fields
                    assert success['ended'] and success['result'] == 0 and not success['flags'] & 1, dict(success)
                    value = snapshots(success['output'], 3, 0)
                    assert value and value[0][1] == 24 and len(value[0][2]) == min(limit, 24), value
                    assert struct.unpack_from('<H', value[0][2])[0] == 9, value
                    assert failed['flags'] & 1 and not failed['output'], dict(failed)
                if mode == 'record-input' and not filtered:
                    parent = next(row for row in rows if row['name'] == 'IDispatch::Invoke')
                    assert parent['started'] <= guides[0]['started'] <= guides[0]['ended'] <= parent['ended']
                if guides:
                    item = collector.call('page', database=str(database),
                        api='IRecordInfo::GetGuid', limit=1)['calls'][0]
                    detail = collector.call('details', database=str(database), target=item['target'], callId=item['id'])
                    assert 'GUID' in detail['parameters'] and 'pguid' in detail['parameters'], detail
                checked.append(dict(mode=mode, limit=limit, filtered=filtered, recordCalls=len(guides),
                                    fieldCalls=len(fields), discoveredLeafCalls=len(leaves)))
                print(f'Automation records: {mode}, cap={limit}, filtered={filtered} passed.', flush=True)

            # A filtered record factory still permits a breakpoint on the first returned object's method.
            selected = next(api['id'] for api in hello['catalog'] if api['name'] == 'IDispatch::GetTypeInfoCount')
            database = root / 'first-method-break.db'
            collector.call('launch', database=str(database), executable=str(target_path), arguments='record-array',
                apiMask=hello['comMask'], bufferLimit=16, instructionEngine=True, followChildren=False,
                excludedApis=['IDispatch::Invoke', 'IRecordInfo::GetField'], entryApi=selected)
            stopped = collector.wait(lambda value: value['breakpoint'] or value['finished'])
            assert stopped['breakpoint'] and stopped['stoppedCall']['name'] == 'IDispatch::GetTypeInfoCount', stopped
            collector.call('breakApi', entryApi=-1, exitApi=-1)
            collector.call('continue', callId=stopped['stoppedCall']['id'])
            collector.wait(lambda value: value['finished'])
            (root / 'audit.json').write_text(json.dumps(dict(checks=checked, firstMethodBreakpoint=True), indent=2),
                                           encoding='utf-8')
    print('Automation records: direct, by-reference, nested values, input callbacks, field outputs and bounds passed.')


def main_interfaces():
    parser = path_parser('collector', 'target', '--artifact')
    parser.add_argument('--baseline', action='store_true')
    options = parser.parse_args()
    check_interfaces(options.collector.resolve(), options.target.resolve(),
        options.artifact.resolve() if options.artifact else None, options.baseline)


def main_arrays():
    parser = path_parser('collector', 'target', '--inspector', '--artifact')
    parser.add_argument('--baseline', action='store_true')
    options = parser.parse_args()
    check_arrays(options.collector.resolve(), options.target.resolve(),
        options.inspector.resolve() if options.inspector else None,
        options.artifact.resolve() if options.artifact else None, options.baseline)


def main_strings():
    parser = path_parser('collector', 'target', '--inspector', '--artifact')
    parser.add_argument('--baseline', action='store_true')
    args = parser.parse_args()
    check_strings(args.collector.resolve(), args.target.resolve(), args.inspector.resolve() if args.inspector else None,
        args.artifact.resolve() if args.artifact else None, args.baseline)


def main_enumeration():
    parser = path_parser('collector', 'target', '--artifact')
    parser.add_argument('--baseline', action='store_true')
    options = parser.parse_args()
    check_enumeration(options.collector.resolve(), options.target.resolve(),
        options.artifact.resolve() if options.artifact else None, options.baseline)


def main_records():
    args = path_parser('collector', 'target', '--artifacts').parse_args()
    check_records(args.collector.resolve(), args.target.resolve(), args.artifacts.resolve() if args.artifacts else None)


if __name__ == '__main__':
    run_scenarios({
        'interfaces': main_interfaces,
        'arrays': main_arrays,
        'strings': main_strings,
        'enumeration': main_enumeration,
        'records': main_records,
    })
