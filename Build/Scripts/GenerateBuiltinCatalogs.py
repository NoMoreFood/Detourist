import sys
sys.dont_write_bytecode = True

import argparse
from contextlib import closing
import json
import pathlib
import sqlite3
import uuid


SDK_HEADERS = """#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <wininet.h>
#include <msiquery.h>
#include <pdh.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <winspool.h>
#include <powrprof.h>
#include <objbase.h>
#include <ole2.h>
#include <oleauto.h>
#include <olectl.h>
#include <roapi.h>
#include <winstring.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <ws2ipdef.h>
#include <windns.h>
#include <iphlpapi.h>
#include <pathcch.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <aclapi.h>
#include <userenv.h>
#include <authz.h>
#include <dwmapi.h>
#include <commctrl.h>
#include <processtopologyapi.h>
#include <d2d1.h>
#include <d2d1_1.h>
#include <d3d11.h>
#include <d3d12.h>
#include <dwrite.h>
#include <dxgi.h>
#include <dxgi1_3.h>
#include <mfcaptureengine.h>
#include <CertBCli.h>
#include <mmreg.h>
#include <mmiscapi.h>
#include <msacm.h>
#undef WIN32
#define WIN32 1
#include <WinFax.h>
#include <lzexpand.h>
#include <clfs.h>
extern "C" {
#include <schannel.h>
}
#include <activeds.h>
#include <playsoundapi.h>
#include <dsclient.h>
#include <slpublic.h>
#include <winldap.h>
#include <winber.h>
#include <lmcons.h>
#define HLOG LMERR_HLOG
#include <lmerrlog.h>
#undef HLOG
#include <lm.h>
#include <lmdfs.h>
#include <lmat.h>
#include <nb30.h>
#include <ntsecapi.h>
#include <dsgetdc.h>
#include <dsrole.h>
#include <davclnt.h>
#include <ntdsapi.h>
#include <dsparse.h>
#include <d3dcompiler.h>
#define RPCPROXY_ENABLE_CPP_NO_CINTERFACE
#include <rpcproxy.h>
#include <midles.h>

#include <mstcpip.h>
#include <d3d10shader.h>
#include <vfw.h>
#include <wab.h>
struct __declspec(uuid("00020021-0000-0000-c000-000000000046")) IAVIStream;
struct __declspec(uuid("51b0ca8b-ec0b-4519-870d-8ee1cb5017c7")) ID3D10Effect;
struct CABINET_SESSION;
using PSESSION = CABINET_SESSION*;
struct CCscSearchApiInterface;
struct LAYOUTORTIPPROFILE;
struct LAYOUTORTIP;
struct ID3D11ShaderTrace;
struct ITnef;
using LPITNEF = ITnef*;
struct _CM_PARTIAL_RESOURCE_DESCRIPTOR;
using PCM_PARTIAL_RESOURCE_DESCRIPTOR = _CM_PARTIAL_RESOURCE_DESCRIPTOR*;
struct _IO_RESOURCE_DESCRIPTOR;
using PIO_RESOURCE_DESCRIPTOR = _IO_RESOURCE_DESCRIPTOR*;
struct CABINETDLLVERSIONINFO { DWORD cbStruct, dwReserved1, dwReserved2, dwFileVersionMS, dwFileVersionLS; };
using PCABINETDLLVERSIONINFO = CABINETDLLVERSIONINFO*;
enum D3DX11_IMAGE_FILE_FORMAT : unsigned int;
struct ID3DX11ThreadPump;
struct ID3DX11DataLoader;
struct ID3DX11DataProcessor;
struct D3DX11_IMAGE_INFO { UINT Width, Height, Depth, ArraySize, MipLevels, MiscFlags; DXGI_FORMAT Format; D3D11_RESOURCE_DIMENSION ResourceDimension; D3DX11_IMAGE_FILE_FORMAT ImageFileFormat; };
struct D3DX11_IMAGE_LOAD_INFO { UINT Width, Height, Depth, FirstMipLevel, MipLevels; D3D11_USAGE Usage; UINT BindFlags, CpuAccessFlags, MiscFlags; DXGI_FORMAT Format; UINT Filter, MipFilter; D3DX11_IMAGE_INFO* pSrcInfo; };
struct D3DX11_TEXTURE_LOAD_INFO { D3D11_BOX* pSrcBox; D3D11_BOX* pDstBox; UINT SrcFirstMip, DstFirstMip, NumMips, SrcFirstElement, DstFirstElement, NumElements, Filter, MipFilter; };
using MRUCMPPROCW = int (CALLBACK*)(LPCWSTR, LPCWSTR);
struct MRUINFO { DWORD cbSize; UINT uMax, fFlags; HKEY hKey; LPCWSTR lpszSubKey; MRUCMPPROCW lpfnCompare; };
using LPMRUINFO = MRUINFO*;
using HBC = void*;
struct EDB_RSTMAPA { LPSTR szDatabaseName, szNewDatabaseName; };
struct EDB_RSTMAPW { LPWSTR szDatabaseName, szNewDatabaseName; };
"""


def write(path, text):
    encoded = text.replace('\r\n', '\n').replace('\n', '\r\n').encode('utf-8')
    if not path.exists() or path.read_bytes() != encoded:
        path.write_bytes(encoded)


def write_layouts(path, layouts):
    records = '\n'.join('    {' + f'{family}, {level}, {size}, "{name}", {len(strings)}, ' +
        '{' + ', '.join(map(str, strings)) + '}, ' + str(len(sids)) + ', {' +
        ', '.join(map(str, sids)) + '}, ' + f'{hours}, {units}, {security}, {len(buffers)}, ' +
        '{{' + ', '.join('{' + str(pointer) + ', ' + str(length) + '}' for pointer, length in buffers) + '}}},'
        for family, level, size, name, strings, sids, hours, units, security, buffers in layouts)
    text = f"""#pragma once
#include <array>
#include <cstdint>

namespace Detourist
{{
struct NetApiBufferLayout
{{
    uint16_t pointer;
    uint16_t length;
}};

struct NetApiRecordLayout
{{
    uint16_t family;
    uint32_t level;
    uint16_t bytes;
    const char* name;
    uint8_t stringCount;
    std::array<uint16_t, 32> stringOffsets;
    uint8_t sidCount;
    std::array<uint16_t, 4> sidOffsets;
    uint16_t logonHoursOffset;
    uint16_t unitsPerWeekOffset;
    uint16_t securityDescriptorOffset;
    uint8_t bufferCount;
    std::array<NetApiBufferLayout, 3> buffers;
}};

inline constexpr std::array<NetApiRecordLayout, {len(layouts)}> NetApiRecordLayouts = {{{{
{records}
}}}};

inline const char* NetApiLayoutName(uint32_t id)
{{
    return id < NetApiRecordLayouts.size() ? NetApiRecordLayouts[id].name : "";
}}
}}
"""
    write(path, text)


def select_architecture(connection, pointer_size):
    if pointer_size not in (4, 8):
        raise ValueError('Unsupported catalog architecture.')
    if connection.execute('PRAGMA user_version').fetchone() != (15,):
        raise ValueError('Unsupported API catalog schema.')
    if pointer_size == 8:
        return
    definitions = connection.execute("SELECT sql FROM sqlite_schema WHERE type='view'").fetchall()
    for sql, in definitions:
        connection.execute(('CREATE TEMP ' + sql.removeprefix('CREATE ')).replace('/*architecture*/8', '4'))


def generate_layouts(connection, output):
    layouts = [(family, level, size, name, json.loads(strings), json.loads(sids), hours, units,
        security, json.loads(buffers)) for family, level, size, name, strings, sids, hours, units,
        security, buffers in connection.execute('SELECT family,level,bytes,name,strings,sids,hours,units,'
            'security,buffers FROM netapi_layouts ORDER BY id')]
    write_layouts(output / 'NetApiRecordLayouts.h', layouts)
    replication = []
    for size, array, count, strings, binary, binary_count in connection.execute(
            'SELECT element_bytes,array_offset,count_offset,strings,binary_offset,binary_count '
            'FROM replication_layouts ORDER BY id'):
        strings = json.loads(strings)
        replication.append('    {' + f'{size}, {array}, {count}, {len(strings)}, ' +
            '{' + ', '.join(map(str, strings)) + '}, ' + f'{binary}, {binary_count}' + '},')
    records = '\n'.join(replication)
    text = f"""#pragma once
#include <array>
#include <cstdint>

namespace Detourist
{{
struct ReplicationLayout
{{
    uint16_t elementBytes;
    uint8_t headerBytes, countOffset, stringCount;
    std::array<uint8_t, 4> stringOffsets;
    uint8_t binaryOffset, binaryCountOffset;
}};

inline constexpr std::array<ReplicationLayout, {len(replication)}> ReplicationLayouts = {{{{
{records}
}}}};
}}
"""
    write(output / 'ReplicationRecordLayouts.h', text)
    assertions = """#pragma once
#include <cstddef>
#include <winnetwk.h>
#include <npapi.h>

// Validate catalog record offsets against the native SDK compiler.
"""
    assertions += ''.join(f'static_assert({expression});\n' for expression, in connection.execute(
        'SELECT expression FROM layout_assertions ORDER BY id'))
    write(output / 'NetApiRecordLayoutAssertions.h', assertions)


def generate(connection, output):
    header = '// Generated from the API catalog by Build/Scripts/GenerateBuiltinCatalogs.py.\n'
    groups = {}
    for group in ('core', 'com', 'native', 'win32', 'win32u'):
        groups[group] = connection.execute('SELECT b.id,f.name,d.prototype,d.failure_rule,d.failure_mode,'
            'd.supported,d.flags,d.declaration FROM builtin_apis b JOIN functions f ON f.id=b.function_id '
            'JOIN builtin_bindings d ON d.id=b.id JOIN builtin_groups g '
            'ON b.id>=g.first_id AND b.id<g.first_id+g.count WHERE g.name=? ORDER BY b.id', (group,)).fetchall()
        expected = connection.execute('SELECT count FROM builtin_groups WHERE name=?', (group,)).fetchone()
        if expected is None or len(groups[group]) != expected[0]:
            raise ValueError('Incomplete builtin bindings: ' + group)
    generate_layouts(connection, output)
    write(output / 'CoreCatalog.inc', header + ''.join(
        f'CORE_API({name}, {failure})\n' for _, name, _, _, failure, _, _, _ in groups['core']))
    write(output / 'NativeCatalog.inc', header + ''.join(
        f'NATIVE_API({name}, {str(bool(failure)).lower()}, {prototype})\n'
        for _, name, prototype, failure, _, _, _, _ in groups['native']))
    write(output / 'Win32uCatalog.inc', header + ''.join(
        f'WIN32U_API({name}, {failure}, {prototype})\n' if supported else f'WIN32U_UNSUPPORTED({name})\n'
        for _, name, prototype, failure, _, supported, _, _ in groups['win32u']))
    com = [header]
    for _, name, prototype, _, _, _, _, _ in groups['com']:
        if '::' not in name:
            com.append(f'COM_EXPORT({name})\n')
            continue
        owner, method = name.split('::')
        slots = connection.execute('SELECT DISTINCT m.slot FROM interface_methods m '
            'JOIN interfaces i ON i.id=m.interface_id JOIN functions f ON f.id=m.function_id '
            'WHERE i.name=? AND f.name=?', (owner, name)).fetchall()
        if len(slots) != 1:
            raise ValueError(f'Ambiguous catalog method slot: {name}')
        identity = 'Com' + ('EnumVariant' if owner == 'IEnumVARIANT' else '') + method
        prototype = prototype or f'decltype(&{owner}::{method})'
        com.append(f'COM_METHOD({identity}, {owner}, {slots[0][0]}, {prototype})\n')
    write(output / 'ComCatalog.inc', ''.join(com))
    macros = connection.execute('SELECT name,scope FROM binding_macros ORDER BY position').fetchall()
    write(output / 'Win32Bindings.h', header + ''.join(f'#undef {name}\n' for name, scope in macros if scope & 1) +
        ''.join(f'WIN32_BINDING({name})\n' for _, name, *_ in groups['win32']))
    declarations = [header, SDK_HEADERS]
    for name, iid in connection.execute('SELECT name,iid FROM interfaces WHERE name IN '
            "('IAddrBook','IMessage','IWABObject') ORDER BY name"):
        declarations.append(f'struct __declspec(uuid("{uuid.UUID(bytes_le=iid)}")) {name};\n')
    declarations.extend(f'#undef {name}\n' for name, scope in macros if scope & 2)
    declarations.extend(row[-1] + '\n' for row in sorted(
        (row for row in groups['win32'] if row[-1]), key=lambda row: '...' not in row[-1]))
    declarations.extend(['\nnamespace Detourist\n{\n',
        'template<class Function> constexpr Function ResolveWin32Prototype(Function function)\n',
        '{\n    return function;\n}\n'])
    # Overloaded and variadic SDK entry points use the catalog's compiler binding contracts.
    adapters = sorted((row for row in groups['win32'] if row[6]), key=lambda row: (row[6] != 1, row[1]))
    for _, name, prototype, _, _, _, flags, _ in adapters:
        declarations.append(f'using {name}Prototype = {prototype};\n')
        if flags == 1:
            declarations.extend([f'constexpr auto ResolveWin32Prototype({name}Prototype function)\n',
                '{\n    return function;\n}\n'])
        elif flags == 4:
            declarations.extend([f'inline auto ResolveWin32Prototype(decltype(&::{name}) function)\n',
                '{\n', f'    return reinterpret_cast<{name}Prototype>(function);\n', '}\n'])
    declarations.append('}\n')
    write(output / 'Win32Headers.inc', ''.join(declarations))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=pathlib.Path, required=True)
    parser.add_argument('--catalog', type=pathlib.Path, required=True)
    parser.add_argument('--pointer-size', type=int, choices=(4, 8), required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(args.catalog.resolve().as_uri() + '?mode=ro', uri=True)) as connection:
        select_architecture(connection, args.pointer_size)
        generate(connection, args.output_dir)


if __name__ == '__main__':
    main()
