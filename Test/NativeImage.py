import os
from pathlib import Path
import struct


def native_export(module, name, pointer_size, byte_count=32):
    # Read the target architecture's installed image independently of the controller's loaded DLLs.
    windows = Path(os.environ['SystemRoot'])
    directory = windows / 'SysWOW64' if pointer_size == 4 and (windows / 'SysWOW64').exists() else windows / 'System32'
    if pointer_size == 8 and struct.calcsize('P') == 4 and (windows / 'Sysnative').exists():
        directory = windows / 'Sysnative'
    image = (directory / module).read_bytes()
    header = struct.unpack_from('<I', image, 0x3C)[0]
    machine, count = struct.unpack_from('<HH', image, header + 4)
    assert machine == (0x14C if pointer_size == 4 else 0x8664), (module, machine)
    optional_bytes = struct.unpack_from('<H', image, header + 20)[0]
    sections = [struct.unpack_from('<IIII', image, header + 24 + optional_bytes + index * 40 + 8)
                for index in range(count)]

    def offset(address):
        for virtual_bytes, start, raw_bytes, raw in sections:
            if start <= address < start + max(virtual_bytes, raw_bytes):
                return raw + address - start
        raise AssertionError(f'Unmapped export metadata: {module}, {address:#x}')

    exports = offset(struct.unpack_from('<I', image, header + 24 + (96 if pointer_size == 4 else 112))[0])
    count, addresses, symbols, ordinals = struct.unpack_from('<IIII', image, exports + 24)
    for index in range(count):
        text = offset(struct.unpack_from('<I', image, offset(symbols) + index * 4)[0])
        if image[text:image.index(b'\0', text)].decode('ascii') != name:
            continue
        ordinal = struct.unpack_from('<H', image, offset(ordinals) + index * 2)[0]
        address = struct.unpack_from('<I', image, offset(addresses) + ordinal * 4)[0]
        code = offset(address)
        return address, image[code:code + byte_count]
    raise AssertionError(f'Installed export missing: {module}!{name}')
