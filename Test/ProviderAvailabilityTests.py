import sys
sys.dont_write_bytecode = True

from pathlib import Path
import subprocess
import tempfile


def run(executable, fixture):
    with tempfile.TemporaryDirectory(prefix='Detourist-Providers-') as temporary:
        directory = Path(temporary)
        missing = directory / 'missing.dll'
        corrupt = directory / 'corrupt.dll'
        corrupt.write_bytes(b'This is not a PE image.')
        dependency = directory / 'missing-dependency.dll'
        image = bytearray(fixture.read_bytes())
        offset = image.upper().find(b'KERNEL32.DLL\0')
        assert offset >= 0, 'The provider fixture has no kernel import.'
        image[offset:offset + 12] = b'LOST_ABI.DLL'
        dependency.write_bytes(image)
        for provider, expected in ((missing, 77), (corrupt, 4), (dependency, 4)):
            result = subprocess.run([str(executable), '--target', 'combase', str(provider)],
                capture_output=True, text=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
            assert result.returncode == expected, (provider.name, result.returncode, result.stdout, result.stderr)
        print('PASS: missing optional DLLs skip; corrupt DLLs and broken installed dependencies fail.')


if __name__ == '__main__':
    run(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
