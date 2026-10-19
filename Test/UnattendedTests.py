import os
import subprocess
import sys


if __name__ == '__main__':
    result = subprocess.run([sys.argv[1], '--crt-assert'], capture_output=True, timeout=10,
                            env={**os.environ, 'DETOURIST_TEST_UNATTENDED': '1'})
    assert result.returncode == 668, (result.returncode, result.stderr)
    assert b'Detourist unattended assertion probe' in result.stderr, result.stderr
