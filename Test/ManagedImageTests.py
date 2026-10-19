import sys
sys.dont_write_bytecode = True

import subprocess
import tempfile
from pathlib import Path

from TestSupport import Collector, open_trace, run_paths


def check_images(collector_path, target_path):
    with tempfile.TemporaryDirectory(prefix='Detourist-ManagedImages-') as directory:
        result = Path(directory) / 'result.txt'
        database = str(Path(directory) / 'capture.db')
        subprocess.run([str(target_path), str(result), '--com-images'], check=True, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.read_text() == 'image-ok'
        result.unlink()
        collector = Collector(collector_path)
        try:
            hello = collector.call('hello')
            status = collector.capture(database=database, executable=str(target_path),
                arguments=f'"{result}" --com-images', apiMask=hello['comMask'], followChildren=False, timeout=90)
            assert 'nonzero' not in status['message'], status
            assert result.is_file() and result.read_text() == 'image-ok', status
            collector.require_exited(database)
            with open_trace(database) as connection:
                calls = connection.execute(
                    "SELECT count(*) FROM calls c JOIN apis a ON a.id=c.api AND a.target=c.target "
                    "WHERE a.name='IWICBitmapDecoder::Initialize' AND c.ended IS NOT NULL").fetchone()[0]
                assert calls >= 20, f'Native image decoder capture was lost: {calls}'
        finally:
            collector.call('stop')
            collector.close()


if __name__ == '__main__':
    run_paths(check_images, 'collector', 'target')
