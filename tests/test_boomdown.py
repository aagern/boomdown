import subprocess
import sys


def test_cli_requires_url():
    result = subprocess.run(
        [sys.executable, 'boomdown.py'],
        capture_output=True, text=True,
        cwd='/Users/alex/scripts/Python/boomdown',
    )
    assert result.returncode != 0
    assert 'url' in result.stderr.lower() or 'required' in result.stderr.lower()
