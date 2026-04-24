import subprocess
import sys

import pytest

from boomdown import (
    extract_xmedia_ready,
    extract_chunk_urls,
    extract_iv_from_chunklist,
)

SAMPLE_CHUNKLIST = """\
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-MEDIA-READY:2c0d166b363b36350329283621242f373533173239330e5e052552350a1b165f2e353d51
#EXT-X-KEY:METHOD=AES-128,URI="https://play.boomstream.com/api/process/abc",IV=0x1234567890abcdef1234567890abcdef
#EXTINF:6.000,
https://cdn.boomstream.com/chunk_000.ts
#EXTINF:6.000,
https://cdn.boomstream.com/chunk_001.ts
#EXT-X-ENDLIST
"""

CHUNKLIST_NO_IV = """\
#EXTM3U
#EXT-X-MEDIA-READY:aabbcc
#EXT-X-KEY:METHOD=AES-128,URI="https://play.boomstream.com/api/process/abc"
#EXTINF:6.000,
https://cdn.boomstream.com/chunk_000.ts
#EXT-X-ENDLIST
"""


def test_cli_requires_url():
    result = subprocess.run(
        [sys.executable, 'boomdown.py'],
        capture_output=True, text=True,
        cwd='/Users/alex/scripts/Python/boomdown',
    )
    assert result.returncode != 0
    assert 'url' in result.stderr.lower() or 'required' in result.stderr.lower()


def test_extract_xmedia_ready():
    result = extract_xmedia_ready(SAMPLE_CHUNKLIST)
    assert result == '2c0d166b363b36350329283621242f373533173239330e5e052552350a1b165f2e353d51'


def test_extract_xmedia_ready_missing():
    with pytest.raises(ValueError, match='EXT-X-MEDIA-READY'):
        extract_xmedia_ready('#EXTM3U\n')


def test_extract_chunk_urls():
    urls = extract_chunk_urls(SAMPLE_CHUNKLIST)
    assert urls == [
        'https://cdn.boomstream.com/chunk_000.ts',
        'https://cdn.boomstream.com/chunk_001.ts',
    ]


def test_extract_iv_present():
    iv = extract_iv_from_chunklist(SAMPLE_CHUNKLIST)
    assert iv == bytes.fromhex('1234567890abcdef1234567890abcdef')
    assert len(iv) == 16


def test_extract_iv_absent():
    assert extract_iv_from_chunklist(CHUNKLIST_NO_IV) is None


# ── Task 3: AES key retrieval ─────────────────────────────────────────────────

import responses as responses_lib
from boomdown import get_aes_key


@responses_lib.activate
def test_get_aes_key_returns_16_bytes():
    key_text = '5p13wrNTEYPCCiiE'  # 16 ASCII chars = 128-bit key
    responses_lib.add(
        responses_lib.GET,
        'https://play.boomstream.com/api/process/abc123',
        body=key_text,
    )
    key_bytes = get_aes_key('abc123')
    assert len(key_bytes) == 16
    assert key_bytes == bytes(ord(c) for c in key_text)


@responses_lib.activate
def test_get_aes_key_raises_on_http_error():
    responses_lib.add(
        responses_lib.GET,
        'https://play.boomstream.com/api/process/bad',
        status=403,
    )
    with pytest.raises(Exception):
        get_aes_key('bad')


# ── Task 4: IV fallback via XOR decode ────────────────────────────────────────

from boomdown import _xor_decrypt, compute_iv_from_xmedia_ready


def test_xor_decrypt_roundtrip():
    from boomdown import XOR_KEY
    plaintext = 'hello world XOR!'  # 16 chars
    key_repeated = (XOR_KEY * 10)[:len(plaintext)]
    hex_enc = ''.join(f'{ord(c) ^ ord(k):02x}' for c, k in zip(plaintext, key_repeated))
    assert _xor_decrypt(hex_enc, XOR_KEY) == plaintext


def test_compute_iv_length():
    # 36-byte X-MEDIA-READY; IV = decoded bytes 20–35
    sample = '2c0d166b363b36350329283621242f373533173239330e5e052552350a1b165f2e353d51'
    iv = compute_iv_from_xmedia_ready(sample)
    assert len(iv) == 16
    assert isinstance(iv, bytes)
