import re
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


# ── Task 5: Chunk download and AES-128-CBC decryption ─────────────────────────

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as crypto_padding
from boomdown import download_and_decrypt_chunk


def _encrypt_chunk(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padder = crypto_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


@responses_lib.activate
def test_download_and_decrypt_chunk():
    key = b'0123456789abcdef'
    iv  = b'\x00' * 16
    plaintext = b'\x47' * 188  # one MPEG-TS packet (sync byte pattern)

    ciphertext = _encrypt_chunk(plaintext, key, iv)
    responses_lib.add(
        responses_lib.GET,
        'https://cdn.example.com/chunk_000.ts',
        body=ciphertext,
    )
    result = download_and_decrypt_chunk('https://cdn.example.com/chunk_000.ts', key, iv)
    assert result == plaintext


# ── Task 6: Merge chunks to MP4 with ffmpeg ───────────────────────────────────

import os
from unittest.mock import patch, MagicMock
from boomdown import merge_to_mp4


def test_merge_to_mp4_calls_ffmpeg_with_single_ts(tmp_path):
    chunks = [str(tmp_path / f'{i:05d}.ts') for i in range(3)]
    for c in chunks:
        open(c, 'wb').close()
    output = str(tmp_path / 'out.mp4')

    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        merge_to_mp4(chunks, output)

    call_args = mock_run.call_args[0][0]
    assert call_args[0] == 'ffmpeg'
    # Must NOT use the concat demuxer — ffmpeg must receive a single -i TS file
    assert '-f' not in call_args
    assert 'concat' not in call_args
    assert output in call_args


def test_merge_to_mp4_concatenates_chunks_in_order(tmp_path):
    chunk_data = [b'\x01\x02\x03\x04', b'\x05\x06\x07\x08', b'\x09\x0a\x0b\x0c']
    chunks = []
    for i, data in enumerate(chunk_data):
        path = str(tmp_path / f'{i:05d}.ts')
        with open(path, 'wb') as f:
            f.write(data)
        chunks.append(path)
    output = str(tmp_path / 'out.mp4')

    ffmpeg_input_bytes = []

    def capture_ffmpeg(cmd, **kwargs):
        ts_path = cmd[cmd.index('-i') + 1]
        with open(ts_path, 'rb') as f:
            ffmpeg_input_bytes.append(f.read())
        return MagicMock(returncode=0)

    with patch('subprocess.run', side_effect=capture_ffmpeg):
        merge_to_mp4(chunks, output)

    assert ffmpeg_input_bytes[0] == b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c'


def test_merge_to_mp4_cleans_up_tmp_ts(tmp_path):
    chunks = [str(tmp_path / '00000.ts')]
    open(chunks[0], 'wb').close()
    output = str(tmp_path / 'out.mp4')

    with patch('subprocess.run'):
        merge_to_mp4(chunks, output)

    assert not os.path.exists(output + '.tmp.ts')


# ── New pipeline: ffmpeg handles HLS decryption ───────────────────────────────

from boomdown import patch_key_uri, download_video


def test_patch_key_uri_replaces_uri():
    chunklist = (
        '#EXT-X-KEY:METHOD=AES-128,'
        'URI="https://play.boomstream.com/api/process/abc",'
        'IV=0x1234567890abcdef1234567890abcdef\n'
        'https://cdn.example.com/chunk.ts\n'
    )
    result = patch_key_uri(chunklist, '/tmp/key.bin')
    assert 'URI="file:///tmp/key.bin"' in result
    assert 'https://play.boomstream.com' not in result
    # IV and rest of the tag must be preserved
    assert 'IV=0x1234567890abcdef1234567890abcdef' in result


def test_download_video_writes_raw_key_and_patched_m3u8(tmp_path):
    chunklist = (
        '#EXT-X-KEY:METHOD=AES-128,URI="https://example.com/key",IV=0x00\n'
        'https://example.com/chunk.ts\n'
    )
    key_bytes = b'0123456789abcdef'
    output = str(tmp_path / 'out.mp4')

    captured_key = []
    captured_m3u8 = []

    def capture_ffmpeg(cmd, **kwargs):
        ml_path = cmd[cmd.index('-i') + 1]
        with open(ml_path, 'r') as f:
            content = f.read()
        m = re.search(r'URI="file://([^"]+)"', content)
        if m:
            with open(m.group(1), 'rb') as f:
                captured_key.append(f.read())
        captured_m3u8.append(content)
        return MagicMock(returncode=0)

    with patch('subprocess.run', side_effect=capture_ffmpeg):
        download_video(chunklist, key_bytes, output)

    assert captured_key[0] == key_bytes
    assert 'file://' in captured_m3u8[0]


def test_download_video_cleans_up_temp_files(tmp_path):
    chunklist = '#EXT-X-KEY:METHOD=AES-128,URI="https://example.com/key"\n'
    key_bytes = b'0123456789abcdef'
    output = str(tmp_path / 'out.mp4')

    captured_ml_path = []

    def capture_ffmpeg(cmd, **kwargs):
        captured_ml_path.append(cmd[cmd.index('-i') + 1])
        return MagicMock(returncode=0)

    with patch('subprocess.run', side_effect=capture_ffmpeg):
        download_video(chunklist, key_bytes, output)

    assert not os.path.exists(captured_ml_path[0])
