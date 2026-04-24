#!/usr/bin/env python3
"""boomdown — download AES-128 encrypted Boomstream HLS videos."""
import argparse
import os
import re
import subprocess
import sys
import tempfile

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

BOOMSTREAM_API = 'https://play.boomstream.com/api/process/'
XOR_KEY = 'bla_bla_bla'
HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'
    ),
    'Referer': 'https://play.boomstream.com/',
}


def fetch_text(url: str) -> str:
    r = requests.get(url, headers=HEADERS)
    r.raise_for_status()
    return r.text


def extract_xmedia_ready(chunklist: str) -> str:
    for line in chunklist.splitlines():
        if line.startswith('#EXT-X-MEDIA-READY:'):
            return line.split(':', 1)[1].strip()
    raise ValueError('No #EXT-X-MEDIA-READY tag found in chunklist')


def extract_chunk_urls(chunklist: str) -> list:
    return [line.strip() for line in chunklist.splitlines()
            if line.strip().startswith('https://')]


def _xor_decrypt(hex_string: str, key: str) -> str:
    """XOR-decodes a hex-encoded string with a repeating string key."""
    n_bytes = len(hex_string) // 2
    repeated = (key * (n_bytes // len(key) + 1))[:n_bytes]
    return ''.join(
        chr(int(hex_string[i * 2:i * 2 + 2], 16) ^ ord(repeated[i]))
        for i in range(n_bytes)
    )


def compute_iv_from_xmedia_ready(xmedia_ready: str) -> bytes:
    """Computes the AES IV from #EXT-X-MEDIA-READY via XOR decode (fallback)."""
    decrypted = _xor_decrypt(xmedia_ready, XOR_KEY)
    return bytes(ord(c) for c in decrypted[20:36])


def get_aes_key(xmedia_ready: str) -> bytes:
    """Fetches the 16-byte AES-128 key from the Boomstream API."""
    r = requests.get(BOOMSTREAM_API + xmedia_ready, headers=HEADERS)
    r.raise_for_status()
    # API returns key as a UTF-8 string; each char's ordinal is one key byte
    return bytes(ord(c) for c in r.text)


def download_and_decrypt_chunk(url: str, key: bytes, iv: bytes) -> bytes:
    r = requests.get(url, headers=HEADERS)
    r.raise_for_status()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(r.content) + decryptor.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()
    except ValueError:
        return decrypted  # no valid PKCS7 padding — return raw


def extract_iv_from_chunklist(chunklist: str):
    """Returns 16-byte IV from #EXT-X-KEY:IV=0x... or None if absent."""
    for line in chunklist.splitlines():
        if '#EXT-X-KEY' in line:
            m = re.search(r'IV=0x([0-9a-fA-F]{32})', line)
            if m:
                return bytes.fromhex(m.group(1))
    return None


def main():
    parser = argparse.ArgumentParser(description='Boomstream HLS video downloader')
    parser.add_argument('url', help='chunklist.m3u8 URL (intercepted from Chrome DevTools)')
    parser.add_argument('--output', default='output.mp4', help='output filename (default: output.mp4)')
    args = parser.parse_args()
    run(args.url, args.output)


def merge_to_mp4(chunk_paths: list, output: str) -> None:
    """Concatenates decrypted .ts chunks and remuxes to MP4 (no re-encode)."""
    concat_list = output + '.concat.txt'
    try:
        with open(concat_list, 'w') as f:
            for path in chunk_paths:
                f.write(f"file '{path}'\n")
        subprocess.run(
            ['ffmpeg', '-y', '-f', 'concat', '-safe', '0',
             '-i', concat_list, '-c', 'copy', output],
            check=True,
        )
    finally:
        if os.path.exists(concat_list):
            os.unlink(concat_list)


def run(chunklist_url: str, output: str) -> None:
    pass


if __name__ == '__main__':
    main()
