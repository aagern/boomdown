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


def run(chunklist_url: str, output: str) -> None:
    pass


if __name__ == '__main__':
    main()
