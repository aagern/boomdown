#!/usr/bin/env python3
"""boomdown — download AES-128 encrypted Boomstream HLS videos."""
import argparse
import os
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
