#!/usr/bin/env python3
"""Build the upstream-pinned WAL-fixed SQLite into a new isolated prefix."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request

VERSION = '3530000'
SHA256 = '851e9b38192fe2ceaa65e0baa665e7fa06230c3d9bd1a6a9662d02380d73365a'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prefix = args.output.absolute()
    if prefix.exists():
        parser.error('Use a new output prefix; existing libraries are never replaced')
    with tempfile.TemporaryDirectory(prefix='hermes-sqlite-build-') as work:
        work = Path(work)
        archive = work / 'sqlite.tar.gz'
        with urllib.request.urlopen(f'https://sqlite.org/2026/sqlite-autoconf-{VERSION}.tar.gz', timeout=60) as response:
            archive.write_bytes(response.read())
        if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
            raise SystemExit('SQLite source checksum mismatch')
        with tarfile.open(archive) as source:
            source.extractall(work, filter='data')
        source = work / ('sqlite-autoconf-' + VERSION)
        subprocess.run(['./configure', '--prefix=' + str(prefix), '--disable-static', '--disable-readline',
                        '--enable-fts5', '--enable-fts4', '--enable-rtree'], cwd=source, check=True)
        subprocess.run(['make', '-j4'], cwd=source, check=True)
        subprocess.run(['make', 'install'], cwd=source, check=True)
    print('Private SQLite prefix installed: ' + str(prefix))
    print('Set LD_LIBRARY_PATH=' + str(prefix / 'lib') + ' for the gateway and its operator CLI.')


if __name__ == '__main__':
    main()
