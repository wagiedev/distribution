#!/usr/bin/env python3
"""Move build bytes through private S3 storage; GitHub carries a bounded receipt.

Objects are scoped to the producing repository/run/attempt and addressed by SHA256.
Consumers trust the GitHub-authenticated receipt, never an S3 listing or metadata.
The endpoint and credentials come from runner configuration, never from a receipt.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import glob
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile

SCHEMA = 'wagie.nuc-artifact/v1'
RECEIPT = 'nuc-artifact.json'
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_FILES = 4096
SHA = re.compile(r'[0-9a-f]{64}')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(repository, run, attempt, sha):
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'invalid repository')
    require(re.fullmatch(r'[1-9][0-9]*', run), 'invalid run')
    require(re.fullmatch(r'[1-9][0-9]*', attempt), 'invalid attempt')
    require(re.fullmatch(r'[0-9a-f]{40}', sha), 'invalid source revision')
    return dict(repository=repository, run=run, attempt=attempt, sha=sha)


def safe_path(value):
    require(isinstance(value, str) and value and '\\' not in value and '\x00' not in value,
            'invalid artifact path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and
            all(part not in ('', '.', '..') for part in path.parts), 'unsafe artifact path')
    require(value != RECEIPT, 'reserved receipt path')
    return path


def select_files(patterns, workspace):
    """Match Actions paths, retaining the common ancestor before each wildcard."""
    selected, roots = set(), []
    for pattern in patterns.splitlines():
        pattern = pattern.strip()
        if not pattern:
            continue
        require(not pattern.startswith('!'), 'negative patterns are not supported')
        full = Path(workspace) / pattern
        # The fixed prefix defines the archive root, even when a glob has one match.
        root = full
        while glob.has_magic(str(root)):
            root = root.parent
        if root == full and not root.is_dir():
            root = root.parent
        roots.append(root.absolute())
        for match in glob.glob(str(full), recursive=True):
            path = Path(match)
            require(not path.is_symlink(), 'artifact links are forbidden')
            candidates = path.rglob('*') if path.is_dir() else [path]
            for candidate in candidates:
                require(not candidate.is_symlink(), 'artifact links are forbidden')
                if candidate.is_dir():
                    continue
                require(candidate.is_file(), 'artifact special files are forbidden')
                if any(part.startswith('.') for part in candidate.relative_to(root).parts):
                    continue
                selected.add(candidate.absolute())
    if not selected:
        return None, []
    root = Path(os.path.commonpath(roots))
    require(len(selected) <= MAX_FILES, 'too many artifact files')
    return root, sorted(selected)


def validate(receipt, expected, name=None):
    require(set(receipt) == {'schema', 'identity', 'name', 'files'}, 'invalid receipt fields')
    require(receipt['schema'] == SCHEMA and receipt['identity'] == expected, 'artifact identity mismatch')
    require(isinstance(receipt['name'], str) and receipt['name'], 'invalid artifact name')
    if name:
        require(receipt['name'] == name, 'artifact name mismatch')
    files = receipt['files']
    require(isinstance(files, list) and 0 < len(files) <= MAX_FILES, 'invalid artifact file count')
    seen = set()
    for item in files:
        require(isinstance(item, dict) and set(item) == {'path', 'size', 'sha256', 'mode'},
                'invalid file record')
        path = safe_path(item['path'])
        require(item['path'] not in seen, 'duplicate artifact path')
        require(type(item['size']) is int and item['size'] >= 0, 'invalid file size')
        require(isinstance(item['sha256'], str) and SHA.fullmatch(item['sha256']), 'invalid file digest')
        require(item['mode'] in (0o644, 0o755), 'invalid file mode')
        seen.add(path.as_posix())
    for path in seen:
        require(not any(parent.as_posix() in seen for parent in PurePosixPath(path).parents),
                'artifact file/directory collision')
    return files


class Store:
    def __init__(self, source):
        self.endpoint = os.environ['WAGIE_ARTIFACT_ENDPOINT']
        self.bucket = os.environ['WAGIE_ARTIFACT_BUCKET']
        require(re.fullmatch(r'https://[A-Za-z0-9.:-]+', self.endpoint), 'artifact endpoint must use HTTPS')
        require(re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', self.bucket), 'invalid configured bucket')
        self.prefix = f"v1/{source['repository']}/{source['run']}/{source['attempt']}/sha256"
        self.env = dict(os.environ, AWS_ACCESS_KEY_ID=os.environ['WAGIE_ARTIFACT_ACCESS_KEY_ID'],
                        AWS_SECRET_ACCESS_KEY=os.environ['WAGIE_ARTIFACT_SECRET_ACCESS_KEY'],
                        AWS_DEFAULT_REGION='us-east-1', AWS_EC2_METADATA_DISABLED='true',
                        AWS_PAGER='', AWS_RETRY_MODE='standard', AWS_MAX_ATTEMPTS='3')
        self.env.pop('AWS_SESSION_TOKEN', None)
        self.env.pop('AWS_PROFILE', None)
        self.ca_certificate = os.environ['WAGIE_ARTIFACT_CA_CERT']
        require(self.ca_certificate.startswith('-----BEGIN CERTIFICATE-----'), 'missing artifact store CA certificate')

    def copy(self, local, sha, upload=False):
        remote = f's3://{self.bucket}/{self.prefix}/{sha}'
        paths = [str(local), remote] if upload else [remote, str(local)]
        with tempfile.NamedTemporaryFile(prefix='nuc-store-ca-', suffix='.pem', mode='w',
                                         dir=os.environ.get('RUNNER_TEMP')) as certificate:
            certificate.write(self.ca_certificate)
            certificate.flush()
            subprocess.run(['aws', '--endpoint-url', self.endpoint, '--ca-bundle', certificate.name,
                            '--cli-connect-timeout', '5', '--cli-read-timeout', '60', 's3', 'cp', *paths,
                            '--only-show-errors', '--no-progress'], env=self.env, check=True)


def publish(patterns, workspace, output, name, source, copy):
    root, paths = select_files(patterns, workspace)
    require(paths, 'no artifact files found')
    files = []
    for path in paths:
        mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
        files.append(dict(path=path.relative_to(root).as_posix(), size=path.stat().st_size,
                          sha256=digest(path), mode=mode))
    receipt = dict(schema=SCHEMA, identity=source, name=name, files=files)
    validate(receipt, source, name)
    encoded = (json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(len(encoded) <= MAX_RECEIPT_BYTES, 'artifact receipt exceeds 1 MiB')
    # Identical files within this handoff need only one physical upload.
    unique = {item['sha256']: path for item, path in zip(files, paths)}
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda pair: copy(pair[1], pair[0], upload=True), unique.items()))
    # Refuse changed producer files rather than publishing a receipt for a moving input.
    for item, path in zip(files, paths):
        require(path.stat().st_size == item['size'] and digest(path) == item['sha256'],
                'artifact changed during upload')
    output.mkdir(parents=True, exist_ok=True)
    require(not (output / RECEIPT).exists(), 'receipt already exists')
    (output / RECEIPT).write_bytes(encoded)
    print(f"Stored {sum(item['size'] for item in files)} bytes on the NUC; GitHub receipt: {len(encoded)} bytes")


def restore(root, source, name, copy):
    receipt_path = root / RECEIPT
    require(not receipt_path.is_symlink() and receipt_path.is_file(), 'missing artifact receipt')
    require(receipt_path.stat().st_size <= MAX_RECEIPT_BYTES, 'artifact receipt exceeds 1 MiB')
    receipt = json.loads(receipt_path.read_bytes())
    files = validate(receipt, source, name)
    # Download and authenticate the complete set before exposing any producer files.
    with tempfile.TemporaryDirectory(prefix='.nuc-restore-', dir=root.parent) as scratch:
        stage = Path(scratch)

        def fetch(item):
            path = stage / item['path']
            path.parent.mkdir(parents=True, exist_ok=True)
            copy(path, item['sha256'])
            require(path.is_file() and not path.is_symlink() and path.stat().st_size == item['size'] and
                    digest(path) == item['sha256'], 'artifact bytes do not match the authenticated receipt')
            path.chmod(item['mode'])

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(fetch, files))
        for item in files:
            target = root / item['path']
            require(not target.exists() and not target.is_symlink(), 'artifact destination already exists')
            require(not any(parent.is_symlink() for parent in target.parents), 'artifact destination is a link')
        for item in files:
            target = root / item['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(stage / item['path']), target)
    receipt_path.unlink()
    print(f"Verified and restored {len(files)} files from NUC storage")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['publish', 'restore', 'check-small', 'probe'])
    parser.add_argument('--path', help='newline-separated upload patterns, or restore directory')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--name')
    parser.add_argument('--workspace', default=os.environ.get('GITHUB_WORKSPACE', os.getcwd()))
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--run', default=os.environ.get('GITHUB_RUN_ID'))
    parser.add_argument('--attempt', default=os.environ.get('GITHUB_RUN_ATTEMPT'))
    parser.add_argument('--sha', default=os.environ.get('GITHUB_SHA'))
    parser.add_argument('--if-no-files-found', choices=['error', 'warn'], default='error')
    args = parser.parse_args()
    require(args.command == 'probe' or args.path, 'artifact path is required')
    if args.command == 'check-small':
        _, paths = select_files(args.path, args.workspace)
        require(paths and sum(path.stat().st_size for path in paths) <= MAX_RECEIPT_BYTES,
                'GitHub evidence must be nonempty and at most 1 MiB')
        return
    source = identity(args.repository, args.run, args.attempt, args.sha)
    if args.command == 'probe':
        store = Store(source)
        with tempfile.TemporaryDirectory(prefix='nuc-probe-', dir=os.environ.get('RUNNER_TEMP')) as scratch:
            original, restored = Path(scratch) / 'original', Path(scratch) / 'restored'
            original.write_bytes(os.urandom(32))
            sha = digest(original)
            store.copy(original, sha, upload=True)
            store.copy(restored, sha)
            require(digest(restored) == sha, 'artifact store probe failed')
        print('Private NUC artifact upload and download passed')
    elif args.command == 'publish':
        require(args.output and args.name, 'publish requires output and name')
        if args.if_no_files_found == 'warn' and not select_files(args.path, args.workspace)[1]:
            print('No optional artifact files found')
            return
        publish(args.path, args.workspace, args.output, args.name, source, Store(source).copy)
    else:
        restore(Path(args.workspace) / args.path, source, args.name, Store(source).copy)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
