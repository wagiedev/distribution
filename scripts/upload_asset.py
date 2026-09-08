#!/usr/bin/env python3

import argparse
import hashlib
import http.client
import json
import os
import ssl
import stat
import sys
import urllib.parse
from contextlib import contextmanager
from pathlib import Path

import release_policy as policy


UPLOAD_HOST = "uploads.github.com"
API_VERSION = "2026-03-10"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def validate_response(value, release_id, name, hashed, size):
    if not isinstance(value, dict):
        policy.fail("release asset upload response is not an object")
    policy.integer(value.get("id"), "uploaded release asset ID")
    policy.integer(value.get("size"), "uploaded release asset size", maximum=policy.MAX_ARTIFACT_BYTES)
    fixed = {
        "name": name,
        "state": "uploaded",
        "size": size,
        "digest": "sha256:" + hashed,
    }
    if any(value.get(key) != expected for key, expected in fixed.items()):
        policy.fail(f"release {release_id} upload response disagrees for {name}")
    return value


@contextmanager
def open_asset(path, name):
    path = Path(path)
    policy.safe_filename(name)
    if path.name != name:
        policy.fail("release asset path and requested name disagree")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        policy.fail(f"cannot open release asset {name}: {error}")
    handle = os.fdopen(descriptor, "rb")
    try:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            policy.fail(f"release asset {name} is not a regular file")
        if info.st_size <= 0 or info.st_size > policy.MAX_ARTIFACT_BYTES:
            policy.fail(f"release asset {name} has a size outside policy")
        hashed = hashlib.sha256()
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hashed.update(chunk)
        handle.seek(0)
        yield handle, hashed.hexdigest(), info.st_size
    finally:
        handle.close()


def upload(release_id, asset, name, token, connection_factory=http.client.HTTPSConnection):
    policy.integer(release_id, "destination release ID")
    query = urllib.parse.urlencode({"name": name}, quote_via=urllib.parse.quote)
    endpoint = (
        f"/repos/{policy.DESTINATION_REPOSITORY}/releases/{release_id}/assets?{query}"
    )
    with open_asset(asset, name) as (handle, hashed, size):
        connection = connection_factory(
            UPLOAD_HOST,
            timeout=120,
            context=ssl.create_default_context(),
        )
        try:
            connection.putrequest("POST", endpoint)
            connection.putheader("Accept", "application/vnd.github+json")
            connection.putheader("Authorization", "Bearer " + token)
            connection.putheader("Content-Type", "application/octet-stream")
            connection.putheader("Content-Length", str(size))
            connection.putheader("User-Agent", "wagie-distribution")
            connection.putheader("X-GitHub-Api-Version", API_VERSION)
            connection.endheaders()
            sent = 0
            streamed = hashlib.sha256()
            for chunk in iter(lambda: handle.read(min(1024 * 1024, size - sent + 1)), b""):
                if sent + len(chunk) > size:
                    policy.fail("release asset grew after authentication")
                streamed.update(chunk)
                connection.send(chunk)
                sent += len(chunk)
            if sent != size or streamed.hexdigest() != hashed:
                policy.fail("release asset changed after authentication")
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                policy.fail("release asset upload response exceeds policy")
            if response.status != 201:
                detail = raw.decode("utf-8", errors="replace")
                policy.fail(f"release asset upload returned HTTP {response.status}: {detail}")
            try:
                value = json.loads(
                    raw,
                    object_pairs_hook=policy.strict_object,
                    parse_constant=policy.reject_constant,
                )
            except (UnicodeError, json.JSONDecodeError) as error:
                policy.fail(f"invalid release asset upload response: {error}")
            return validate_response(value, release_id, name, hashed, size)
        finally:
            connection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-id", required=True, type=int)
    parser.add_argument("--asset", required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    token = os.environ.get("GH_TOKEN")
    if not token:
        policy.fail("destination release token is required")
    value = upload(args.release_id, args.asset, args.name, token)
    json.dump(value, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    try:
        main()
    except policy.PolicyError as error:
        print(error, file=sys.stderr)
        sys.exit(1)
