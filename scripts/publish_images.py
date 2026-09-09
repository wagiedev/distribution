#!/usr/bin/env python3
"""Promote verified OCI bytes to fixed Docker Hub destinations; never execute images."""

import argparse
import base64
import gzip
import hashlib
import http.client
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
from pathlib import Path, PurePosixPath

import oci_policy
from release_policy import PolicyError, fail, read_json, require_regular, strict_object


USERNAME = "wagiedev"
IMMUTABLE_RULE = r"^[0-9]+\.[0-9]+\.[0-9]+(-toolchains)?$"
REPOSITORIES = ("wagied", "wagied-headquarters", "wagied-runner")
ACCEPT = ", ".join(("application/vnd.oci.image.index.v1+json",
                    "application/vnd.oci.image.manifest.v1+json"))
MAX_RESPONSE = 8 * 1024 * 1024
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 19


def decode_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=strict_object)
    except (ValueError, UnicodeError) as error:
        fail(f"invalid registry JSON: {error}")


class DockerHub:
    """Fixed HTTPS hosts; redirects and unexpected statuses are never followed."""

    def __init__(self, pat, connection=http.client.HTTPSConnection):
        if not re.fullmatch(r"dckr_pat_[A-Za-z0-9_-]+", pat or ""):
            fail("DOCKERHUB_TOKEN must be a Docker Hub personal access token")
        self.pat = pat
        self.connection = connection

    def request(self, host, method, path, headers=None, body=None):
        connection = self.connection(host, timeout=60)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                fail("registry response exceeds policy")
            return response.status, dict((k.lower(), v) for k, v in response.getheaders()), raw
        except (OSError, http.client.HTTPException):
            fail(f"Docker Hub request failed: {method} {host}{path}")
        finally:
            connection.close()

    def hub_token(self):
        status, _, raw = self.request(
            "hub.docker.com", "POST", "/v2/auth/token",
            {"Content-Type": "application/json"},
            json.dumps({"identifier": USERNAME, "secret": self.pat}).encode(),
        )
        if status != 200:
            fail(f"Docker Hub PAT authentication failed ({status})")
        token = decode_json(raw)
        if not isinstance(token, dict) or not isinstance(token.get("access_token"), str) or not token["access_token"]:
            fail("Docker Hub did not return an access token")
        return token["access_token"]

    def policy(self, repository, token):
        status, _, raw = self.request(
            "hub.docker.com", "GET",
            f"/v2/namespaces/{USERNAME}/repositories/{repository}",
            {"Authorization": "Bearer " + token},
        )
        if status != 200:
            fail(f"cannot authenticate Docker Hub repository {repository} ({status})")
        value = decode_json(raw)
        if (not isinstance(value, dict) or value.get("name") != repository
                or value.get("namespace") != USERNAME or value.get("is_private") is not False
                or value.get("immutable_tags_settings") != {"enabled": True, "rules": [IMMUTABLE_RULE]}
                or type(value.get("immutable_tags_settings", {}).get("enabled")) is not bool):
            fail(f"Docker Hub repository {repository} is not public with the exact immutable version policy")

    def registry_token(self, repository):
        query = urllib.parse.urlencode({"service": "registry.docker.io",
                                        "scope": f"repository:{USERNAME}/{repository}:pull"})
        basic = base64.b64encode(f"{USERNAME}:{self.pat}".encode()).decode("ascii")
        status, _, raw = self.request("auth.docker.io", "GET", "/token?" + query,
                                      {"Authorization": "Basic " + basic})
        if status != 200:
            fail(f"Docker Hub registry authentication failed ({status})")
        value = decode_json(raw)
        if not isinstance(value, dict) or not isinstance(value.get("token"), str) or not value["token"]:
            fail("registry did not return a pull token")
        return value["token"]

    def manifest(self, repository, reference, token):
        return self.request("registry-1.docker.io", "GET",
                            f"/v2/{USERNAME}/{repository}/manifests/{reference}",
                            {"Authorization": "Bearer " + token, "Accept": ACCEPT})

    def absent(self, repository, tag, token):
        status, _, raw = self.manifest(repository, tag, token)
        if status != 404:
            fail(f"cannot prove {USERNAME}/{repository}:{tag} absent ({status}); no adoption or overwrite")
        value = decode_json(raw)
        errors = value.get("errors") if isinstance(value, dict) else None
        if (not isinstance(errors, list) or not errors
                or any(not isinstance(e, dict) or e.get("code") != "MANIFEST_UNKNOWN" for e in errors)):
            fail(f"registry did not prove tag {repository}:{tag} absent")

    def readback(self, repository, reference, digest, size, token):
        status, headers, raw = self.manifest(repository, reference, token)
        if (status != 200 or headers.get("docker-content-digest") != digest
                or len(raw) != size or "sha256:" + hashlib.sha256(raw).hexdigest() != digest):
            fail(f"registry bytes disagree for {repository}:{reference}")


def checked_destinations(manifest):
    """Repeat fixed destination checks at the network mutation boundary."""
    expected = {"wagied": ("wagied", manifest["version"]),
                "wagied-headquarters": ("wagied-headquarters", manifest["version"]),
                "wagied-runner": ("wagied-runner", manifest["version"]),
                "wagied-runner-toolchains": ("wagied-runner", manifest["version"] + "-toolchains")}
    values = manifest["images"]
    if len(values) != 4 or {image["variant"] for image in values} != set(expected):
        fail("image publication catalog is not exact")
    result = []
    for image in values:
        repository, tag = expected[image["variant"]]
        if (image["repository"] != f"docker.io/{USERNAME}/{repository}"
                or image["tag"] != tag or image["layout"] != f"images/{image['variant']}"):
            fail("image publication destination disagrees with policy")
        result.append((image, repository, tag))
    return result


def promote(root, manifest, hub, copy_image):
    destinations = checked_destinations(manifest)
    token = hub.hub_token()
    for repository in REPOSITORIES:
        hub.policy(repository, token)
    for _, repository, tag in destinations:
        hub.absent(repository, tag, hub.registry_token(repository))
    # Every destination must pass preflight before the first registry write.
    for image, repository, tag in destinations:
        hub.policy(repository, hub.hub_token())
        hub.absent(repository, tag, hub.registry_token(repository))
        copy_image(Path(root) / image["layout"], image["repository"] + ":" + tag, image["indexDigest"])
        token = hub.registry_token(repository)
        hub.readback(repository, tag, image["indexDigest"], image["indexSize"], token)
        hub.readback(repository, image["indexDigest"], image["indexDigest"], image["indexSize"], token)
        for platform in image["platforms"]:
            hub.readback(repository, platform["manifestDigest"], platform["manifestDigest"],
                         platform["manifestSize"], token)
    # Re-read all tags after the last copy, including both tags in the runner repository.
    for image, repository, tag in destinations:
        hub.policy(repository, hub.hub_token())
        hub.readback(repository, tag, image["indexDigest"], image["indexSize"],
                     hub.registry_token(repository))


def skopeo_publisher(pat, directory):
    auth = Path(directory) / "auth.json"
    auth.touch(mode=0o600, exist_ok=False)
    auth.write_text(json.dumps({"auths": {"docker.io": {
        "auth": base64.b64encode(f"{USERNAME}:{pat}".encode()).decode("ascii")}}}), encoding="ascii")
    empty_auth = Path(directory) / "source-auth.json"
    empty_auth.write_text('{"auths":{}}', encoding="ascii")
    policy = Path(directory) / "policy.json"
    policy.write_text('{"default":[{"type":"insecureAcceptAnything"}]}', encoding="ascii")
    registries = Path(directory) / "registries.conf"
    registries.write_text('unqualified-search-registries = []\n', encoding="ascii")
    environment = {key: value for key, value in os.environ.items()
                   if key not in {"DOCKERHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "REGISTRY_AUTH_FILE"}}
    environment["CONTAINERS_REGISTRIES_CONF"] = str(registries)

    def copy_image(layout, destination, expected_digest):
        digest_file = Path(directory) / "copied-digest"
        if digest_file.exists():
            digest_file.unlink()
        subprocess.run([
            "/usr/bin/skopeo", "--policy", str(policy), "copy", "--all", "--preserve-digests",
            "--retry-times", "0", "--src-authfile", str(empty_auth), "--dest-authfile", str(auth),
            "--digestfile", str(digest_file), "oci:" + str(layout), "docker://" + destination,
        ], check=True, env=environment, timeout=1800)
        if digest_file.read_text(encoding="ascii").strip() != expected_digest:
            fail("Skopeo changed the image index digest")

    return copy_image


def archive_evidence(root, output):
    root, output = Path(root), Path(output)
    members = 0
    with output.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for path in sorted(root.rglob("*")):
                    mode = path.lstat().st_mode
                    if stat.S_ISDIR(mode):
                        continue
                    members += 1
                    if members > MAX_ARCHIVE_MEMBERS:
                        fail("container evidence archive has too many members")
                    require_regular(path, oci_policy.MAX_EVIDENCE)
                    info = tarfile.TarInfo(path.relative_to(root).as_posix())
                    info.size = path.stat().st_size
                    info.mode = 0o644
                    with path.open("rb") as handle:
                        archive.addfile(info, handle)
    require_regular(output, MAX_ARCHIVE)


def unpack_evidence(archive_path, output):
    """Read metadata only: no tar extraction API, links, devices or executable modes."""
    require_regular(Path(archive_path), MAX_ARCHIVE)
    output = Path(output)
    output.mkdir(mode=0o700)
    names = set()
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive:
            name = member.name
            path = PurePosixPath(name)
            if (not member.isfile() or member.mode != 0o644 or path.is_absolute()
                    or ".." in path.parts or str(path) != name or name in names
                    or len(names) >= MAX_ARCHIVE_MEMBERS
                    or not 0 < member.size <= oci_policy.MAX_EVIDENCE):
                fail("unsafe or non-exact container evidence archive member")
            names.add(name)
            # Bound expanded bytes by the finite file count and per-file OCI
            # evidence limit; MAX_ARCHIVE applies to the compressed archive.
            target = output.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open("xb") as destination:
                while chunk := source.read(1024 * 1024):
                    destination.write(chunk)


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    publish = commands.add_parser("publish")
    publish.add_argument("--root", required=True)
    publish.add_argument("--inputs", required=True)
    publish.add_argument("--source-sha", required=True)
    publish.add_argument("--source-epoch", required=True, type=int)
    publish.add_argument("--version", required=True)
    unpack = commands.add_parser("unpack-evidence")
    unpack.add_argument("--archive", required=True)
    unpack.add_argument("--output", required=True)
    archive = commands.add_parser("archive-evidence")
    archive.add_argument("--root", required=True)
    archive.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "unpack-evidence":
        unpack_evidence(args.archive, args.output)
    elif args.command == "archive-evidence":
        archive_evidence(args.root, args.output)
    else:
        # Repeat receiver policy while credentials are held only by reviewed receiver code.
        oci_policy.verify_transfer(args.root, args.version, args.source_sha, args.source_epoch,
                          args.inputs, require_signature=True)
        manifest = read_json(Path(args.root) / "images.json")
        pat = os.environ.get("DOCKERHUB_TOKEN", "")
        hub = DockerHub(pat)
        with tempfile.TemporaryDirectory(prefix="wagie-dockerhub-") as temporary:
            promote(args.root, manifest, hub, skopeo_publisher(pat, temporary))


if __name__ == "__main__":
    try:
        main()
    except (PolicyError, oci_policy.PolicyError, OSError, ValueError, tarfile.TarError,
            subprocess.SubprocessError) as error:
        print(f"image publication failed: {error}", file=sys.stderr)
        sys.exit(1)
