#!/usr/bin/env python3
"""Closed OCI release transfer policy. Never unpacks or executes image layers.

Keep this reviewed policy identical to wagie-distribution/scripts/oci_policy.py.
Signature authentication is the caller's responsibility; a bundle's presence is
not authentication. --inputs must come from the independently authorized source
revision, never from the producer's transfer directory.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys


SOURCE_REPOSITORY = "Savid/wagie"
VARIANTS = ("wagied", "wagied-headquarters", "wagied-runner", "wagied-runner-toolchains")
ARCHITECTURES = ("amd64", "arm64")
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"
MANIFEST_MEDIA = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MEDIA = "application/vnd.oci.image.config.v1+json"
LAYER_MEDIA = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
}
MAX_JSON = 16 * 1024 * 1024
MAX_EVIDENCE = 64 * 1024 * 1024
MAX_BLOB = 4 * 1024 * 1024 * 1024
MAX_TRANSFER = 40 * 1024 * 1024 * 1024
MAX_FILES = 8192
MAX_LAYERS = 256
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
COMMON_CHECKS = [
    "binary-identity", "entrypoint-sanitizes-gotraceback", "nonroot-runtime",
    "data-directory-persistence", "role-command-boundary",
]
RUNNER_CHECKS = [
    "runner-ordinary-boot", "runner-root-refused", "agent-pool-isolation", "harness-versions",
]


class PolicyError(Exception):
    pass


def fail(message):
    raise PolicyError(message)


def exact_keys(value, required, label, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        fail(f"{label} has a non-exact schema")


def integer(value, label, minimum=1, maximum=MAX_TRANSFER):
    if type(value) is not int or not minimum <= value <= maximum:
        fail(f"{label} is not a bounded integer")
    return value


def matches(value, pattern, label):
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        fail(f"invalid {label}")
    return value


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def parse_json(raw, label):
    def reject_constant(value):
        fail(f"non-finite JSON number {value}")
    try:
        return json.loads(raw, object_pairs_hook=strict_object, parse_constant=reject_constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        fail(f"invalid JSON in {label}: {error}")


def file_bytes(path, maximum):
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
                fail(f"{path} is not a bounded regular file")
            raw = handle.read(maximum + 1)
            if len(raw) != info.st_size:
                fail(f"{path} changed size while reading")
            return raw
    except OSError as error:
        fail(f"cannot read {path}: {error}")


def identity(version, source_sha, source_epoch):
    if not isinstance(version, str) or len(version) > 32:
        fail("stable version is outside policy")
    matches(version, VERSION, "stable version")
    if any(int(part) > 2_147_483_647 for part in version.split(".")):
        fail("stable version is outside policy")
    matches(source_sha, SHA1, "source SHA")
    integer(source_epoch, "source epoch", maximum=253_402_300_799)
    return {
        "version": version, "sourceRepository": SOURCE_REPOSITORY,
        "sourceSHA": source_sha, "sourceEpoch": source_epoch,
    }


def checks(variant):
    result = list(COMMON_CHECKS)
    if variant != "wagied-headquarters":
        result.extend(RUNNER_CHECKS)
    if variant in {"wagied", "wagied-runner-toolchains"}:
        result.append("toolchain-versions")
    if variant == "wagied-headquarters":
        result.append("headquarters-runtime-dependencies")
    return result


def destination(variant, version):
    name = "wagied-runner" if variant == "wagied-runner-toolchains" else variant
    tag = version + ("-toolchains" if variant == "wagied-runner-toolchains" else "")
    return "docker.io/wagiedev/" + name, tag


class Tree:
    """Inventory before reading; permit only declared regular files/directories."""

    def __init__(self, root):
        self.root = Path(root)
        self.files = {}
        self.directories = set()
        self.used = set()
        self.hashed_layers = set()
        self.total = 0
        self._walk(self.root, "", 0)

    def _walk(self, path, relative, depth):
        if depth > 6:
            fail("transfer directory depth exceeds policy")
        try:
            if not stat.S_ISDIR(path.lstat().st_mode):
                fail(f"{path} is not a real directory")
            with os.scandir(path) as entries:
                for entry in entries:
                    if len(self.files) + len(self.directories) >= MAX_FILES:
                        fail("transfer entry count exceeds policy")
                    if not re.fullmatch(r"[A-Za-z0-9._-]+", entry.name) or entry.name in {".", ".."}:
                        fail("unsafe transfer path")
                    name = f"{relative}/{entry.name}" if relative else entry.name
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        self.directories.add(name)
                        self._walk(Path(entry.path), name, depth + 1)
                    elif stat.S_ISREG(info.st_mode):
                        if not 0 < info.st_size <= MAX_BLOB:
                            fail(f"{name} size exceeds policy")
                        self.files[name] = info.st_size
                        self.total += info.st_size
                        if self.total > MAX_TRANSFER:
                            fail("transfer total size exceeds policy")
                    else:
                        fail(f"{name} is not a regular file or directory")
        except OSError as error:
            fail(f"cannot inventory transfer: {error}")

    def read(self, name, maximum=MAX_JSON):
        if name not in self.files or self.files[name] > maximum:
            fail(f"missing or oversized {name}")
        self.used.add(name)
        return file_bytes(self.root / name, maximum)

    def json(self, name, maximum=MAX_JSON):
        return parse_json(self.read(name, maximum), name)

    def blob(self, layout, descriptor, media, platform=None, json_blob=True):
        exact_keys(descriptor, {"mediaType", "digest", "size"}, "OCI descriptor", {"annotations", "platform"})
        if not isinstance(descriptor["mediaType"], str) or descriptor["mediaType"] not in media:
            fail("OCI descriptor media type is outside policy")
        digest = matches(descriptor["digest"], DIGEST, "OCI descriptor digest")
        maximum = MAX_JSON if json_blob else MAX_BLOB
        size = integer(descriptor["size"], "OCI descriptor size", maximum=maximum)
        annotations(descriptor.get("annotations", {}))
        if platform is None and "platform" in descriptor:
            fail("unexpected platform on OCI descriptor")
        if platform is not None:
            validate_platform(descriptor.get("platform"), platform)
        name = f"{layout}/blobs/sha256/{digest[7:]}"
        if self.files.get(name) != size:
            fail(f"OCI descriptor size disagrees for {name}")
        self.used.add(name)
        if not json_blob and name in self.hashed_layers:
            return None
        if json_blob:
            raw = self.read(name, maximum)
            actual = hashlib.sha256(raw).hexdigest()
        else:
            hashed = hashlib.sha256()
            count = 0
            try:
                with os.fdopen(os.open(self.root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
                    info = os.fstat(handle.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size != size:
                        fail("OCI layer changed before hashing")
                    while chunk := handle.read(1024 * 1024):
                        count += len(chunk)
                        if count > size:
                            fail("OCI layer grew while hashing")
                        hashed.update(chunk)
                if count != size:
                    fail("OCI layer changed while hashing")
            except OSError as error:
                fail(f"cannot hash OCI layer: {error}")
            actual = hashed.hexdigest()
        if actual != digest[7:]:
            fail(f"OCI blob digest mismatch for {name}")
        if not json_blob:
            self.hashed_layers.add(name)
        return parse_json(raw, name) if json_blob else None

    def closed(self):
        expected_directories = set()
        for name in self.used:
            expected_directories.update(str(parent) for parent in Path(name).parents if str(parent) != ".")
        if set(self.files) != self.used or self.directories != expected_directories:
            fail(f"transfer closure mismatch: undeclared files={sorted(set(self.files) - self.used)} directories={sorted(self.directories - expected_directories)}")


def annotations(value):
    if not isinstance(value, dict) or len(value) > 32 or any(
        not isinstance(key, str) or not isinstance(item, str) or len(key) > 256 or len(item) > 4096
        for key, item in value.items()
    ):
        fail("OCI annotations are outside policy")


def validate_platform(value, architecture):
    exact_keys(value, {"os", "architecture"}, "OCI platform", {"variant"})
    if value["os"] != "linux" or value["architecture"] != architecture:
        fail("OCI platform disagrees with required architecture")
    if "variant" in value and (architecture != "arm64" or value["variant"] != "v8"):
        fail("OCI platform variant is outside policy")


def index_document(value):
    exact_keys(value, {"schemaVersion", "manifests"}, "OCI index", {"mediaType", "annotations"})
    integer(value["schemaVersion"], "OCI index schema", 2, 2)
    if value.get("mediaType", INDEX_MEDIA) != INDEX_MEDIA:
        fail("OCI index media type is outside policy")
    annotations(value.get("annotations", {}))
    if not isinstance(value["manifests"], list):
        fail("OCI index manifests are not a list")


def validate_config(value, architecture, release, layer_count):
    exact_keys(value, {"architecture", "os", "config", "rootfs"}, "OCI config", {"created", "author", "history", "variant"})
    validate_platform({key: value[key] for key in ("architecture", "os", "variant") if key in value}, architecture)
    expected_created = datetime.datetime.fromtimestamp(release["sourceEpoch"], datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if value.get("created") != expected_created:
        fail("OCI config creation time disagrees with release epoch")
    config = value["config"]
    exact_keys(config, set(), "OCI runtime config", {"User", "ExposedPorts", "Env", "Entrypoint", "Cmd", "Volumes", "WorkingDir", "Labels", "StopSignal", "ArgsEscaped", "Healthcheck", "Shell", "OnBuild"})
    labels = config.get("Labels")
    annotations(labels)
    expected = {
        "org.opencontainers.image.version": release["version"],
        "org.opencontainers.image.revision": release["sourceSHA"],
        "org.opencontainers.image.source": "https://github.com/" + SOURCE_REPOSITORY,
    }
    if any(labels.get(key) != item for key, item in expected.items()):
        fail("OCI config release labels disagree with expected identity")
    rootfs = value["rootfs"]
    exact_keys(rootfs, {"type", "diff_ids"}, "OCI rootfs")
    if rootfs["type"] != "layers" or not isinstance(rootfs["diff_ids"], list) or len(rootfs["diff_ids"]) != layer_count:
        fail("OCI config rootfs does not describe its layers")
    for digest in rootfs["diff_ids"]:
        matches(digest, DIGEST, "rootfs diff ID")
    history = value.get("history", [])
    if not isinstance(history, list) or len(history) > 1024:
        fail("OCI config history exceeds policy")
    for item in history:
        exact_keys(item, set(), "OCI history item", {"created", "created_by", "author", "comment", "empty_layer"})
        if "empty_layer" in item and type(item["empty_layer"]) is not bool:
            fail("OCI history empty_layer is not boolean")


def evidence_record(tree, variant, architecture, suffix):
    path = f"evidence/{variant}/{architecture}.{suffix}.json"
    raw = tree.read(path, MAX_EVIDENCE)
    return {"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}, parse_json(raw, path)


def validate_test(value, variant, platform, release):
    exact_keys(value, {"schema", "version", "sourceSHA", "sourceEpoch", "variant", "platform", "manifestDigest", "configDigest", "binarySHA256", "buildIdentity", "checks", "result"}, "image test evidence")
    expected = {
        "schema": "wagie.image-test/v1", "version": release["version"],
        "sourceSHA": release["sourceSHA"], "sourceEpoch": release["sourceEpoch"],
        "variant": variant, "platform": platform["platform"],
        "manifestDigest": platform["manifestDigest"], "configDigest": platform["configDigest"],
        "checks": checks(variant), "result": "passed",
    }
    integer(value["sourceEpoch"], "test source epoch")
    if any(value[key] != item for key, item in expected.items()):
        fail("image test evidence disagrees with release, subject, or required checks")
    matches(value["binarySHA256"], SHA256, "tested binary SHA-256")
    build = value["buildIdentity"]
    expected_build = {
        "schema": "wagie.build-identity/v1",
        "profile": "release/" + ("wagied-runner" if variant == "wagied-runner-toolchains" else variant),
        "version": release["version"], "commit": release["sourceSHA"],
        "sourceEpoch": release["sourceEpoch"], "runnerProtocolVersion": 1,
    }
    exact_keys(build, expected_build, "tested binary build identity")
    integer(build["sourceEpoch"], "build source epoch")
    integer(build["runnerProtocolVersion"], "runner protocol version", 1, 1)
    if build != expected_build:
        fail("tested binary build identity disagrees with release role")


def validate_spdx(value, manifest_digest):
    if not isinstance(value, dict) or any(value.get(key) != expected for key, expected in {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "dataLicense": "CC0-1.0",
    }.items()):
        fail("image SBOM is not an SPDX 2.3 document")
    describes, packages = value.get("documentDescribes"), value.get("packages")
    if not isinstance(describes, list) or len(describes) != 1 or not isinstance(describes[0], str):
        fail("image SBOM must describe exactly one image subject")
    if not isinstance(packages, list) or not 1 <= len(packages) <= 100_000:
        fail("image SBOM package count exceeds policy")
    ids = set()
    subject = None
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("SPDXID"), str) or package["SPDXID"] in ids:
            fail("image SBOM has invalid or duplicate package IDs")
        ids.add(package["SPDXID"])
        if package["SPDXID"] == describes[0]:
            subject = package
    if subject is None or not isinstance(subject.get("checksums"), list):
        fail("image SBOM subject checksum disagrees with child manifest")
    checksums = {}
    for item in subject["checksums"]:
        exact_keys(item, {"algorithm", "checksumValue"}, "image SBOM subject checksum")
        algorithm, checksum = item["algorithm"], item["checksumValue"]
        if not isinstance(algorithm, str) or not isinstance(checksum, str) or algorithm in checksums:
            fail("image SBOM subject has duplicate or invalid checksum algorithms")
        checksums[algorithm] = checksum
    if checksums.get("SHA256") != manifest_digest[7:]:
        fail("image SBOM subject checksum disagrees with child manifest")


def platform_evidence(tree, variant, architecture, platform, release):
    sbom, spdx = evidence_record(tree, variant, architecture, "spdx")
    test, evidence = evidence_record(tree, variant, architecture, "test")
    validate_spdx(spdx, platform["manifestDigest"])
    validate_test(evidence, variant, platform, release)
    return {**platform, "sbom": sbom, "test": test}


def image_record(tree, variant, release):
    layout = f"images/{variant}"
    if tree.json(f"{layout}/oci-layout") != {"imageLayoutVersion": "1.0.0"}:
        fail("OCI layout version is not exact")
    outer = tree.json(f"{layout}/index.json")
    index_document(outer)
    if len(outer["manifests"]) != 1:
        fail("OCI layout must reference exactly one image index")
    descriptor = outer["manifests"][0]
    index = tree.blob(layout, descriptor, {INDEX_MEDIA})
    index_document(index)
    if len(index["manifests"]) != 2:
        fail("image index must contain exactly two platforms")
    platforms = []
    for architecture, child in zip(ARCHITECTURES, index["manifests"], strict=True):
        manifest = tree.blob(layout, child, {MANIFEST_MEDIA}, architecture)
        exact_keys(manifest, {"schemaVersion", "mediaType", "config", "layers"}, "OCI manifest", {"annotations"})
        integer(manifest["schemaVersion"], "OCI manifest schema", 2, 2)
        if manifest["mediaType"] != MANIFEST_MEDIA:
            fail("OCI manifest media type is outside policy")
        annotations(manifest.get("annotations", {}))
        layers = manifest["layers"]
        if not isinstance(layers, list) or not 1 <= len(layers) <= MAX_LAYERS:
            fail("OCI layer count exceeds policy")
        config = tree.blob(layout, manifest["config"], {CONFIG_MEDIA})
        validate_config(config, architecture, release, len(layers))
        for layer in layers:
            tree.blob(layout, layer, LAYER_MEDIA, json_blob=False)
        platform = {
            "platform": "linux/" + architecture,
            "manifestDigest": child["digest"], "manifestSize": child["size"],
            "configDigest": manifest["config"]["digest"],
        }
        platforms.append(platform_evidence(tree, variant, architecture, platform, release))
    repository, tag = destination(variant, release["version"])
    return {
        "variant": variant, "repository": repository, "tag": tag, "layout": layout,
        "indexDigest": descriptor["digest"], "indexSize": descriptor["size"], "platforms": platforms,
    }


def validate_manifest(value, release, inputs_digest):
    exact_keys(value, {"schema", *release, "inputsSHA256", "images"}, "images manifest")
    integer(value["sourceEpoch"], "manifest source epoch")
    if value["schema"] != "wagie.images/v1" or value["inputsSHA256"] != inputs_digest or any(value[key] != item for key, item in release.items()):
        fail("images manifest release identity or reviewed inputs disagree")
    if not isinstance(value["images"], list) or len(value["images"]) != 4:
        fail("images manifest catalog is not closed")
    for variant, image in zip(VARIANTS, value["images"], strict=True):
        exact_keys(image, {"variant", "repository", "tag", "layout", "indexDigest", "indexSize", "platforms"}, "image record")
        repository, tag = destination(variant, release["version"])
        if any(image[key] != expected for key, expected in {"variant": variant, "repository": repository, "tag": tag, "layout": "images/" + variant}.items()):
            fail("image destination or layout is outside the finite catalog")
        matches(image["indexDigest"], DIGEST, "image index digest")
        integer(image["indexSize"], "image index size", maximum=MAX_JSON)
        if not isinstance(image["platforms"], list) or len(image["platforms"]) != 2:
            fail("image manifest platforms are not exact")
        for architecture, platform in zip(ARCHITECTURES, image["platforms"], strict=True):
            exact_keys(platform, {"platform", "manifestDigest", "manifestSize", "configDigest", "sbom", "test"}, "platform record")
            if platform["platform"] != "linux/" + architecture:
                fail("image manifest platform is outside policy")
            matches(platform["manifestDigest"], DIGEST, "child manifest digest")
            matches(platform["configDigest"], DIGEST, "config digest")
            integer(platform["manifestSize"], "child manifest size", maximum=MAX_JSON)
            for field, suffix in (("sbom", "spdx"), ("test", "test")):
                record = platform[field]
                exact_keys(record, {"path", "sha256", "size"}, "evidence record")
                if record["path"] != f"evidence/{variant}/{architecture}.{suffix}.json":
                    fail("evidence path is outside policy")
                matches(record["sha256"], SHA256, "evidence digest")
                integer(record["size"], "evidence size", maximum=MAX_EVIDENCE)


def signature(tree, required):
    if required or "images.json.sigstore.json" in tree.files:
        bundle = tree.json("images.json.sigstore.json", 1024 * 1024)
        if not isinstance(bundle, dict) or not bundle:
            fail("image signature bundle is not a JSON object")


def verify_transfer(root, version, source_sha, source_epoch, inputs, require_signature=False, write=False):
    release = identity(version, source_sha, source_epoch)
    inputs_digest = hashlib.sha256(file_bytes(inputs, 1024 * 1024)).hexdigest()
    tree = Tree(root)
    value = {
        "schema": "wagie.images/v1", **release, "inputsSHA256": inputs_digest,
        "images": [image_record(tree, variant, release) for variant in VARIANTS],
    }
    if not write:
        supplied = tree.json("images.json")
        validate_manifest(supplied, release, inputs_digest)
        if value != supplied:
            fail("images manifest disagrees with actual OCI layout or evidence bytes")
    elif "images.json" in tree.files or "images.json.sigstore.json" in tree.files:
        fail("refusing to overwrite an existing images manifest or signature")
    signature(tree, require_signature)
    tree.closed()
    if write:
        with (tree.root / "images.json").open("x", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
    return value


def verify_evidence(root, version, source_sha, source_epoch, inputs):
    """Verify public metadata only; it cannot replace full OCI graph validation."""
    release = identity(version, source_sha, source_epoch)
    trusted_inputs = file_bytes(inputs, 1024 * 1024)
    tree = Tree(root)
    value = tree.json("images.json")
    validate_manifest(value, release, hashlib.sha256(trusted_inputs).hexdigest())
    if tree.read("image-inputs.env", 1024 * 1024) != trusted_inputs:
        fail("public image inputs differ from reviewed inputs")
    signature(tree, True)
    for image in value["images"]:
        for architecture, platform in zip(ARCHITECTURES, image["platforms"], strict=True):
            actual = platform_evidence(tree, image["variant"], architecture, platform, release)
            if actual != platform:
                fail("public image evidence digest or size disagrees with signed manifest")
    tree.closed()
    return value


def export_evidence(root, output, version, source_sha, source_epoch, inputs):
    value = verify_transfer(root, version, source_sha, source_epoch, inputs, require_signature=True)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    names = {"images.json", "images.json.sigstore.json"}
    names.update(platform[field]["path"] for image in value["images"] for platform in image["platforms"] for field in ("sbom", "test"))
    for name in sorted(names):
        destination_path = output / name
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(root) / name, destination_path, follow_symlinks=False)
    (output / "image-inputs.env").write_bytes(file_bytes(inputs, 1024 * 1024))
    verify_evidence(output, version, source_sha, source_epoch, inputs)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("write", "verify", "export-evidence", "verify-evidence"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-epoch", required=True, type=int)
    parser.add_argument("--source-repo", default=SOURCE_REPOSITORY, choices=(SOURCE_REPOSITORY,))
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--require-signature", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    common = (args.root, args.version, args.source_sha, args.source_epoch, args.inputs)
    try:
        if args.command == "export-evidence":
            if args.output is None:
                fail("export-evidence requires --output")
            export_evidence(args.root, args.output, *common[1:])
        elif args.command == "verify-evidence":
            verify_evidence(*common)
        else:
            verify_transfer(*common, require_signature=args.require_signature, write=args.command == "write")
    except (PolicyError, OSError) as error:
        print(f"OCI policy: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
