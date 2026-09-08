#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path


SOURCE_REPOSITORY = "Savid/wagie"
DESTINATION_REPOSITORY = "wagiedev/distribution"
SOURCE_WORKFLOW = ".github/workflows/release.yml"
CHANNEL = "stable"
MAX_ARTIFACT_BYTES = 160 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_SAFE_INTEGER = 9_007_199_254_740_991
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._+-]+$")
UTC_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
RELEASE_KEYS = {
    "schemaVersion",
    "channel",
    "releaseVersion",
    "tag",
    "sourceRepository",
    "sourceSHA",
    "sourceCommittedAt",
    "sourceEpoch",
    "artifacts",
}
INDEX_KEYS = {
    "schemaVersion",
    "channel",
    "releaseVersion",
    "tag",
    "sourceRepository",
    "sourceSHA",
    "sourceEpoch",
    "payload",
}
ARTIFACT_KEYS = {
    "filename",
    "size",
    "sha256",
    "members",
    "platform",
    "role",
    "kind",
}
SOURCE_SUCCESS_JOBS = {
    "preflight",
    "distribution_preflight",
    "go_builder",
    "tui_linux_builder",
    "assemble",
    "public_installer_physical",
    "seal_distribution",
    "container_build",
    "seal_containers",
}


class PolicyError(Exception):
    pass


def fail(message):
    raise PolicyError(message)


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_constant(value):
    fail(f"non-finite JSON number {value!r}")


def read_json(path, maximum=MAX_MANIFEST_BYTES):
    path = Path(path)
    require_regular(path, maximum)
    try:
        raw = path.read_bytes()
        return json.loads(
            raw,
            object_pairs_hook=strict_object,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid {path.name}: {error}")


def exact_keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        fail(f"{label} has a non-exact schema")


def integer(value, label, minimum=1, maximum=MAX_SAFE_INTEGER):
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{label} is not an integer")
    if value < minimum or value > maximum:
        fail(f"{label} is outside policy")
    return value


def positive_coordinate(value, label):
    if POSITIVE_INTEGER.fullmatch(value) is None:
        fail(f"{label} is invalid")
    parsed = int(value)
    if parsed > MAX_SAFE_INTEGER:
        fail(f"{label} is outside policy")
    return parsed


def stable_version(value):
    match = SEMVER.fullmatch(value) if isinstance(value, str) else None
    if match is None or any(int(component) > 2_147_483_647 for component in match.groups()):
        fail(f"invalid stable version {value!r}")
    return value


def utc_timestamp(value, label):
    if not isinstance(value, str) or UTC_TIMESTAMP.fullmatch(value) is None:
        fail(f"{label} is not an exact UTC timestamp")
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label} is invalid")


def safe_filename(value):
    if not isinstance(value, str) or SAFE_FILENAME.fullmatch(value) is None:
        fail(f"unsafe filename {value!r}")
    if value in {".", ".."} or len(value.encode("utf-8")) > 255:
        fail(f"unsafe filename {value!r}")
    return value


def require_regular(path, maximum=MAX_ARTIFACT_BYTES):
    try:
        info = Path(path).lstat()
    except OSError as error:
        fail(f"cannot inspect {path}: {error}")
    if not stat.S_ISREG(info.st_mode):
        fail(f"{path} is not a regular file")
    if info.st_size <= 0 or info.st_size > maximum:
        fail(f"{path} has a size outside policy")
    return info.st_size


def require_directory(path):
    try:
        info = Path(path).lstat()
    except OSError as error:
        fail(f"cannot inspect {path}: {error}")
    if not stat.S_ISDIR(info.st_mode):
        fail(f"{path} is not a directory")


def digest(path):
    size = require_regular(path)
    hashed = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hashed.update(chunk)
    return hashed.hexdigest(), size


def artifact_item(filename, platform, role, kind):
    return {
        "filename": filename,
        "platform": platform,
        "role": role,
        "kind": kind,
    }


def archive_members(role):
    names = {
        "all": ["wagied"],
        "headquarters": ["wagied-headquarters"],
        "runner": ["wagied-runner"],
        "client": ["wagie", "wagiectl"],
    }
    if role not in names:
        fail("archive role is outside the release catalog")
    return names[role]


def payload_catalog(version):
    stable_version(version)
    result = {}
    roles = (
        ("wagied", "all"),
        ("wagied-headquarters", "headquarters"),
        ("wagied-runner", "runner"),
    )
    targets = (
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("darwin", "amd64"),
        ("darwin", "arm64"),
    )
    for prefix, role in roles:
        for goos, architecture in targets:
            name = f"{prefix}_{version}_{goos}_{architecture}.tar.gz"
            result[name] = artifact_item(name, f"{goos}/{architecture}", role, "archive")
    for name, item in tuple(result.items()):
        sbom = name + ".sbom.json"
        result[sbom] = artifact_item(sbom, item["platform"], item["role"], "sbom")
    result["checksums.txt"] = artifact_item(
        "checksums.txt", "any", "distribution", "checksum"
    )
    result["install.sh"] = artifact_item(
        "install.sh", "any", "distribution", "installer"
    )
    clients = {
        f"wagie_{version}_linux_x64_glibc.tar.gz": "linux/amd64",
    }
    for name, platform in clients.items():
        result[name] = artifact_item(name, platform, "client", "archive")
        sbom = name + ".sbom.json"
        result[sbom] = artifact_item(sbom, platform, "client", "sbom")
    name = f"wagie_{version}_checksums.txt"
    result[name] = artifact_item(name, "any", "client", "checksum")
    result["release.json"] = artifact_item(
        "release.json", "any", "distribution", "release-metadata"
    )
    if len(result) != 30:
        fail("internal release catalog is not closed")
    return result


def signature_pairs(version):
    return (
        ("checksums.txt", "checksums.txt.sigstore.json"),
        (
            f"wagie_{version}_checksums.txt",
            f"wagie_{version}_checksums.txt.sigstore.json",
        ),
        ("release.json", "release.json.sigstore.json"),
        ("release-manifest.sha256", "release-manifest.sha256.sigstore.json"),
    )


def final_asset_names(version):
    result = set(payload_catalog(version))
    result.update(bundle for _, bundle in signature_pairs(version)[:-1])
    result.update({"release-manifest.sha256", "release-manifest.sha256.sigstore.json"})
    if len(result) != 35:
        fail("internal final release closure is invalid")
    return result


def exact_directory(path, expected, label):
    path = Path(path)
    require_directory(path)
    try:
        entries = list(path.iterdir())
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    actual = {entry.name for entry in entries}
    if len(actual) != len(entries):
        fail(f"{label} contains duplicate names")
    if actual != set(expected):
        fail(
            f"{label} closure mismatch missing={sorted(set(expected) - actual)} "
            f"extra={sorted(actual - set(expected))}"
        )
    for entry in entries:
        safe_filename(entry.name)
        require_regular(entry)


def validate_artifact(value, expected, label):
    exact_keys(value, ARTIFACT_KEYS, label)
    name = safe_filename(value["filename"])
    if expected is None or any(value[key] != expected[key] for key in expected):
        fail(f"{label} identity is outside the release catalog")
    size = integer(value["size"], f"{label} size", maximum=MAX_ARTIFACT_BYTES)
    hashed = value["sha256"]
    if not isinstance(hashed, str) or SHA256.fullmatch(hashed) is None:
        fail(f"{label} has an invalid SHA-256 digest")
    members = value["members"]
    expected_members = archive_members(value["role"]) if value["kind"] == "archive" else []
    if not isinstance(members, list) or len(members) != len(expected_members):
        fail(f"{label} executable members are not exact")
    for member, expected_name in zip(members, expected_members, strict=True):
        exact_keys(member, {"name", "sha256"}, f"{label} member")
        if member["name"] != expected_name:
            fail(f"{label} executable members are not exactly ordered")
        if not isinstance(member["sha256"], str) or SHA256.fullmatch(member["sha256"]) is None:
            fail(f"{label} has an invalid member digest")
    return name, size, hashed


def parse_release(path, expected_repository, expected_sha, expected_tag):
    value = read_json(path)
    exact_keys(value, RELEASE_KEYS, "release.json")
    integer(value["schemaVersion"], "release schema version", 1, 1)
    version = stable_version(value["releaseVersion"])
    epoch = integer(value["sourceEpoch"], "release source epoch")
    try:
        committed = datetime.datetime.fromtimestamp(
            epoch, datetime.timezone.utc
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        fail("release source epoch is outside UTC policy")
    fixed = {
        "schemaVersion": 1,
        "channel": CHANNEL,
        "tag": "v" + version,
        "sourceRepository": SOURCE_REPOSITORY,
        "sourceSHA": expected_sha,
        "sourceCommittedAt": committed,
    }
    if any(value.get(key) != item for key, item in fixed.items()):
        fail("release.json identity disagrees with policy")
    if expected_repository != SOURCE_REPOSITORY or expected_tag != "v" + version:
        fail("dispatch identity disagrees with release.json")
    if SHA1.fullmatch(value["sourceSHA"]) is None:
        fail("release.json source SHA is invalid")
    catalog = payload_catalog(version)
    expected_names = sorted(set(catalog) - {"release.json"})
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 29:
        fail("release.json artifact catalog is not closed")
    records = {}
    for expected_name, artifact in zip(expected_names, artifacts, strict=True):
        if not isinstance(artifact, dict) or artifact.get("filename") != expected_name:
            fail("release.json artifact catalog is not exactly sorted")
        name, _, _ = validate_artifact(
            artifact, catalog[expected_name], f"release.json artifact {expected_name}"
        )
        if name in records:
            fail(f"release.json duplicates {name}")
        records[name] = artifact
    return value, records


def parse_index(path, release, release_records, assets):
    value = read_json(path)
    exact_keys(value, INDEX_KEYS, "asset-index.json")
    integer(value["schemaVersion"], "index schema version", 1, 1)
    fixed = {
        "channel": CHANNEL,
        "releaseVersion": release["releaseVersion"],
        "tag": release["tag"],
        "sourceRepository": release["sourceRepository"],
        "sourceSHA": release["sourceSHA"],
        "sourceEpoch": release["sourceEpoch"],
    }
    if any(value.get(key) != item for key, item in fixed.items()):
        fail("asset-index.json identity disagrees with release.json")
    catalog = payload_catalog(release["releaseVersion"])
    payload = value["payload"]
    names = sorted(catalog)
    if not isinstance(payload, list) or len(payload) != 30:
        fail("asset-index.json payload is not closed")
    indexed = {}
    for expected_name, artifact in zip(names, payload, strict=True):
        if not isinstance(artifact, dict) or artifact.get("filename") != expected_name:
            fail("asset-index.json payload is not exactly sorted")
        name, size, hashed = validate_artifact(
            artifact, catalog[expected_name], f"indexed artifact {expected_name}"
        )
        actual_hash, actual_size = digest(assets / name)
        if (actual_hash, actual_size) != (hashed, size):
            fail(f"indexed bytes disagree for {name}")
        if name != "release.json" and artifact != release_records[name]:
            fail(f"release.json and index disagree for {name}")
        indexed[name] = artifact
    return indexed


def parse_checksums(path, expected):
    require_regular(path, MAX_MANIFEST_BYTES)
    try:
        lines = Path(path).read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        fail(f"invalid {Path(path).name}: {error}")
    if len(lines) != len(expected):
        fail(f"{Path(path).name} does not describe its exact closure")
    result = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            fail(f"malformed {Path(path).name}")
        hashed, name = line[:64], safe_filename(line[66:])
        if SHA256.fullmatch(hashed) is None or name in result:
            fail(f"invalid {Path(path).name} entry")
        result[name] = hashed
    if list(result) != sorted(result) or set(result) != set(expected):
        fail(f"{Path(path).name} membership or order disagrees with policy")
    return result


def verify_embedded_checksums(assets, indexed, version):
    go_names = {
        name
        for name, value in indexed.items()
        if value["role"] in {"all", "headquarters", "runner"} or name == "install.sh"
    }
    tui_names = {
        name
        for name, value in indexed.items()
        if value["role"] == "client" and value["kind"] != "checksum"
    }
    groups = (
        ("checksums.txt", go_names),
        (f"wagie_{version}_checksums.txt", tui_names),
    )
    for checksum_name, names in groups:
        entries = parse_checksums(assets / checksum_name, names)
        for name, hashed in entries.items():
            if indexed[name]["sha256"] != hashed:
                fail(f"{checksum_name} digest disagrees for {name}")


def verify_manifest(assets, version):
    premanifest = final_asset_names(version) - {
        "release-manifest.sha256",
        "release-manifest.sha256.sigstore.json",
    }
    entries = parse_checksums(assets / "release-manifest.sha256", premanifest)
    for name, hashed in entries.items():
        if digest(assets / name)[0] != hashed:
            fail(f"release manifest digest disagrees for {name}")


def verify_evidence(evidence):
    names = {
        "asset-index.json",
        "goreleaser-artifacts.json",
        "goreleaser-checksums.txt",
    }
    exact_directory(evidence, names, "release evidence")
    read_json(evidence / "goreleaser-artifacts.json", MAX_EVIDENCE_BYTES)
    require_regular(evidence / "goreleaser-checksums.txt", MAX_EVIDENCE_BYTES)
    try:
        (evidence / "goreleaser-checksums.txt").read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        fail(f"invalid GoReleaser checksum evidence: {error}")


def verify_transfer(root, source_repository, source_sha, tag):
    if source_repository != SOURCE_REPOSITORY:
        fail("source repository is not authorized")
    if SHA1.fullmatch(source_sha) is None:
        fail("source SHA is invalid")
    version = stable_version(tag.removeprefix("v"))
    if tag != "v" + version:
        fail("tag is not an exact stable tag")
    root = Path(root)
    require_directory(root)
    entries = list(root.iterdir())
    if {entry.name for entry in entries} != {"assets", "evidence"} or len(entries) != 2:
        fail("transfer root must contain exactly assets and evidence")
    assets, evidence = root / "assets", root / "evidence"
    exact_directory(assets, final_asset_names(version), "release assets")
    verify_evidence(evidence)
    release, release_records = parse_release(
        assets / "release.json", source_repository, source_sha, tag
    )
    indexed = parse_index(
        evidence / "asset-index.json", release, release_records, assets
    )
    verify_embedded_checksums(assets, indexed, version)
    verify_manifest(assets, version)


def validate_inputs(args):
    if args.source_repository != SOURCE_REPOSITORY:
        fail("source repository is not authorized")
    positive_coordinate(args.source_run_id, "source run ID")
    if SHA1.fullmatch(args.source_sha) is None:
        fail("source SHA is invalid")
    version = stable_version(args.tag.removeprefix("v"))
    if args.tag != "v" + version:
        fail("tag is not an exact stable tag")
    positive_coordinate(args.source_artifact_id, "source artifact ID")
    if SHA256.fullmatch(args.source_artifact_digest) is None:
        fail("source artifact digest is invalid")
    positive_coordinate(args.container_artifact_id, "container artifact ID")
    if SHA256.fullmatch(args.container_artifact_digest) is None:
        fail("container artifact digest is invalid")
    if args.container_artifact_id == args.source_artifact_id:
        fail("native and container artifact IDs must differ")


def validate_source(args):
    validate_inputs(args)
    run = read_json(args.run, MAX_EVIDENCE_BYTES)
    jobs = read_json(args.jobs, MAX_EVIDENCE_BYTES)
    artifact = read_json(args.artifact, MAX_EVIDENCE_BYTES)
    container_artifact = read_json(args.container_artifact, MAX_EVIDENCE_BYTES)
    tag_commit = read_json(args.tag_commit, MAX_EVIDENCE_BYTES)
    run_id = positive_coordinate(args.source_run_id, "source run ID")
    attempt = 1
    if not isinstance(run, dict):
        fail("source workflow run response is invalid")
    integer(run.get("id"), "source workflow run ID")
    integer(run.get("run_attempt"), "source workflow run attempt")
    expected_run = {
        "id": run_id,
        "run_attempt": attempt,
        "event": "push",
        "status": "in_progress",
        "conclusion": None,
        "head_sha": args.source_sha,
        "head_branch": args.tag,
        "path": SOURCE_WORKFLOW,
    }
    if not isinstance(run, dict) or any(run.get(key) != value for key, value in expected_run.items()):
        fail("source workflow run identity is not live and exact")
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    if not isinstance(repository, dict) or repository.get("full_name") != SOURCE_REPOSITORY:
        fail("source workflow run repository is not authorized")
    if not isinstance(head_repository, dict) or head_repository.get("full_name") != SOURCE_REPOSITORY:
        fail("source workflow run head repository is not authorized")
    repository_id = integer(repository.get("id"), "source repository ID")
    head_repository_id = integer(head_repository.get("id"), "source head repository ID")
    if head_repository_id != repository_id:
        fail("source workflow run crosses repositories")
    if not isinstance(jobs, dict) or set(jobs) != {"total_count", "jobs"}:
        fail("source jobs response is invalid")
    job_values = jobs["jobs"]
    integer(jobs.get("total_count"), "source jobs total count")
    if not isinstance(job_values, list) or jobs["total_count"] != len(job_values):
        fail("source jobs response count is invalid")
    by_name = {}
    for job in job_values:
        if not isinstance(job, dict) or not isinstance(job.get("name"), str):
            fail("source jobs response contains an invalid job")
        if job["name"] in by_name:
            fail(f"source jobs response duplicates {job['name']}")
        by_name[job["name"]] = job
    for name in SOURCE_SUCCESS_JOBS:
        job = by_name.get(name)
        if job is None or job.get("status") != "completed" or job.get("conclusion") != "success":
            fail(f"source prerequisite job {name} is not successful")
        integer(job.get("run_id"), f"source prerequisite job {name} run ID")
        integer(job.get("run_attempt"), f"source prerequisite job {name} run attempt")
        if job.get("run_id") != run_id or job.get("run_attempt") != attempt:
            fail(f"source prerequisite job {name} belongs to another attempt")
    dispatch = by_name.get("dispatch_distribution")
    if dispatch is None or dispatch.get("status") != "in_progress" or dispatch.get("conclusion") is not None:
        fail("source distribution dispatch is not live")
    integer(dispatch.get("run_id"), "source distribution dispatch run ID")
    integer(dispatch.get("run_attempt"), "source distribution dispatch run attempt")
    if dispatch.get("run_id") != run_id or dispatch.get("run_attempt") != attempt:
        fail("source distribution dispatch belongs to another attempt")
    validate_artifact_identity(artifact, args.source_artifact_id, args.source_artifact_digest,
                               "distribution-release", by_name["seal_distribution"],
                               run_id, repository_id, args.source_sha)
    validate_artifact_identity(container_artifact, args.container_artifact_id,
                               args.container_artifact_digest, "container-release",
                               by_name["seal_containers"], run_id, repository_id,
                               args.source_sha)
    if not isinstance(tag_commit, dict) or tag_commit.get("sha") != args.source_sha:
        fail("source tag does not resolve to the dispatched SHA")


def validate_artifact_identity(artifact, artifact_id, artifact_digest, name, seal,
                               run_id, repository_id, source_sha):
    if not isinstance(artifact, dict):
        fail("source artifact response is invalid")
    artifact_run = artifact.get("workflow_run")
    expected_artifact = {
        "id": positive_coordinate(artifact_id, "source artifact ID"),
        "name": name,
        "expired": False,
        "digest": "sha256:" + artifact_digest,
    }
    if any(artifact.get(key) != value for key, value in expected_artifact.items()):
        fail("source artifact identity is invalid")
    integer(artifact.get("id"), "source artifact ID")
    if type(artifact.get("expired")) is not bool:
        fail("source artifact expiration state is not a boolean")
    if not isinstance(artifact_run, dict):
        fail("source artifact has no workflow provenance")
    for field in ("id", "repository_id", "head_repository_id"):
        integer(artifact_run.get(field), f"source artifact workflow {field}")
    if (
        artifact_run.get("id") != run_id
        or artifact_run.get("head_sha") != source_sha
        or artifact_run.get("repository_id") != repository_id
        or artifact_run.get("head_repository_id") != repository_id
    ):
        fail("source artifact workflow provenance disagrees")
    seal_started = utc_timestamp(seal.get("started_at"), "source seal start")
    seal_completed = utc_timestamp(seal.get("completed_at"), "source seal completion")
    artifact_created = utc_timestamp(artifact.get("created_at"), "source artifact creation")
    artifact_updated = utc_timestamp(artifact.get("updated_at"), "source artifact update")
    if not seal_started <= artifact_created <= artifact_updated <= seal_completed:
        fail("source artifact was not created by the current seal job attempt")


def publication_assets(root, version, container_evidence=None):
    assets = Path(root) / "assets"
    names = final_asset_names(version)
    exact_directory(assets, names, "release assets")
    result = {name: assets / name for name in names}
    if container_evidence is not None:
        path = Path(container_evidence)
        if path.name != f"containers_{version}.tar.gz":
            fail("container evidence name disagrees with release")
        require_regular(path, MAX_EVIDENCE_BYTES)
        result[path.name] = path
    return result


def write_checksums(root, output, container_evidence=None):
    assets = Path(root) / "assets"
    release = read_json(assets / "release.json")
    if not isinstance(release, dict):
        fail("release.json is not an object")
    version = stable_version(release.get("releaseVersion"))
    files = publication_assets(root, version, container_evidence)
    output = Path(output)
    if output.exists() or output.is_symlink():
        fail("attestation checksum output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="ascii", newline="\n") as handle:
        for name, path in sorted(files.items()):
            handle.write(f"{digest(path)[0]}  {name}\n")


def verify_release_readback(path, root, tag, release_id, phase, receiver_sha, container_evidence=None):
    release = read_json(path, MAX_EVIDENCE_BYTES)
    if not isinstance(release, dict):
        fail("destination release response is invalid")
    version = stable_version(tag.removeprefix("v"))
    if tag != "v" + version:
        fail("destination release identity is invalid")
    if not isinstance(receiver_sha, str) or SHA1.fullmatch(receiver_sha) is None:
        fail("destination commit is invalid")
    integer(release_id, "destination release ID")
    integer(release.get("id"), "destination release readback ID")
    for field in ("draft", "prerelease", "immutable"):
        if type(release.get(field)) is not bool:
            fail(f"destination release {field} is not a boolean")
    fixed = {
        "id": release_id,
        "target_commitish": receiver_sha,
        "tag_name": tag,
        "name": tag,
        "draft": phase == "draft",
        "prerelease": False,
        "immutable": phase == "published",
    }
    if any(release.get(key) != value for key, value in fixed.items()):
        fail(f"destination {phase} release identity disagrees")
    if phase == "draft" and release.get("published_at") is not None:
        fail("draft release already has a publication time")
    if phase == "published":
        utc_timestamp(release.get("published_at"), "release publication time")
    assets = release.get("assets")
    files = publication_assets(root, version, container_evidence)
    expected_names = sorted(files)
    if not isinstance(assets, list) or len(assets) != len(expected_names):
        fail(f"destination {phase} release asset closure is invalid")
    records = {}
    for asset in assets:
        if not isinstance(asset, dict):
            fail("destination release contains an invalid asset")
        name = safe_filename(asset.get("name"))
        if name in records or name not in expected_names:
            fail(f"destination release contains an unexpected asset {name}")
        expected_hash, expected_size = digest(files[name])
        integer(asset.get("id"), "destination release asset ID")
        integer(asset.get("size"), "destination release asset size", maximum=MAX_ARTIFACT_BYTES)
        if (
            asset.get("state") != "uploaded"
            or asset.get("size") != expected_size
            or asset.get("digest") != "sha256:" + expected_hash
        ):
            fail(f"destination release asset readback disagrees for {name}")
        records[name] = asset
    if set(records) != set(expected_names):
        fail(f"destination {phase} release assets are not closed")


def add_coordinates(parser):
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-run-id", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-artifact-id", required=True)
    parser.add_argument("--source-artifact-digest", required=True)
    parser.add_argument("--container-artifact-id", required=True)
    parser.add_argument("--container-artifact-digest", required=True)


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    inputs = commands.add_parser("validate-inputs")
    add_coordinates(inputs)
    source = commands.add_parser("validate-source")
    add_coordinates(source)
    source.add_argument("--run", required=True)
    source.add_argument("--jobs", required=True)
    source.add_argument("--artifact", required=True)
    source.add_argument("--container-artifact", required=True)
    source.add_argument("--tag-commit", required=True)
    verify = commands.add_parser("verify-transfer")
    verify.add_argument("--root", required=True)
    verify.add_argument("--source-repository", required=True)
    verify.add_argument("--source-sha", required=True)
    verify.add_argument("--tag", required=True)
    pairs = commands.add_parser("signature-pairs")
    pairs.add_argument("--tag", required=True)
    assets = commands.add_parser("list-assets")
    assets.add_argument("--tag", required=True)
    checksums = commands.add_parser("write-checksums")
    checksums.add_argument("--root", required=True)
    checksums.add_argument("--output", required=True)
    checksums.add_argument("--container-evidence")
    readback = commands.add_parser("verify-release-readback")
    readback.add_argument("--release", required=True)
    readback.add_argument("--root", required=True)
    readback.add_argument("--tag", required=True)
    readback.add_argument("--release-id", required=True, type=int)
    readback.add_argument("--receiver-sha", required=True)
    readback.add_argument("--phase", required=True, choices=("draft", "published"))
    readback.add_argument("--container-evidence")
    args = parser.parse_args()
    if args.command == "validate-inputs":
        validate_inputs(args)
    elif args.command == "validate-source":
        validate_source(args)
    elif args.command == "verify-transfer":
        verify_transfer(args.root, args.source_repository, args.source_sha, args.tag)
    elif args.command == "signature-pairs":
        version = stable_version(args.tag.removeprefix("v"))
        if args.tag != "v" + version:
            fail("tag is not an exact stable tag")
        for blob, bundle in signature_pairs(version):
            print(f"{blob}\t{bundle}")
    elif args.command == "list-assets":
        version = stable_version(args.tag.removeprefix("v"))
        if args.tag != "v" + version:
            fail("tag is not an exact stable tag")
        for name in sorted(final_asset_names(version)):
            print(name)
    elif args.command == "write-checksums":
        write_checksums(args.root, args.output, args.container_evidence)
    elif args.command == "verify-release-readback":
        verify_release_readback(
            args.release,
            args.root,
            args.tag,
            args.release_id,
            args.phase,
            args.receiver_sha,
            args.container_evidence,
        )


if __name__ == "__main__":
    try:
        main()
    except PolicyError as error:
        print(error, file=sys.stderr)
        sys.exit(1)
