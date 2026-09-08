import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
import subprocess
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import release_policy as policy  # noqa: E402
import upload_asset  # noqa: E402


VERSION = "1.2.3"
TAG = "v" + VERSION
SOURCE_SHA = "a" * 40
SOURCE_DIGEST = "b" * 64
SOURCE_RUN_ID = "12345"
SOURCE_ARTIFACT_ID = "67890"
CONTAINER_ARTIFACT_ID = "67891"
CONTAINER_DIGEST = "c" * 64
SOURCE_EPOCH = 1_700_000_000


def hashed(path):
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


def json_write(path, value):
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")


def coordinates(**changes):
    values = {
        "source_repository": policy.SOURCE_REPOSITORY,
        "source_run_id": SOURCE_RUN_ID,
        "source_sha": SOURCE_SHA,
        "tag": TAG,
        "source_artifact_id": SOURCE_ARTIFACT_ID,
        "source_artifact_digest": SOURCE_DIGEST,
        "container_artifact_id": CONTAINER_ARTIFACT_ID,
        "container_artifact_digest": CONTAINER_DIGEST,
    }
    values.update(changes)
    return SimpleNamespace(**values)


class TransferFixture:
    def __init__(self, base):
        self.root = Path(base) / "transfer"
        self.assets = self.root / "assets"
        self.evidence = self.root / "evidence"
        self.assets.mkdir(parents=True)
        self.evidence.mkdir()
        self.catalog = policy.payload_catalog(VERSION)
        checksum_names = {"checksums.txt", f"wagie_{VERSION}_checksums.txt"}
        for name in sorted(set(self.catalog) - checksum_names - {"release.json"}):
            (self.assets / name).write_bytes(("payload:" + name).encode())

        self.write_embedded_checksums()
        records = [self.record(name) for name in sorted(set(self.catalog) - {"release.json"})]
        release = {
            "schemaVersion": 1,
            "channel": policy.CHANNEL,
            "releaseVersion": VERSION,
            "tag": TAG,
            "sourceRepository": policy.SOURCE_REPOSITORY,
            "sourceSHA": SOURCE_SHA,
            "sourceCommittedAt": "2023-11-14T22:13:20Z",
            "sourceEpoch": SOURCE_EPOCH,
            "artifacts": records,
        }
        json_write(self.assets / "release.json", release)
        payload = [self.record(name) for name in sorted(self.catalog)]
        index = {
            "schemaVersion": 1,
            "channel": policy.CHANNEL,
            "releaseVersion": VERSION,
            "tag": TAG,
            "sourceRepository": policy.SOURCE_REPOSITORY,
            "sourceSHA": SOURCE_SHA,
            "sourceEpoch": SOURCE_EPOCH,
            "payload": payload,
        }
        json_write(self.evidence / "asset-index.json", index)
        json_write(self.evidence / "goreleaser-artifacts.json", [])
        (self.evidence / "goreleaser-checksums.txt").write_text(
            "c" * 64 + "  install.sh\n", encoding="ascii"
        )
        for _, bundle in policy.signature_pairs(VERSION)[:-1]:
            (self.assets / bundle).write_bytes(("signature:" + bundle).encode())
        premanifest = policy.final_asset_names(VERSION) - {
            "release-manifest.sha256",
            "release-manifest.sha256.sigstore.json",
        }
        self.write_checksum_file(self.assets / "release-manifest.sha256", premanifest)
        (self.assets / "release-manifest.sha256.sigstore.json").write_bytes(b"manifest-signature")

    def record(self, name):
        item = dict(self.catalog[name])
        item["size"] = hashed(self.assets / name)[1]
        item["sha256"] = hashed(self.assets / name)[0]
        item["members"] = [
            {"name": member, "sha256": "d" * 64}
            for member in {
                "all": ["wagied"], "headquarters": ["wagied-headquarters"],
                "runner": ["wagied-runner"], "client": ["wagie", "wagiectl"],
            }.get(item["role"], [])
        ] if item["kind"] == "archive" else []
        return item

    def write_checksum_file(self, path, names):
        path.write_text(
            "".join(f"{hashed(self.assets / name)[0]}  {name}\n" for name in sorted(names)),
            encoding="ascii",
        )

    def write_embedded_checksums(self):
        go_names = {
            name
            for name, value in self.catalog.items()
            if value["role"] in {"all", "headquarters", "runner"} or name == "install.sh"
        }
        tui_names = {
            name
            for name, value in self.catalog.items()
            if value["role"] == "client" and value["kind"] != "checksum"
        }
        self.write_checksum_file(self.assets / "checksums.txt", go_names)
        self.write_checksum_file(self.assets / f"wagie_{VERSION}_checksums.txt", tui_names)

    def release_api(self, phase):
        return {
            "id": 77,
            "tag_name": TAG,
            "target_commitish": "e" * 40,
            "name": TAG,
            "draft": phase == "draft",
            "prerelease": False,
            "immutable": phase == "published",
            "published_at": None if phase == "draft" else "2026-09-01T00:00:00Z",
            "assets": [
                {
                    "id": index + 1,
                    "name": name,
                    "state": "uploaded",
                    "size": hashed(self.assets / name)[1],
                    "digest": "sha256:" + hashed(self.assets / name)[0],
                }
                for index, name in enumerate(sorted(policy.final_asset_names(VERSION)))
            ],
        }


class ReleasePolicyTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return TransferFixture(temporary.name)

    def verify(self, fixture):
        policy.verify_transfer(
            fixture.root, policy.SOURCE_REPOSITORY, SOURCE_SHA, TAG
        )

    def test_valid_closed_transfer(self):
        self.verify(self.fixture())

    def test_native_client_catalog_is_linux_only_and_retains_darwin_daemons(self):
        self.assertNotIn("tui_darwin_builder", policy.SOURCE_SUCCESS_JOBS)
        self.assertIn("tui_linux_builder", policy.SOURCE_SUCCESS_JOBS)
        self.assertNotIn("macos_sign", policy.SOURCE_SUCCESS_JOBS)
        catalog = policy.payload_catalog(VERSION)
        clients = {
            name for name, item in catalog.items()
            if item["role"] == "client"
        }
        self.assertEqual({
            f"wagie_{VERSION}_linux_x64_glibc.tar.gz",
            f"wagie_{VERSION}_linux_x64_glibc.tar.gz.sbom.json",
            f"wagie_{VERSION}_checksums.txt",
        }, clients)
        for prefix in ("wagied", "wagied-headquarters", "wagied-runner"):
            for architecture in ("amd64", "arm64"):
                self.assertIn(f"{prefix}_{VERSION}_darwin_{architecture}.tar.gz", catalog)

    def test_artifact_members_are_exact_ordered_and_required(self):
        fixture = self.fixture()
        name = f"wagie_{VERSION}_linux_x64_glibc.tar.gz"
        expected = fixture.catalog[name]
        valid = fixture.record(name)
        self.assertEqual(["wagie", "wagiectl"], [member["name"] for member in valid["members"]])
        policy.validate_artifact(valid, expected, "client")
        mutations = {
            "missing field": lambda v: v.pop("members"),
            "old scalar field": lambda v: v.update(executableSHA256="d" * 64),
            "null": lambda v: v.update(members=None),
            "empty": lambda v: v.update(members=[]),
            "missing control CLI": lambda v: v["members"].pop(),
            "wrong order": lambda v: v["members"].reverse(),
            "duplicate member": lambda v: v["members"].append(copy.deepcopy(v["members"][0])),
            "wrong name": lambda v: v["members"][0].update(name="other"),
            "uppercase digest": lambda v: v["members"][0].update(sha256="D" * 64),
            "unknown member field": lambda v: v["members"][0].update(extra=True),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                candidate = copy.deepcopy(valid)
                mutate(candidate)
                with self.assertRaises(policy.PolicyError):
                    policy.validate_artifact(candidate, expected, "client")
        metadata = fixture.record("install.sh")
        self.assertEqual([], metadata["members"])
        metadata["members"] = [{"name": "wagie", "sha256": "d" * 64}]
        with self.assertRaisesRegex(policy.PolicyError, "members are not exact"):
            policy.validate_artifact(metadata, fixture.catalog["install.sh"], "installer")

    def test_transfer_rejects_every_closure_and_integrity_break(self):
        mutations = {
            "extra asset": lambda f: (f.assets / "extra").write_bytes(b"x"),
            "unpublished Darwin client": lambda f: (f.assets / f"wagie_{VERSION}_darwin_arm64.tar.gz").write_bytes(b"x"),
            "missing asset": lambda f: (f.assets / "install.sh").unlink(),
            "modified payload": lambda f: (f.assets / "install.sh").write_bytes(b"changed"),
            "extra evidence": lambda f: (f.evidence / "extra").write_bytes(b"x"),
            "symlink asset": lambda f: self.replace_with_symlink(f.assets / "install.sh"),
            "manifest digest": lambda f: self.replace_first_digest(f.assets / "release-manifest.sha256"),
            "embedded checksum": lambda f: self.replace_first_digest(f.assets / "checksums.txt"),
            "release source": lambda f: self.mutate_json(f.assets / "release.json", lambda v: v.update(sourceSHA="f" * 40)),
            "index source": lambda f: self.mutate_json(f.evidence / "asset-index.json", lambda v: v.update(sourceSHA="f" * 40)),
            "unknown release field": lambda f: self.mutate_json(f.assets / "release.json", lambda v: v.update(extra=True)),
            "boolean release schema": lambda f: self.mutate_json(f.assets / "release.json", lambda v: v.update(schemaVersion=True)),
            "boolean index schema": lambda f: self.mutate_json(f.evidence / "asset-index.json", lambda v: v.update(schemaVersion=True)),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                fixture = self.fixture()
                mutate(fixture)
                with self.assertRaises(policy.PolicyError):
                    self.verify(fixture)

    def test_transfer_rejects_duplicate_json_fields(self):
        fixture = self.fixture()
        release = fixture.assets / "release.json"
        raw = release.read_text(encoding="utf-8")
        release.write_text(raw.replace('{"schemaVersion":1', '{"schemaVersion":1,"schemaVersion":1', 1), encoding="utf-8")
        with self.assertRaises(policy.PolicyError):
            self.verify(fixture)

    def test_dispatch_coordinates_are_exact_and_bounded(self):
        policy.validate_inputs(coordinates())
        bad = {
            "repository": {"source_repository": "other/wagie"},
            "shell": {"tag": "v1.2.3'; touch /tmp/pwn; '"},
            "leading zero": {"source_run_id": "01"},
            "zero": {"source_artifact_id": "0"},
            "oversize run": {"source_run_id": str(policy.MAX_SAFE_INTEGER + 1)},
            "oversize artifact": {"source_artifact_id": str(policy.MAX_SAFE_INTEGER + 1)},
            "uppercase SHA": {"source_sha": "A" * 40},
            "prefixed digest": {"source_artifact_digest": "sha256:" + SOURCE_DIGEST},
            "same artifact": {"container_artifact_id": SOURCE_ARTIFACT_ID},
            "container zero": {"container_artifact_id": "0"},
            "container digest": {"container_artifact_digest": "C" * 64},
            "prerelease": {"tag": "v1.2.3-rc.1"},
        }
        for name, change in bad.items():
            with self.subTest(name=name), self.assertRaises(policy.PolicyError):
                policy.validate_inputs(coordinates(**change))

    def test_source_run_and_artifact_are_live_and_exact(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        run = {
            "id": int(SOURCE_RUN_ID),
            "run_attempt": 1,
            "event": "push",
            "status": "in_progress",
            "conclusion": None,
            "head_sha": SOURCE_SHA,
            "head_branch": TAG,
            "path": policy.SOURCE_WORKFLOW,
            "repository": {"id": 99, "full_name": policy.SOURCE_REPOSITORY},
            "head_repository": {"id": 99, "full_name": policy.SOURCE_REPOSITORY},
        }
        jobs = [
            {
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "run_id": int(SOURCE_RUN_ID),
                "run_attempt": 1,
                "started_at": "2026-09-01T00:00:00Z",
                "completed_at": "2026-09-01T00:10:00Z",
            }
            for name in sorted(policy.SOURCE_SUCCESS_JOBS)
        ]
        jobs.append(
            {
                "name": "dispatch_distribution",
                "status": "in_progress",
                "conclusion": None,
                "run_id": int(SOURCE_RUN_ID),
                "run_attempt": 1,
            }
        )
        values = {
            "run": run,
            "jobs": {"total_count": len(jobs), "jobs": jobs},
            "artifact": {
                "id": int(SOURCE_ARTIFACT_ID),
                "name": "distribution-release",
                "expired": False,
                "digest": "sha256:" + SOURCE_DIGEST,
                "workflow_run": {
                    "id": int(SOURCE_RUN_ID),
                    "head_sha": SOURCE_SHA,
                    "repository_id": 99,
                    "head_repository_id": 99,
                },
                "created_at": "2026-09-01T00:08:00Z",
                "updated_at": "2026-09-01T00:09:00Z",
            },
            "tag_commit": {"sha": SOURCE_SHA},
        }

        values["container_artifact"] = copy.deepcopy(values["artifact"])
        values["container_artifact"].update(id=int(CONTAINER_ARTIFACT_ID), name="container-release", digest="sha256:" + CONTAINER_DIGEST)

        def attempt(changes=None):
            candidate = copy.deepcopy(values)
            if changes is not None:
                changes(candidate)
            paths = {}
            for key, value in candidate.items():
                paths[key] = base / f"{key}.json"
                json_write(paths[key], value)
            args = coordinates(
                run=str(paths["run"]),
                jobs=str(paths["jobs"]),
                artifact=str(paths["artifact"]),
                container_artifact=str(paths["container_artifact"]),
                tag_commit=str(paths["tag_commit"]),
            )
            policy.validate_source(args)

        attempt()

        mutations = {
            "completed replay": lambda v: v["run"].update(status="completed", conclusion="success"),
            "wrong workflow": lambda v: v["run"].update(path=".github/workflows/other.yml"),
            "wrong tag": lambda v: v["run"].update(head_branch="main"),
            "wrong source attempt": lambda v: v["run"].update(run_attempt=2),
            "missing gate": lambda v: v["jobs"]["jobs"].pop(0),
            "failed gate": lambda v: v["jobs"]["jobs"][0].update(conclusion="failure"),
            "wrong gate attempt": lambda v: v["jobs"]["jobs"][0].update(run_attempt=2),
            "dispatch complete": lambda v: v["jobs"]["jobs"][-1].update(status="completed", conclusion="success"),
            "wrong dispatch attempt": lambda v: v["jobs"]["jobs"][-1].update(run_attempt=2),
            "artifact digest": lambda v: v["artifact"].update(digest="sha256:" + "f" * 64),
            "artifact boolean ID": lambda v: v["artifact"].update(id=True),
            "artifact expired scalar": lambda v: v["artifact"].update(expired=0),
            "older attempt artifact": lambda v: v["artifact"].update(created_at="2026-08-31T23:59:00Z", updated_at="2026-08-31T23:59:30Z"),
            "artifact after seal": lambda v: v["artifact"].update(created_at="2026-09-01T00:11:00Z", updated_at="2026-09-01T00:12:00Z"),
            "wrong container name": lambda v: v["container_artifact"].update(name="distribution-release"),
            "wrong container digest": lambda v: v["container_artifact"].update(digest="sha256:" + "f" * 64),
            "wrong container run": lambda v: v["container_artifact"]["workflow_run"].update(id=999),
            "wrong container SHA": lambda v: v["container_artifact"]["workflow_run"].update(head_sha="f" * 40),
            "old container attempt": lambda v: v["container_artifact"].update(created_at="2026-08-31T23:59:00Z", updated_at="2026-08-31T23:59:30Z"),
            "failed container build": lambda v: next(j for j in v["jobs"]["jobs"] if j["name"] == "container_build").update(conclusion="failure"),
            "failed container seal": lambda v: next(j for j in v["jobs"]["jobs"] if j["name"] == "seal_containers").update(conclusion="failure"),
            "tag moved": lambda v: v["tag_commit"].update(sha="f" * 40),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), self.assertRaises(policy.PolicyError):
                attempt(mutation)

    def test_attestation_checksums_cover_the_exact_final_assets(self):
        fixture = self.fixture()
        output = Path(tempfile.mkdtemp()) / "subjects.sha256"
        self.addCleanup(lambda: output.parent.rmdir() if output.parent.exists() else None)
        policy.write_checksums(fixture.root, output)
        entries = output.read_text(encoding="ascii").splitlines()
        self.assertEqual(35, len(entries))
        self.assertEqual(sorted(entries, key=lambda line: line[66:]), entries)
        with self.assertRaises(policy.PolicyError):
            policy.write_checksums(fixture.root, output)
        output.unlink()

    def test_release_readback_is_exact_for_draft_and_published(self):
        fixture = self.fixture()
        for phase in ("draft", "published"):
            with self.subTest(phase=phase):
                response = fixture.release_api(phase)
                path = fixture.root / f"{phase}.json"
                json_write(path, response)
                policy.verify_release_readback(path, fixture.root, TAG, 77, phase, "e" * 40)

    def test_release_readback_rejects_scalar_and_asset_drift(self):
        mutations = {
            "boolean release ID": lambda v: v.update(id=True),
            "numeric immutable": lambda v: v.update(immutable=1),
            "wrong tag": lambda v: v.update(tag_name="v1.2.4"),
            "wrong destination commit": lambda v: v.update(target_commitish="f" * 40),
            "invalid publication time": lambda v: v.update(published_at=""),
            "mutable publication": lambda v: v.update(immutable=False),
            "missing asset": lambda v: v["assets"].pop(),
            "duplicate asset": lambda v: v["assets"].append(copy.deepcopy(v["assets"][0])),
            "wrong digest": lambda v: v["assets"][0].update(digest="sha256:" + "f" * 64),
            "boolean asset ID": lambda v: v["assets"][0].update(id=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                fixture = self.fixture()
                response = fixture.release_api("published")
                mutate(response)
                path = fixture.root / "readback.json"
                json_write(path, response)
                with self.assertRaises(policy.PolicyError):
                    policy.verify_release_readback(path, fixture.root, TAG, 77, "published", "e" * 40)

    def test_exact_release_upload_response_is_digest_bound(self):
        fixture = self.fixture()
        name = "install.sh"
        asset_hash, asset_size = hashed(fixture.assets / name)
        response = {
            "id": 91,
            "name": name,
            "state": "uploaded",
            "size": asset_size,
            "digest": "sha256:" + asset_hash,
        }
        self.assertEqual(
            response,
            upload_asset.validate_response(response, 77, name, asset_hash, asset_size),
        )
        for field, value in (
            ("id", True),
            ("name", "other"),
            ("state", "new"),
            ("size", asset_size + 1),
            ("digest", "sha256:" + "f" * 64),
        ):
            with self.subTest(field=field), self.assertRaises(policy.PolicyError):
                candidate = dict(response)
                candidate[field] = value
                upload_asset.validate_response(candidate, 77, name, asset_hash, asset_size)

    def test_upload_streams_the_descriptor_that_was_hashed(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        asset = Path(temporary.name) / "asset.bin"
        original = b"descriptor-held-release-bytes"
        replacement = b"substituted-path-bytes"
        asset.write_bytes(original)
        expected_hash = hashlib.sha256(original).hexdigest()

        class Response:
            status = 201

            def read(self, _maximum):
                return json.dumps(
                    {
                        "id": 7,
                        "name": "asset.bin",
                        "state": "uploaded",
                        "size": len(original),
                        "digest": "sha256:" + expected_hash,
                    }
                ).encode()

        class Connection:
            def __init__(self, *_args, **_kwargs):
                self.sent = bytearray()

            def putrequest(self, _method, _endpoint):
                pass

            def putheader(self, _name, _value):
                pass

            def endheaders(self):
                moved = asset.with_suffix(".held")
                asset.rename(moved)
                asset.write_bytes(replacement)

            def send(self, chunk):
                self.sent.extend(chunk)

            def getresponse(self):
                return Response()

            def close(self):
                pass

        holder = {}

        def factory(*args, **kwargs):
            holder["connection"] = Connection(*args, **kwargs)
            return holder["connection"]

        result = upload_asset.upload(77, asset, "asset.bin", "token", factory)
        self.assertEqual(original, bytes(holder["connection"].sent))
        self.assertEqual("sha256:" + expected_hash, result["digest"])
        self.assertEqual(replacement, asset.read_bytes())

    def test_upload_rejects_in_place_mutation_after_authentication(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        asset = Path(temporary.name) / "asset.bin"
        original = b"authenticated bytes"
        for mutated in (b"x" * len(original), original + b"growth", b"short"):
            with self.subTest(mutated=mutated):
                asset.write_bytes(original)
                class Connection:
                    def __init__(self, *_args, **_kwargs):
                        self.sent = bytearray()
                        self.closed = False

                    def putrequest(self, _method, _endpoint):
                        pass

                    def putheader(self, _name, _value):
                        pass

                    def endheaders(self):
                        asset.write_bytes(mutated)

                    def send(self, chunk):
                        self.sent.extend(chunk)

                    def getresponse(self):
                        raise AssertionError("changed upload cannot be accepted")

                    def close(self):
                        self.closed = True

                connection = Connection()
                with self.assertRaisesRegex(policy.PolicyError, "after authentication"):
                    upload_asset.upload(77, asset, "asset.bin", "token", lambda *_args, **_kwargs: connection)
                self.assertTrue(connection.closed)
                self.assertLessEqual(len(connection.sent), len(original))

    def test_one_byte_upload_and_readback_reject_boolean_size(self):
        digest = hashlib.sha256(b"x").hexdigest()
        value = {"id": 1, "name": "install.sh", "state": "uploaded", "size": True, "digest": "sha256:" + digest}
        with self.assertRaisesRegex(policy.PolicyError, "not an integer"):
            upload_asset.validate_response(value, 77, "install.sh", digest, 1)
        fixture = self.fixture()
        (fixture.assets / "install.sh").write_bytes(b"x")
        response = fixture.release_api("published")
        next(asset for asset in response["assets"] if asset["name"] == "install.sh")["size"] = True
        path = fixture.root / "readback.json"
        json_write(path, response)
        with self.assertRaisesRegex(policy.PolicyError, "not an integer"):
            policy.verify_release_readback(path, fixture.root, TAG, 77, "published", "e" * 40)

    def test_publish_transaction_uses_exact_object_authority(self):
        fixture = self.fixture()
        state = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: self.remove_tree(state))
        result = self.run_publisher(fixture, state, "success")
        self.assertEqual(0, result.returncode, result.stderr)
        uploads = (state / "uploads.log").read_text(encoding="utf-8").splitlines()
        expected_names = sorted(policy.final_asset_names(VERSION))
        self.assertEqual([f"77\t{name}" for name in expected_names] + [f"77\tcontainers_{VERSION}.tar.gz"], uploads)
        calls = (state / "calls.log").read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            [
                "GET\trepos/wagiedev/distribution/commits/master",
                "GET\trepos/wagiedev/distribution/releases?per_page=100",
                f"GET\trepos/wagiedev/distribution/git/ref/tags/{TAG}",
                "POST\trepos/wagiedev/distribution/git/refs",
                "POST\trepos/wagiedev/distribution/releases",
                "GET\trepos/wagiedev/distribution/releases/77",
                f"GET\trepos/wagiedev/distribution/git/ref/tags/{TAG}",
                "PATCH\trepos/wagiedev/distribution/releases/77",
                "GET\trepos/wagiedev/distribution/releases/77",
                f"GET\trepos/wagiedev/distribution/git/ref/tags/{TAG}",
            ],
            calls,
        )

    def test_publish_refuses_preexisting_and_unproven_absence_before_mutation(self):
        for scenario in ("preexisting", "absence-error", "malformed-list"):
            with self.subTest(scenario=scenario):
                fixture = self.fixture()
                state = Path(tempfile.mkdtemp())
                self.addCleanup(lambda state=state: self.remove_tree(state))
                result = self.run_publisher(fixture, state, scenario)
                self.assertNotEqual(0, result.returncode)
                calls = (state / "calls.log").read_text(encoding="utf-8").splitlines()
                self.assertEqual(
                    [
                        "GET\trepos/wagiedev/distribution/commits/master",
                        "GET\trepos/wagiedev/distribution/releases?per_page=100",
                    ],
                    calls,
                )
                self.assertFalse((state / "tag-created").exists())
                self.assertFalse((state / "release-created").exists())
                self.assertFalse((state / "uploads.log").exists())

    def run_publisher(self, fixture, state, scenario):
        container_evidence = state / f"containers_{VERSION}.tar.gz"
        container_evidence.write_bytes(b"verified-container-evidence")
        fake_bin = state / "bin"
        fake_bin.mkdir()
        (fake_bin / "gh").symlink_to(ROOT / "tests" / "fakes" / "gh")
        python_wrapper = fake_bin / "python3"
        python_wrapper.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ $1 == scripts/upload_asset.py ]]; then\n"
            "  shift\n"
            "  exec \"$REAL_PYTHON\" \"$FAKE_UPLOAD\" \"$@\"\n"
            "fi\n"
            "exec \"$REAL_PYTHON\" \"$@\"\n",
            encoding="utf-8",
        )
        python_wrapper.chmod(0o755)
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": str(fake_bin) + os.pathsep + environment["PATH"],
                "REAL_PYTHON": sys.executable,
                "FAKE_UPLOAD": str(ROOT / "tests" / "fakes" / "upload_asset.py"),
                "FAKE_GH_STATE": str(state),
                "FAKE_GH_SCENARIO": scenario,
                "FAKE_TRANSFER_ROOT": str(fixture.root),
                "GH_TOKEN": "test-token",
                "TAG": TAG,
                "SOURCE_REPOSITORY": policy.SOURCE_REPOSITORY,
                "SOURCE_RUN_ID": SOURCE_RUN_ID,
                "SOURCE_SHA": SOURCE_SHA,
                "SOURCE_ARTIFACT_ID": SOURCE_ARTIFACT_ID,
                "SOURCE_ARTIFACT_DIGEST": SOURCE_DIGEST,
                "CONTAINER_ARTIFACT_ID": CONTAINER_ARTIFACT_ID,
                "CONTAINER_ARTIFACT_DIGEST": CONTAINER_DIGEST,
                "FAKE_CONTAINER_EVIDENCE": str(container_evidence),
                "GITHUB_SHA": "e" * 40,
                "GITHUB_REPOSITORY": policy.DESTINATION_REPOSITORY,
            }
        )
        return subprocess.run(
            ["bash", "scripts/publish.sh", str(fixture.root), str(container_evidence)],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )

    @staticmethod
    def remove_tree(path):
        for child in sorted(path.rglob("*"), reverse=True):
            if child.is_symlink() or child.is_file():
                child.unlink()
            else:
                child.rmdir()
        path.rmdir()

    @staticmethod
    def mutate_json(path, mutation):
        value = json.loads(path.read_text(encoding="utf-8"))
        mutation(value)
        json_write(path, value)

    @staticmethod
    def replace_first_digest(path):
        raw = path.read_text(encoding="ascii")
        path.write_text("f" * 64 + raw[64:], encoding="ascii")

    @staticmethod
    def replace_with_symlink(path):
        target = path.parent / "target"
        target.write_bytes(b"target")
        path.unlink()
        path.symlink_to(target)


if __name__ == "__main__":
    unittest.main()
