"""Publication authority, fail-closed preflight and exact registry-byte readback."""

import copy
import gzip
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import publish_images as publisher
import oci_policy
from release_policy import PolicyError
from test_oci_policy import Fixture, SOURCE_EPOCH, SOURCE_SHA, VERSION


PAT = "dckr_pat_test-only-never-live"


class HubFixture(publisher.DockerHub):
    """Hub API transport fixture. All registry manifest bodies are real OCI bytes."""

    def __init__(self, fixture):
        super().__init__(PAT)
        self.fixture = fixture
        self.calls, self.copies = [], []
        self.published, self.manifests = {}, {}
        self.failure = None
        self.readback_mutation = None

    def request(self, host, method, path, headers=None, body=None):
        self.calls.append((host, method, path))
        if self.failure:
            response = self.failure(host, method, path)
            if response is not None:
                return response
        if host == "hub.docker.com" and path == "/v2/auth/token":
            assert method == "POST"
            assert json.loads(body) == {"identifier": "wagiedev", "secret": PAT}
            return 200, {}, b'{"access_token":"hub-token"}'
        if host == "hub.docker.com":
            assert headers["Authorization"] == "Bearer hub-token"
            repository = path.rsplit("/", 1)[-1]
            assert repository in publisher.REPOSITORIES
            return 200, {}, json.dumps({"name": repository, "namespace": "wagiedev", "is_private": False,
                "immutable_tags_settings": {"enabled": True, "rules": [publisher.IMMUTABLE_RULE]}}).encode()
        if host == "auth.docker.io":
            assert method == "GET" and headers["Authorization"].startswith("Basic ")
            return 200, {}, b'{"token":"registry-token"}'
        assert host == "registry-1.docker.io" and method == "GET"
        assert headers["Authorization"] == "Bearer registry-token"
        assert headers["Accept"] == publisher.ACCEPT
        _, _, _, repository, _, reference = path.split("/")
        raw = self.published.get((repository, reference), self.manifests.get((repository, reference)))
        if raw is None:
            return 404, {}, b'{"errors":[{"code":"MANIFEST_UNKNOWN","message":"missing"}]}'
        result = 200, {"docker-content-digest": "sha256:" + hashlib.sha256(raw).hexdigest()}, raw
        return self.readback_mutation(result, reference) if self.readback_mutation else result

    def copy_image(self, layout, destination, digest):
        self.copies.append(destination)
        repository, tag = destination.removeprefix("docker.io/wagiedev/").split(":")
        for blob in (layout / "blobs" / "sha256").iterdir():
            self.manifests[(repository, "sha256:" + blob.name)] = blob.read_bytes()
        self.published[(repository, tag)] = self.manifests[(repository, digest)]


class PublicationTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture = Fixture(Path(temporary.name))
        return fixture, HubFixture(fixture)

    def test_exact_four_destinations_preserve_every_index_and_platform_digest(self):
        fixture, hub = self.fixture()
        publisher.promote(fixture.root, fixture.expected, hub, hub.copy_image)
        self.assertEqual([
            "docker.io/wagiedev/wagied:1.2.3", "docker.io/wagiedev/wagied-headquarters:1.2.3",
            "docker.io/wagiedev/wagied-runner:1.2.3", "docker.io/wagiedev/wagied-runner:1.2.3-toolchains",
        ], hub.copies)
        for image in fixture.expected["images"]:
            repository = image["repository"].split("/")[-1]
            self.assertEqual(image["indexDigest"], "sha256:" + hashlib.sha256(hub.published[(repository, image["tag"])]).hexdigest())
            for platform in image["platforms"]:
                self.assertIn(("registry-1.docker.io", "GET", f"/v2/wagiedev/{repository}/manifests/{platform['manifestDigest']}"), hub.calls)

    def test_last_destination_preexisting_or_uncertain_means_zero_writes(self):
        for status, raw in ((200, b"existing"), (401, b"unauthorized"), (403, b"forbidden"),
                            (429, b"rate limited"), (500, b"failure"), (302, b"redirect"),
                            (404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}'),
                            (404, b'{"errors":[]}'), (404, b'{}')):
            with self.subTest(status=status, raw=raw):
                fixture, hub = self.fixture()
                hub.failure = lambda host, method, path: (status, {}, raw) if path.endswith("/manifests/1.2.3-toolchains") else None
                with self.assertRaises(PolicyError):
                    publisher.promote(fixture.root, fixture.expected, hub, hub.copy_image)
                self.assertEqual([], hub.copies)

    def test_immutable_policy_private_repository_or_unknown_shape_means_zero_writes(self):
        valid = {"name": "wagied-runner", "namespace": "wagiedev", "is_private": False,
                 "immutable_tags_settings": {"enabled": True, "rules": [publisher.IMMUTABLE_RULE]}}
        for change in ({"namespace": "attacker"}, {"is_private": True}, {"is_private": 0},
                       {"immutable_tags_settings": {"enabled": False, "rules": [publisher.IMMUTABLE_RULE]}},
                       {"immutable_tags_settings": {"enabled": 1, "rules": [publisher.IMMUTABLE_RULE]}},
                       {"immutable_tags_settings": {"enabled": True, "rules": []}},
                       {"immutable_tags_settings": {"enabled": True, "rules": [".*"]}},
                       {"immutable_tags_settings": None}):
            with self.subTest(change=change):
                fixture, hub = self.fixture()
                response = {**valid, **change}
                hub.failure = lambda host, method, path: (200, {}, json.dumps(response).encode()) if host == "hub.docker.com" and path.endswith("/wagied-runner") else None
                with self.assertRaises(PolicyError):
                    publisher.promote(fixture.root, fixture.expected, hub, hub.copy_image)
                self.assertEqual([], hub.copies)

    def test_replay_never_adopts_existing_tags(self):
        fixture, hub = self.fixture()
        publisher.promote(fixture.root, fixture.expected, hub, hub.copy_image)
        hub.copies.clear()
        with self.assertRaises(PolicyError):
            publisher.promote(fixture.root, fixture.expected, hub, hub.copy_image)
        self.assertEqual([], hub.copies)

    def test_readback_body_header_child_and_status_drift_stop_before_next_image(self):
        mutations = (
            lambda status, headers, raw: (status, headers, raw + b" "),
            lambda status, headers, raw: (status, {"docker-content-digest": "sha256:" + "f" * 64}, raw),
            lambda status, headers, raw: (status, {}, raw),
            lambda status, headers, raw: (503, headers, raw),
        )
        for child_only in (False, True):
            for mutation in mutations:
                with self.subTest(child_only=child_only, mutation=mutation):
                    fixture, hub = self.fixture()
                    child = fixture.expected["images"][0]["platforms"][0]["manifestDigest"]
                    hub.readback_mutation = lambda response, reference: mutation(*response) if not child_only or reference == child else response
                    with self.assertRaises(PolicyError):
                        publisher.promote(fixture.root, fixture.expected, hub, hub.copy_image)
                    self.assertEqual(1, len(hub.copies))

    def test_network_destination_cannot_be_selected_by_manifest(self):
        for key, value in (("repository", "docker.io/attacker/wagied"), ("tag", "latest"),
                           ("layout", "../../code"), ("variant", "unexpected")):
            with self.subTest(key=key):
                fixture, hub = self.fixture()
                manifest = copy.deepcopy(fixture.expected)
                manifest["images"][0][key] = value
                with self.assertRaises(PolicyError):
                    publisher.promote(fixture.root, manifest, hub, hub.copy_image)
                self.assertEqual([], hub.calls)

    def test_pat_is_required_and_skopeo_uses_ephemeral_auth_without_child_secret_env(self):
        for value in ("", "password", "dckr_oat_token", "dckr_pat_a\nsecret"):
            with self.assertRaises(PolicyError):
                publisher.DockerHub(value)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {"DOCKERHUB_TOKEN": PAT}):
            def run(command, **kwargs):
                self.assertEqual("/usr/bin/skopeo", command[0])
                self.assertIn("--all", command)
                self.assertIn("--preserve-digests", command)
                self.assertNotIn(PAT, " ".join(command))
                self.assertNotIn("DOCKERHUB_TOKEN", kwargs["env"])
                auth = Path(command[command.index("--dest-authfile") + 1])
                self.assertEqual(0o600, auth.stat().st_mode & 0o777)
                Path(command[command.index("--digestfile") + 1]).write_text("sha256:" + "a" * 64)
            with mock.patch.object(publisher.subprocess, "run", side_effect=run):
                publisher.skopeo_publisher(PAT, temporary)(Path("/verified/layout"), "docker.io/wagiedev/wagied:1.2.3", "sha256:" + "a" * 64)

    def test_evidence_archive_roundtrip_and_unsafe_members(self):
        fixture, _ = self.fixture()
        (fixture.root / "images.json.sigstore.json").write_text('{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{},"messageSignature":{}}')
        public = fixture.root.parent / "public"
        oci_policy.export_evidence(fixture.root, public, VERSION, SOURCE_SHA, SOURCE_EPOCH, fixture.inputs)
        archive = fixture.root.parent / "containers_1.2.3.tar.gz"
        publisher.archive_evidence(public, archive)
        unpacked = fixture.root.parent / "unpacked"
        publisher.unpack_evidence(archive, unpacked)
        oci_policy.verify_evidence(unpacked, VERSION, SOURCE_SHA, SOURCE_EPOCH, fixture.inputs)
        self.assertFalse((unpacked / "images").exists())
        self.assertEqual(19, len(list(p for p in unpacked.rglob("*") if p.is_file())))
        for name, kind, mode in (("../escape", tarfile.REGTYPE, 0o644), ("/absolute", tarfile.REGTYPE, 0o644),
                                 ("link", tarfile.SYMTYPE, 0o644), ("device", tarfile.CHRTYPE, 0o644),
                                 ("executable", tarfile.REGTYPE, 0o755)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                path = root / "unsafe.tar.gz"
                with tarfile.open(path, "w:gz") as tar:
                    member = tarfile.TarInfo(name)
                    member.size, member.mode, member.type = 1, mode, kind
                    tar.addfile(member, io.BytesIO(b"x"))
                with self.assertRaises(PolicyError):
                    publisher.unpack_evidence(path, root / "output")

    def test_evidence_archive_roundtrips_combined_files_above_compressed_limit(self):
        # The compressed archive and each individual SBOM fit, but their combined
        # expanded bytes exceed the compressed limit (as in the v0.0.33 release).
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(publisher, "MAX_ARCHIVE", 1024), \
                mock.patch.object(oci_policy, "MAX_EVIDENCE", 512):
            root = Path(temporary)
            public = root / "public"
            public.mkdir()
            expected = {f"sbom-{index}.json": bytes([65 + index]) * 400 for index in range(3)}
            for name, raw in expected.items():
                (public / name).write_bytes(raw)
            archive = root / "containers.tar.gz"
            publisher.archive_evidence(public, archive)
            self.assertLess(archive.stat().st_size, 1024)
            unpacked = root / "unpacked"
            publisher.unpack_evidence(archive, unpacked)
            self.assertEqual(expected, {path.name: path.read_bytes() for path in unpacked.iterdir()})

    def test_evidence_archive_rejects_oversized_or_too_many_members_on_both_sides(self):
        for label, sizes in (("oversized", [513]), ("too many", [1] * 20)):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary, \
                    mock.patch.object(oci_policy, "MAX_EVIDENCE", 512):
                root = Path(temporary)
                public = root / "public"
                public.mkdir()
                archive = root / "untrusted.tar.gz"
                with tarfile.open(archive, "w:gz") as tar:
                    for index, size in enumerate(sizes):
                        name, raw = f"member-{index}", b"x" * size
                        (public / name).write_bytes(raw)
                        member = tarfile.TarInfo(name)
                        member.size, member.mode = size, 0o644
                        tar.addfile(member, io.BytesIO(raw))
                with self.assertRaises(PolicyError):
                    publisher.archive_evidence(public, root / "produced.tar.gz")
                with self.assertRaises(PolicyError):
                    publisher.unpack_evidence(archive, root / "unpacked")


@unittest.skipUnless(os.environ.get("WAGIE_TEST_REGISTRY") == "1", "run make test-registry for real Skopeo/registry coverage")
class RegistryIntegrationTests(unittest.TestCase):
    def test_real_multiarch_copy_and_digest_readback(self):
        skopeo = os.environ.get("WAGIE_TEST_SKOPEO") or shutil.which("skopeo")
        if not skopeo:
            self.fail("Skopeo is required by make test-registry")
        # Loopback-only registry, disposable storage and no host Docker credentials.
        registry_image = os.environ.get("WAGIE_TEST_REGISTRY_IMAGE", "registry:2.8.3")
        run = subprocess.run(["docker", "run", "--detach", "--rm", "--publish", "127.0.0.1::5000", registry_image],
                             check=True, text=True, capture_output=True)
        container = run.stdout.strip()
        self.addCleanup(lambda: subprocess.run(["docker", "rm", "--force", container], check=True, capture_output=True))
        port = subprocess.check_output(["docker", "port", container, "5000/tcp"], text=True).strip().rsplit(":", 1)[1]
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            hub = HubFixture(fixture)
            original_request = hub.request

            def request(host, method, path, headers=None, body=None):
                if host != "registry-1.docker.io":
                    return original_request(host, method, path, headers, body)
                connection = http.client.HTTPConnection("127.0.0.1", int(port), timeout=30)
                try:
                    connection.request(method, path, headers={"Accept": publisher.ACCEPT})
                    response = connection.getresponse()
                    raw = response.read()
                    # A fresh Distribution registry reports NAME_UNKNOWN until the first blob upload.
                    if response.status == 404:
                        raw = b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}'
                    return response.status, {k.lower(): v for k, v in response.getheaders()}, raw
                finally:
                    connection.close()

            hub.request = request
            real_run = subprocess.run

            def registry_copy(command, **kwargs):
                command = list(command)
                self.assertEqual("/usr/bin/skopeo", command[0])
                command[0] = skopeo
                destination = command[-1]
                self.assertTrue(destination.startswith("docker://docker.io/wagiedev/"))
                command[-1] = destination.replace("docker://docker.io/", f"docker://127.0.0.1:{port}/")
                command.insert(-2, "--dest-tls-verify=false")
                return real_run(command, **kwargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            with tempfile.TemporaryDirectory() as credentials, mock.patch.object(publisher.subprocess, "run", side_effect=registry_copy):
                publisher.promote(fixture.root, fixture.expected, hub, publisher.skopeo_publisher(PAT, credentials))
            with self.assertRaises(PolicyError):
                publisher.promote(fixture.root, fixture.expected, hub, lambda *_args: self.fail("replay wrote an image"))


if __name__ == "__main__":
    unittest.main()
