"""Real OCI graph fixtures prove the transfer's closed catalog and byte binding."""

import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
POLICY_PATH = HERE / "oci-policy.py"
if not POLICY_PATH.exists():
    POLICY_PATH = HERE.parent / "scripts" / "oci_policy.py"
spec = importlib.util.spec_from_file_location("oci_policy_test_subject", POLICY_PATH)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

VERSION = "1.2.3"
SOURCE_SHA = "a" * 40
SOURCE_EPOCH = 1_700_000_000
VARIANTS = ("wagied", "wagied-headquarters", "wagied-runner", "wagied-runner-toolchains")
ARCHITECTURES = ("amd64", "arm64")
INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_json(path, value):
    path.write_bytes(encoded(value))


def checksum(raw):
    return hashlib.sha256(raw).hexdigest()


class Fixture:
    def __init__(self, directory, mutation=None):
        self.root = directory / "transfer"
        self.root.mkdir()
        self.inputs = directory / "trusted-inputs.env"
        self.inputs.write_bytes(b"SCHEMA_VERSION=1\nBASE_IMAGE=alpine@sha256:" + b"1" * 64 + b"\n")
        self.mutation = mutation or (lambda _kind, _value: None)
        self.expected = {
            "schema": "wagie.images/v1", "version": VERSION,
            "sourceRepository": "Savid/wagie", "sourceSHA": SOURCE_SHA,
            "sourceEpoch": SOURCE_EPOCH, "inputsSHA256": checksum(self.inputs.read_bytes()),
            "images": [self.image(variant) for variant in VARIANTS],
        }
        write_json(self.root / "images.json", self.expected)

    def mutate(self, kind, value, variant="wagied", architecture="amd64"):
        if variant == "wagied" and architecture == "amd64":
            self.mutation(kind, value)

    def blob(self, layout, value, media):
        raw = value if isinstance(value, bytes) else encoded(value)
        digest = checksum(raw)
        (layout / "blobs" / "sha256" / digest).write_bytes(raw)
        return {"mediaType": media, "digest": "sha256:" + digest, "size": len(raw)}

    def record(self, path, value):
        write_json(self.root / path, value)
        raw = (self.root / path).read_bytes()
        return {"path": path, "sha256": checksum(raw), "size": len(raw)}

    def image(self, variant):
        layout = self.root / "images" / variant
        (layout / "blobs" / "sha256").mkdir(parents=True)
        evidence = self.root / "evidence" / variant
        evidence.mkdir(parents=True)
        write_json(layout / "oci-layout", {"imageLayoutVersion": "1.0.0"})
        children, platforms = [], []
        for architecture in ARCHITECTURES:
            contents = f"fixture for {variant} {architecture}".encode()
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                member = tarfile.TarInfo("usr/local/bin/wagied")
                member.size = len(contents)
                member.mode = 0o755
                tar.addfile(member, io.BytesIO(contents))
            unpacked = archive.getvalue()
            layer = self.blob(layout, gzip.compress(unpacked, mtime=0), LAYER)
            config = {
                "created": "2023-11-14T22:13:20Z", "architecture": architecture, "os": "linux",
                "config": {"User": "wagie", "Entrypoint": ["/usr/local/bin/wagied"], "Labels": {
                    "org.opencontainers.image.version": VERSION,
                    "org.opencontainers.image.revision": SOURCE_SHA,
                    "org.opencontainers.image.source": "https://github.com/Savid/wagie",
                }},
                "rootfs": {"type": "layers", "diff_ids": ["sha256:" + checksum(unpacked)]},
                "history": [{"created": "2023-11-14T22:13:20Z", "created_by": "fixture"}],
            }
            self.mutate("config", config, variant, architecture)
            config_descriptor = self.blob(layout, config, CONFIG)
            manifest = {"schemaVersion": 2, "mediaType": MANIFEST, "config": config_descriptor, "layers": [layer]}
            self.mutate("manifest", manifest, variant, architecture)
            descriptor = self.blob(layout, manifest, MANIFEST)
            descriptor["platform"] = {"os": "linux", "architecture": architecture}
            self.mutate("child", descriptor, variant, architecture)
            children.append(descriptor)
            required_checks = ["binary-identity", "entrypoint-sanitizes-gotraceback", "nonroot-runtime", "data-directory-persistence", "role-command-boundary"]
            if variant != "wagied-headquarters":
                required_checks.extend(["runner-ordinary-boot", "runner-root-refused", "agent-pool-isolation", "harness-versions"])
            if variant in {"wagied", "wagied-runner-toolchains"}:
                required_checks.append("toolchain-versions")
            if variant == "wagied-headquarters":
                required_checks.append("headquarters-runtime-dependencies")
            test = {
                "schema": "wagie.image-test/v1", "version": VERSION, "sourceSHA": SOURCE_SHA,
                "sourceEpoch": SOURCE_EPOCH, "variant": variant, "platform": "linux/" + architecture,
                "manifestDigest": descriptor["digest"], "configDigest": config_descriptor["digest"],
                "binarySHA256": checksum(contents), "checks": required_checks, "result": "passed",
                "buildIdentity": {"schema": "wagie.build-identity/v1", "profile": "release/" + ("wagied-runner" if variant == "wagied-runner-toolchains" else variant), "version": VERSION, "commit": SOURCE_SHA, "sourceEpoch": SOURCE_EPOCH, "runnerProtocolVersion": 1},
            }
            spdx = {
                "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "dataLicense": "CC0-1.0",
                "name": variant, "documentNamespace": "https://example.invalid/spdx/" + descriptor["digest"][7:],
                "creationInfo": {"created": "2023-11-14T22:13:20Z", "creators": ["Tool: fixture"]},
                "documentDescribes": ["SPDXRef-Image"],
                "packages": [{"SPDXID": "SPDXRef-Image", "name": variant, "downloadLocation": "NOASSERTION", "checksums": [{"algorithm": "SHA256", "checksumValue": descriptor["digest"][7:]}]}],
            }
            self.mutate("test", test, variant, architecture)
            self.mutate("spdx", spdx, variant, architecture)
            prefix = f"evidence/{variant}/{architecture}"
            platforms.append({
                "platform": "linux/" + architecture, "manifestDigest": descriptor["digest"],
                "manifestSize": descriptor["size"], "configDigest": config_descriptor["digest"],
                "sbom": self.record(prefix + ".spdx.json", spdx), "test": self.record(prefix + ".test.json", test),
            })
        index = {"schemaVersion": 2, "mediaType": INDEX, "manifests": children}
        self.mutate("index", index, variant)
        descriptor = self.blob(layout, index, INDEX)
        outer = {"schemaVersion": 2, "mediaType": INDEX, "manifests": [descriptor]}
        self.mutate("outer", outer, variant)
        write_json(layout / "index.json", outer)
        return {
            "variant": variant, "repository": "docker.io/wagiedev/" + ("wagied-runner" if variant == "wagied-runner-toolchains" else variant),
            "tag": VERSION + ("-toolchains" if variant == "wagied-runner-toolchains" else ""),
            "layout": "images/" + variant, "indexDigest": descriptor["digest"], "indexSize": descriptor["size"], "platforms": platforms,
        }

    def verify(self, **options):
        return policy.verify_transfer(self.root, VERSION, SOURCE_SHA, SOURCE_EPOCH, self.inputs, **options)


class OCIPolicyTests(unittest.TestCase):
    def fixture(self, mutation=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Fixture(Path(temporary.name), mutation)

    def test_accepts_exact_real_oci_graph_and_derives_manifest(self):
        fixture = self.fixture()
        self.assertEqual(fixture.expected, fixture.verify())
        self.assertEqual("docker.io/wagiedev/wagied-runner", fixture.expected["images"][3]["repository"])
        self.assertEqual("1.2.3-toolchains", fixture.expected["images"][3]["tag"])
        (fixture.root / "images.json").unlink()
        self.assertEqual(fixture.expected, fixture.verify(write=True))
        self.assertEqual(fixture.expected, json.loads((fixture.root / "images.json").read_bytes()))
        with self.assertRaisesRegex(policy.PolicyError, "refusing to overwrite"):
            fixture.verify(write=True)

    def test_graph_checks_reject_rehashed_structural_substitutions(self):
        cases = [
            ("wrong architecture", "config", lambda v: v.update(architecture="arm64"), "platform disagrees"),
            ("wrong OS", "config", lambda v: v.update(os="windows"), "platform disagrees"),
            ("wrong revision", "config", lambda v: v["config"]["Labels"].update({"org.opencontainers.image.revision": "b" * 40}), "release labels"),
            ("wrong epoch", "config", lambda v: v.update(created="2023-11-14T22:13:21Z"), "creation time"),
            ("missing diff ID", "config", lambda v: v["rootfs"].update(diff_ids=[]), "rootfs"),
            ("external layer", "manifest", lambda v: v["layers"][0].update(urls=["https://attacker.invalid/layer"]), "non-exact schema"),
            ("foreign layer", "manifest", lambda v: v["layers"][0].update(mediaType="application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"), "media type"),
            ("external config", "manifest", lambda v: v["config"].update(urls=["https://attacker.invalid/config"]), "non-exact schema"),
            ("descriptor traversal", "manifest", lambda v: v["config"].update(digest="sha256:../../secret"), "descriptor digest"),
            ("descriptor boolean size", "manifest", lambda v: v["config"].update(size=True), "bounded integer"),
            ("unknown descriptor property", "child", lambda v: v.update(data="hidden payload"), "non-exact schema"),
            ("wrong descriptor OS", "child", lambda v: v["platform"].update(os="windows"), "platform disagrees"),
            ("missing child", "index", lambda v: v["manifests"].pop(), "exactly two"),
            ("duplicate child", "index", lambda v: v["manifests"].__setitem__(1, copy.deepcopy(v["manifests"][0])), "platform disagrees"),
            ("attestation child", "index", lambda v: v["manifests"].append(copy.deepcopy(v["manifests"][0])), "exactly two"),
            ("nested index", "child", lambda v: v.update(mediaType=INDEX), "media type"),
            ("outer extra image", "outer", lambda v: v["manifests"].append(copy.deepcopy(v["manifests"][0])), "exactly one"),
        ]
        for label, kind, mutation, error in cases:
            with self.subTest(label=label):
                fixture = self.fixture(lambda current, value: mutation(value) if current == kind else None)
                with self.assertRaisesRegex(policy.PolicyError, error):
                    fixture.verify()

    def test_evidence_checks_reject_rehashed_claims_for_wrong_subject_or_release(self):
        cases = [
            ("failed smoke", "test", lambda v: v.update(result="failed"), "required checks"),
            ("missing smoke", "test", lambda v: v["checks"].pop(), "required checks"),
            ("different child", "test", lambda v: v.update(manifestDigest="sha256:" + "f" * 64), "subject"),
            ("different config", "test", lambda v: v.update(configDigest="sha256:" + "f" * 64), "subject"),
            ("different source", "test", lambda v: v.update(sourceSHA="f" * 40), "release"),
            ("wrong physical role", "test", lambda v: v["buildIdentity"].update(profile="release/wagied-headquarters"), "release role"),
            ("boolean protocol", "test", lambda v: v["buildIdentity"].update(runnerProtocolVersion=True), "bounded integer"),
            ("unsigned test extension", "test", lambda v: v.update(extra="ignored?"), "non-exact schema"),
            ("SBOM other child", "spdx", lambda v: v["packages"][0]["checksums"][0].update(checksumValue="f" * 64), "subject checksum"),
            ("SBOM no root", "spdx", lambda v: v.update(documentDescribes=[]), "exactly one"),
            ("SBOM duplicate root", "spdx", lambda v: v["packages"].append(copy.deepcopy(v["packages"][0])), "duplicate package"),
            ("SBOM ambiguous checksum", "spdx", lambda v: v["packages"][0]["checksums"].append({"algorithm": "SHA256", "checksumValue": "f" * 64}), "duplicate or invalid checksum"),
            ("SBOM no SPDX", "spdx", lambda v: v.update(spdxVersion="unknown"), "SPDX 2.3"),
        ]
        for label, kind, mutation, error in cases:
            with self.subTest(label=label):
                fixture = self.fixture(lambda current, value: mutation(value) if current == kind else None)
                with self.assertRaisesRegex(policy.PolicyError, error):
                    fixture.verify()

    def test_rejects_undeclared_bytes_missing_files_symlinks_and_special_files(self):
        cases = ("extra blob", "extra evidence", "extra directory", "missing evidence", "symlink blob", "symlink directory", "corrupt blob", "fifo")
        for label in cases:
            with self.subTest(label=label):
                fixture = self.fixture()
                fixture.verify()
                layout = fixture.root / "images" / "wagied"
                blob = next((layout / "blobs" / "sha256").iterdir())
                if label == "extra blob":
                    (layout / "blobs" / "sha256" / ("f" * 64)).write_bytes(b"undeclared")
                elif label == "extra evidence":
                    (fixture.root / "evidence" / "extra.json").write_bytes(b"{}")
                elif label == "extra directory":
                    (fixture.root / "undeclared").mkdir()
                elif label == "missing evidence":
                    (fixture.root / "evidence" / "wagied" / "amd64.test.json").unlink()
                elif label == "symlink blob":
                    target = fixture.root.parent / "external"
                    target.write_bytes(blob.read_bytes())
                    blob.unlink()
                    blob.symlink_to(target)
                elif label == "symlink directory":
                    (fixture.root / "undeclared").symlink_to(layout, target_is_directory=True)
                elif label == "corrupt blob":
                    raw = blob.read_bytes()
                    blob.write_bytes(b"X" + raw[1:])
                else:
                    import os
                    os.mkfifo(fixture.root / "fifo")
                with self.assertRaises(policy.PolicyError):
                    fixture.verify()

    def test_manifest_catalog_cannot_choose_registry_tag_platform_or_paths(self):
        mutations = [
            lambda v: v["images"][0].update(repository="docker.io/attacker/wagied"),
            lambda v: v["images"][3].update(tag=VERSION),
            lambda v: v["images"][0].update(layout="../../images/wagied"),
            lambda v: v["images"].pop(),
            lambda v: v["images"][0]["platforms"][1].update(platform="linux/amd64"),
            lambda v: v["images"][0]["platforms"][0]["sbom"].update(path="../../secret"),
            lambda v: v.update(inputsSHA256="f" * 64),
            lambda v: v.update(sourceEpoch=True),
            lambda v: v["images"][0].update(indexSize=True),
            lambda v: v.update(extra="not ignored"),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                fixture = self.fixture()
                value = copy.deepcopy(fixture.expected)
                mutation(value)
                write_json(fixture.root / "images.json", value)
                with self.assertRaises(policy.PolicyError):
                    fixture.verify()

    def test_duplicate_json_keys_are_rejected_before_interpretation(self):
        for name in ("images.json", "images/wagied/index.json", "evidence/wagied/amd64.test.json"):
            with self.subTest(name=name):
                fixture = self.fixture()
                path = fixture.root / name
                raw = path.read_bytes()
                path.write_bytes(b'{"duplicate":1,"duplicate":2,' + raw[1:])
                with self.assertRaisesRegex(policy.PolicyError, "duplicate JSON key"):
                    fixture.verify()

    def test_count_size_depth_and_nonfinite_json_limits_fail_closed(self):
        fixture = self.fixture()
        with mock.patch.object(policy, "MAX_FILES", 8), self.assertRaisesRegex(policy.PolicyError, "entry count"):
            fixture.verify()
        with mock.patch.object(policy, "MAX_TRANSFER", 1024), self.assertRaisesRegex(policy.PolicyError, "total size"):
            fixture.verify()
        path = fixture.root / "images.json"
        with mock.patch.object(policy, "MAX_EVIDENCE", 8), self.assertRaisesRegex(policy.PolicyError, "oversized"):
            fixture.verify()
        path.write_bytes(b'{"invalid":NaN}')
        with self.assertRaisesRegex(policy.PolicyError, "non-finite"):
            fixture.verify()
        fixture = self.fixture()
        (fixture.root / "a" / "b" / "c" / "d" / "e" / "f" / "g").mkdir(parents=True)
        with self.assertRaisesRegex(policy.PolicyError, "depth"):
            fixture.verify()

    def test_layers_are_hashed_with_bounded_reads_without_unpacking(self):
        fixture = self.fixture()
        real_fdopen = policy.os.fdopen
        layer_reads = []

        class LayerReader:
            def __init__(self, handle):
                self.handle = handle

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.handle.close()

            def fileno(self):
                return self.handle.fileno()

            def read(self, size=-1):
                layer_reads.append(size)
                if not 0 < size <= 1024 * 1024:
                    raise AssertionError("OCI layer read must be bounded")
                return self.handle.read(size)

        layer_names = set()
        for image in fixture.expected["images"]:
            layout = fixture.root / image["layout"]
            for platform in image["platforms"]:
                manifest = json.loads((layout / "blobs" / "sha256" / platform["manifestDigest"][7:]).read_bytes())
                layer_names.add(str(layout / "blobs" / "sha256" / manifest["layers"][0]["digest"][7:]))

        def tracked_open(descriptor, *args, **kwargs):
            target = policy.os.readlink(f"/proc/self/fd/{descriptor}")
            handle = real_fdopen(descriptor, *args, **kwargs)
            return LayerReader(handle) if target in layer_names else handle

        with mock.patch.object(policy.os, "fdopen", side_effect=tracked_open), mock.patch.object(tarfile, "open", side_effect=AssertionError("policy must not unpack layers")):
            fixture.verify()
        self.assertEqual([1024 * 1024] * 16, layer_reads)

    def test_public_export_is_exact_metadata_and_still_binds_reviewed_inputs(self):
        fixture = self.fixture()
        with self.assertRaisesRegex(policy.PolicyError, "missing or oversized"):
            fixture.verify(require_signature=True)
        write_json(fixture.root / "images.json.sigstore.json", {"signature": "fixture; authenticated externally"})
        output = fixture.root.parent / "public"
        self.assertEqual(fixture.expected, policy.export_evidence(fixture.root, output, VERSION, SOURCE_SHA, SOURCE_EPOCH, fixture.inputs))
        actual = {str(path.relative_to(output)) for path in output.rglob("*") if path.is_file()}
        expected = {"images.json", "images.json.sigstore.json", "image-inputs.env"}
        expected.update(f"evidence/{variant}/{arch}.{suffix}.json" for variant in VARIANTS for arch in ARCHITECTURES for suffix in ("spdx", "test"))
        self.assertEqual(expected, actual)
        self.assertFalse((output / "images").exists())
        self.assertEqual(fixture.expected, policy.verify_evidence(output, VERSION, SOURCE_SHA, SOURCE_EPOCH, fixture.inputs))
        (output / "image-inputs.env").write_bytes(b"producer substitution")
        with self.assertRaisesRegex(policy.PolicyError, "reviewed inputs"):
            policy.verify_evidence(output, VERSION, SOURCE_SHA, SOURCE_EPOCH, fixture.inputs)

    def test_public_metadata_rejects_modified_evidence_even_when_parseable(self):
        fixture = self.fixture()
        write_json(fixture.root / "images.json.sigstore.json", {"signature": "fixture"})
        output = fixture.root.parent / "public"
        policy.export_evidence(fixture.root, output, VERSION, SOURCE_SHA, SOURCE_EPOCH, fixture.inputs)
        path = output / "evidence" / "wagied" / "amd64.spdx.json"
        value = json.loads(path.read_bytes())
        value["name"] = "tampered package metadata"
        write_json(path, value)
        with self.assertRaisesRegex(policy.PolicyError, "digest or size"):
            policy.verify_evidence(output, VERSION, SOURCE_SHA, SOURCE_EPOCH, fixture.inputs)

    def test_cli_verifies_expected_identity_and_exits_nonzero_for_tampering(self):
        fixture = self.fixture()
        command = [sys.executable, "-I", str(POLICY_PATH), "verify", "--root", str(fixture.root), "--version", VERSION, "--source-sha", SOURCE_SHA, "--source-epoch", str(SOURCE_EPOCH), "--inputs", str(fixture.inputs)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        fixture.inputs.write_bytes(b"changed reviewed inputs")
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(1, result.returncode)
        self.assertIn("reviewed inputs disagree", result.stderr)


if __name__ == "__main__":
    unittest.main()
