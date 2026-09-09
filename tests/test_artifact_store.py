"""The GitHub receipt must authenticate bytes, identity, paths and executable modes."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('artifact_store', Path(__file__).resolve().parents[1] / 'scripts/artifact-store.py')
STORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STORE)


class ArtifactStore(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'assets').mkdir()
        (self.source / 'assets/wagie').write_bytes(b'exact executable bytes\x00\xff')
        (self.source / 'assets/wagie').chmod(0o751)
        (self.source / 'evidence').mkdir()
        (self.source / 'evidence/result.json').write_text('{"passed":true}\n')
        self.objects = self.root / 'objects'
        self.objects.mkdir()
        self.receipt = self.root / 'receipt'
        self.identity = STORE.identity('Savid/wagie', '123', '2', 'a' * 40)
        self.copies = []

    def copy(self, path, sha, upload=False):
        self.copies.append((sha, upload))
        source, target = (path, self.objects / sha) if upload else (self.objects / sha, path)
        shutil.copyfile(source, target)

    def publish(self):
        STORE.publish('source/assets\nsource/evidence', self.root, self.receipt, 'fixture', self.identity, self.copy)

    def edit_receipt(self, edit):
        path = self.receipt / STORE.RECEIPT
        data = json.loads(path.read_text())
        edit(data)
        path.write_text(json.dumps(data))

    def test_real_files_roundtrip_with_only_small_receipt_in_github_directory(self):
        self.publish()
        self.assertEqual([path.name for path in self.receipt.iterdir()], ['nuc-artifact.json'])
        self.assertLess((self.receipt / STORE.RECEIPT).stat().st_size, 1024)
        STORE.restore(self.receipt, self.identity, 'fixture', self.copy)
        self.assertEqual((self.receipt / 'assets/wagie').read_bytes(), b'exact executable bytes\x00\xff')
        self.assertEqual((self.receipt / 'assets/wagie').stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.receipt / 'evidence/result.json').read_text(), '{"passed":true}\n')
        self.assertFalse((self.receipt / STORE.RECEIPT).exists())

    def test_wrong_run_attempt_source_and_name_refuse_before_any_download(self):
        self.publish()
        before = len(self.copies)
        for field, wrong in [('repository', 'wagiedev/distribution'), ('run', '124'), ('attempt', '1'), ('sha', 'b' * 40)]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'identity mismatch'):
                STORE.restore(self.receipt, dict(self.identity, **{field: wrong}), 'fixture', self.copy)
        with self.assertRaisesRegex(ValueError, 'name mismatch'):
            STORE.restore(self.receipt, self.identity, 'another', self.copy)
        self.assertEqual(len(self.copies), before)

    def test_corrupt_object_refuses_without_exposing_any_file(self):
        self.publish()
        for path in self.objects.iterdir():
            path.write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError, 'authenticated receipt'):
            STORE.restore(self.receipt, self.identity, 'fixture', self.copy)
        self.assertEqual([path.name for path in self.receipt.iterdir()], ['nuc-artifact.json'])

    def test_unsafe_duplicate_and_colliding_paths_refuse_before_download(self):
        self.publish()
        original = (self.receipt / STORE.RECEIPT).read_bytes()
        for value in ['../escape', '/absolute', 'assets/../../escape', 'assets//wagie', 'nuc-artifact.json']:
            with self.subTest(path=value):
                self.edit_receipt(lambda data: data['files'][0].update(path=value))
                with self.assertRaises(ValueError):
                    STORE.restore(self.receipt, self.identity, 'fixture', self.copy)
                (self.receipt / STORE.RECEIPT).write_bytes(original)
        self.edit_receipt(lambda data: data['files'].append(data['files'][0]))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            STORE.restore(self.receipt, self.identity, 'fixture', self.copy)
        (self.receipt / STORE.RECEIPT).write_bytes(original)
        self.edit_receipt(lambda data: data['files'][1].update(path='assets'))
        with self.assertRaisesRegex(ValueError, 'collision'):
            STORE.restore(self.receipt, self.identity, 'fixture', self.copy)

    def test_symlink_destination_and_existing_files_are_never_overwritten(self):
        self.publish()
        outside = self.root / 'outside'
        outside.mkdir()
        (self.receipt / 'assets').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'destination is a link'):
            STORE.restore(self.receipt, self.identity, 'fixture', self.copy)
        self.assertEqual(list(outside.iterdir()), [])
        (self.receipt / 'assets').unlink()
        (self.receipt / 'assets').mkdir()
        (self.receipt / 'assets/wagie').write_bytes(b'keep me')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            STORE.restore(self.receipt, self.identity, 'fixture', self.copy)
        self.assertEqual((self.receipt / 'assets/wagie').read_bytes(), b'keep me')

    def test_producer_link_and_large_receipt_refuse(self):
        (self.source / 'assets/link').symlink_to(self.source / 'assets/wagie')
        with self.assertRaisesRegex(ValueError, 'links are forbidden'):
            self.publish()
        (self.source / 'assets/link').unlink()
        self.publish()
        (self.receipt / STORE.RECEIPT).write_bytes(b' ' * (STORE.MAX_RECEIPT_BYTES + 1))
        with self.assertRaisesRegex(ValueError, 'exceeds 1 MiB'):
            STORE.restore(self.receipt, self.identity, 'fixture', self.copy)

    def test_globs_keep_common_root_and_deduplicate_file_content(self):
        (self.source / 'assets/copy').write_bytes((self.source / 'assets/wagie').read_bytes())
        STORE.publish('source/assets/*\nsource/evidence/*.json', self.root, self.receipt,
                      'fixture', self.identity, self.copy)
        data = json.loads((self.receipt / STORE.RECEIPT).read_text())
        self.assertEqual([item['path'] for item in data['files']],
                         ['assets/copy', 'assets/wagie', 'evidence/result.json'])
        self.assertEqual(sum(upload for _, upload in self.copies), 2)
        self.assertEqual(sum(not upload for _, upload in self.copies), 2)

    def test_successful_upload_without_readable_object_is_retried_before_receipt(self):
        missing = STORE.digest(self.source / 'assets/wagie')
        attempts = []

        def copy(path, sha, upload=False):
            if sha == missing:
                if upload:
                    attempts.append(sha)
                    if len(attempts) == 1:
                        return  # The CLI acknowledged an upload that is absent from storage.
                elif not (self.objects / sha).exists():
                    raise subprocess.CalledProcessError(1, ['aws', 's3', 'cp'])
            self.copy(path, sha, upload)

        STORE.publish('source/assets\nsource/evidence', self.root, self.receipt,
                      'fixture', self.identity, copy)
        self.assertEqual(len(attempts), 2)
        STORE.restore(self.receipt, self.identity, 'fixture', self.copy)
        self.assertEqual((self.receipt / 'assets/wagie').read_bytes(), b'exact executable bytes\x00\xff')

    def test_persistent_missing_object_refuses_receipt_after_bounded_retries(self):
        attempts = []

        def copy(path, sha, upload=False):
            if upload:
                attempts.append(sha)
                return
            raise subprocess.CalledProcessError(1, ['aws', 's3', 'cp'])

        with self.assertRaises(subprocess.CalledProcessError):
            STORE.publish('source/assets', self.root, self.receipt,
                          'fixture', self.identity, copy)
        self.assertEqual(len(attempts), 3)
        self.assertFalse((self.receipt / STORE.RECEIPT).exists())

    def test_successful_but_corrupt_readback_refuses_receipt_without_retry(self):
        attempts = []

        def copy(path, sha, upload=False):
            if upload:
                attempts.append(sha)
                self.copy(path, sha, upload)
            else:
                path.write_bytes(b'x' * (self.objects / sha).stat().st_size)

        with self.assertRaisesRegex(ValueError, 'stored artifact bytes'):
            STORE.publish('source/assets', self.root, self.receipt,
                          'fixture', self.identity, copy)
        self.assertEqual(len(attempts), 1)
        self.assertFalse((self.receipt / STORE.RECEIPT).exists())


if __name__ == '__main__':
    unittest.main()
