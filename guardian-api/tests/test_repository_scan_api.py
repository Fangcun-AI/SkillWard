import tempfile
import unittest
import sys
import zipfile
from pathlib import Path
from unittest.mock import patch

if not any((Path(p) / "fastapi").exists() for p in sys.path if p):
    project_root = Path(__file__).resolve().parents[2]
    site_packages = next((project_root / ".venv" / "lib").glob("python*/site-packages"), None)
    if site_packages:
        sys.path.insert(0, str(site_packages))

from fastapi.testclient import TestClient

import guardian_api


class _ChunkedResponse:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size=-1):
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class RepositoryScanApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(guardian_api.app)

    def test_repository_scan_rejects_non_http_url(self):
        response = self.client.post(
            "/api/scan/repository",
            json={"repository_url": "file:///tmp/skill"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_repository_url"})

    def test_repository_scan_runs_prepared_skill_and_forwards_options(self):
        calls = {}

        def fake_prepare(repository_url):
            calls["repository_url"] = repository_url
            return "/tmp/prepared-skill", "/tmp/prepared-root"

        async def fake_run_single_scan(
            skill_path,
            use_llm=True,
            use_runtime=False,
            enable_after_tool=True,
            batch_id=None,
            lang="en",
        ):
            calls["scan"] = {
                "skill_path": skill_path,
                "use_llm": use_llm,
                "use_runtime": use_runtime,
                "enable_after_tool": enable_after_tool,
                "batch_id": batch_id,
                "lang": lang,
            }
            return {"report": "ok"}

        with (
            patch.object(guardian_api, "_prepare_repository_skill", fake_prepare),
            patch.object(guardian_api, "_run_single_scan", fake_run_single_scan),
            patch.object(guardian_api.shutil, "rmtree", lambda path, ignore_errors=False: None),
        ):
            response = self.client.post(
                "/api/scan/repository",
                json={
                    "repository_url": "https://github.com/example/skill",
                    "use_llm": False,
                    "use_runtime": True,
                    "enable_after_tool": False,
                    "lang": "zh",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"report": "ok"})
        self.assertEqual(calls["repository_url"], "https://github.com/example/skill")
        self.assertEqual(
            calls["scan"],
            {
                "skill_path": "/tmp/prepared-skill",
                "use_llm": False,
                "use_runtime": True,
                "enable_after_tool": False,
                "batch_id": None,
                "lang": "zh",
            },
        )

    def test_download_repository_archive_rejects_oversized_response(self):
        response = _ChunkedResponse([b"abc", b"def"])

        with tempfile.TemporaryDirectory() as tmp_dir:
            archive_path = Path(tmp_dir) / "repository.zip"
            with patch("urllib.request.urlopen", return_value=response):
                with self.assertRaises(guardian_api._RepositoryScanError) as raised:
                    guardian_api._download_repository_archive(
                        "https://example.com/repository.zip",
                        archive_path,
                        max_bytes=5,
                    )

        self.assertEqual(raised.exception.error, "repository_archive_too_large")
        self.assertEqual(raised.exception.status_code, 413)

    def test_extract_repository_archive_rejects_oversized_zip_contents(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            archive_path = Path(tmp_dir) / "repository.zip"
            extract_dir = Path(tmp_dir) / "extracted"
            with zipfile.ZipFile(archive_path, "w") as zf:
                zf.writestr("skill/SKILL.md", b"a" * 6)
                zf.writestr("skill/extra.txt", b"b" * 6)

            with self.assertRaises(guardian_api._RepositoryScanError) as raised:
                guardian_api._extract_repository_archive(
                    archive_path,
                    extract_dir,
                    max_uncompressed_bytes=10,
                )

        self.assertEqual(raised.exception.error, "repository_archive_too_large")
        self.assertEqual(raised.exception.status_code, 413)

    def test_clone_failure_detail_is_limited_to_last_1000_chars(self):
        stderr = "x" * 1200 + "tail-detail"

        with tempfile.TemporaryDirectory() as tmp_dir:
            error_file = Path(tmp_dir) / "clone.stderr"
            error_file.write_text(stderr)

            detail = guardian_api._read_tail(error_file, 1000)

        self.assertEqual(len(detail), 1000)
        self.assertTrue(detail.endswith("tail-detail"))
        self.assertNotEqual(detail, stderr)
        self.assertEqual(detail.count("x"), 1000 - len("tail-detail"))

    def test_clone_repository_failure_uses_limited_stderr_tail(self):
        stderr = "x" * 1200 + "tail-detail"

        class FakeProcess:
            def __init__(self, stderr_file):
                self._stderr_file = stderr_file

            def wait(self, timeout=None):
                self._stderr_file.write(stderr.encode())
                return 1

        def fake_popen(*args, **kwargs):
            return FakeProcess(kwargs["stderr"])

        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch.object(guardian_api.subprocess, "Popen", fake_popen):
                with self.assertRaises(guardian_api._RepositoryScanError) as raised:
                    guardian_api._clone_repository(
                        "https://github.com/example/skill",
                        Path(tmp_dir) / "repo",
                    )

        self.assertEqual(raised.exception.error, "repository_clone_failed")
        self.assertEqual(len(raised.exception.detail), 1000)
        self.assertTrue(raised.exception.detail.endswith("tail-detail"))
        self.assertEqual(
            raised.exception.detail.count("x"),
            1000 - len("tail-detail"),
        )


if __name__ == "__main__":
    unittest.main()
