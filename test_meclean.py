#!/usr/bin/env python3
"""Path-safety and request checks for meclean."""

import http.client
import os
import tempfile
import threading
import unittest
import urllib.parse
from http.server import ThreadingHTTPServer
from pathlib import Path

import meclean


class PathSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.parent = Path(self.tmp.name)
        self.root = self.parent / "data"
        self.root.mkdir()
        self.sibling = self.parent / "data-evil"
        self.sibling.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_rejects_unsafe_paths(self):
        (self.root / "ok.txt").write_text("x")
        (self.root / "subdir").mkdir()
        secret = self.sibling / "secret.txt"
        secret.write_text("secret")
        (self.root / "escape").symlink_to(secret)
        (self.root / "escdir").symlink_to(self.sibling)
        (self.root / "alias").symlink_to(self.root / "ok.txt")

        cases = [
            "../data-evil/secret.txt",
            str(secret),
            "/etc/passwd",
            "subdir",
            "escape",
            "escdir/secret.txt",
            "alias",
            "",
            "ok.txt\x00.jpg",
            "no-such-file",
            "ok.txt/nope",
            "..",
            "subdir/../../data-evil/secret.txt",
        ]
        for rel in cases:
            with self.subTest(rel=rel):
                with self.assertRaises(meclean.UnsafePath):
                    meclean.safe_target(self.root, rel)
        self.assertEqual(secret.read_text(), "secret")
        self.assertTrue((self.root / "ok.txt").is_file())
        self.assertTrue((self.root / "subdir").is_dir())

    def test_delete_nested_file(self):
        target = self.root / "sub" / "a.txt"
        target.parent.mkdir()
        target.write_text("hello")
        meclean.delete_file(self.root, "sub/a.txt")
        self.assertFalse(target.exists())

    def test_follows_internal_directory_symlink(self):
        real = self.root / "real"
        real.mkdir()
        target = real / "a.txt"
        target.write_text("a")
        (self.root / "via").symlink_to(real)
        self.assertEqual(meclean.safe_target(self.root, "via/a.txt"), target.resolve())

    def test_list_relative_newest_first_skips_other_types(self):
        older = self.root / "old.txt"
        newer = self.root / "sub" / "new.txt"
        newer.parent.mkdir()
        older.write_text("o")
        newer.write_text("n")
        os.utime(older, (1, 1))
        os.utime(newer, (2, 2))
        (self.root / "dir").mkdir()
        (self.root / "link").symlink_to(older)
        listed = meclean.list_files(self.root)
        self.assertEqual([item["path"] for item in listed], ["sub/new.txt", "old.txt"])
        for item in listed:
            meclean.safe_target(self.root, item["path"])

    def test_page_escapes_names(self):
        (self.root / "<b>").write_text("x")
        page = meclean.render_page(self.root, meclean.list_files(self.root), "", "", "tok")
        self.assertIn("&lt;b&gt;", page)
        self.assertNotIn("<b>", page)
        self.assertIn("value=\"tok\"", page)


class RequestTests(unittest.TestCase):
    def test_token_origin_and_fetch_site(self):
        token = "a" * 16
        ok = dict(got_token=token, expected=token, host="clean.lan", origin="", fetch_site="")
        self.assertTrue(meclean.request_allowed(**ok))
        self.assertFalse(meclean.request_allowed(**{**ok, "got_token": "nope"}))
        self.assertFalse(meclean.request_allowed(**{**ok, "got_token": token + "x"}))
        self.assertTrue(meclean.request_allowed(**{**ok, "origin": "http://clean.lan", "fetch_site": "same-origin"}))
        self.assertFalse(meclean.request_allowed(**{**ok, "origin": "http://evil.example"}))
        self.assertFalse(meclean.request_allowed(**{**ok, "fetch_site": "cross-site"}))


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "data"
        self.root.mkdir()
        self.outside = Path(self.tmp.name) / "outside.txt"
        self.outside.write_text("keep")
        self.token = "t" * 24
        handler = meclean.make_handler(self.root, self.token, quiet=True)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.thread.join(timeout=5)
        self.httpd.server_close()
        self.tmp.cleanup()

    def _post(self, path: str, token: str, extra_headers=None):
        body = urllib.parse.urlencode({"path": path, "token": token})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if extra_headers:
            headers.update(extra_headers)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/delete", body, headers)
        response = conn.getresponse()
        status = response.status
        location = response.getheader("Location")
        response.read()
        conn.close()
        return status, location

    def test_health_list_and_post(self):
        target = self.root / "note.txt"
        target.write_text("hello")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/health")
        self.assertEqual(conn.getresponse().read(), b"ok\n")
        conn.request("GET", "/")
        page = conn.getresponse().read().decode()
        conn.close()
        self.assertIn("note.txt", page)
        self.assertIn(self.token, page)

        status, location = self._post("note.txt", "wrong-token")
        self.assertEqual((status, location), (303, "/?msg=rejected"))
        self.assertTrue(target.is_file())

        status, location = self._post(
            "note.txt",
            self.token,
            {"Origin": "http://evil.example"},
        )
        self.assertEqual(location, "/?msg=rejected")
        self.assertTrue(target.is_file())

        status, location = self._post("../outside.txt", self.token)
        self.assertEqual(location, "/?msg=rejected")
        self.assertEqual(self.outside.read_text(), "keep")

        status, location = self._post("note.txt", self.token)
        self.assertEqual((status, location), (303, "/?msg=deleted"))
        self.assertFalse(target.exists())

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/?msg=deleted")
        self.assertIn("File deleted.", conn.getresponse().read().decode())
        conn.close()


if __name__ == "__main__":
    unittest.main()
