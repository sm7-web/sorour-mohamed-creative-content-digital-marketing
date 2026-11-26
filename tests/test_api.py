#!/usr/bin/env python3
"""Automated API tests covering Auth, RBAC, CRUD, Leads, Media validation, and Audit Logs."""

import base64
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

os.environ["QUIET_LOGS"] = "1"

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from server import PortfolioApp, make_handler

# Minimal valid 1x1 PNG bytes
VALID_PNG_B64 = base64.b64encode(
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
).decode("ascii")


class PortfolioApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["ADMIN_EMAIL"] = "owner@test.local"
        os.environ["ADMIN_PASSWORD"] = "StrongPass!2026"
        cls.app = PortfolioApp(
            db_path=Path(cls.tmp.name) / "test.db",
            upload_dir=Path(cls.tmp.name) / "uploads",
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.app))
        cls.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    def req(self, method: str, path: str, body: dict | None = None, token: str | None = None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        r = Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urlopen(r) as resp:
                raw = resp.read()
                ctype = resp.headers.get("Content-Type", "")
                return resp.status, json.loads(raw.decode("utf-8")) if "json" in ctype else raw.decode("utf-8")
        except HTTPError as e:
            raw = e.read().decode("utf-8")
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw

    def login(self, email: str, password: str) -> str:
        status, data = self.req("POST", "/api/auth/login", {"email": email, "password": password})
        self.assertEqual(status, 200)
        return data["token"]

    def test_01_auth_and_rbac(self):
        # Wrong password rejected
        st, _ = self.req("POST", "/api/auth/login", {"email": "owner@test.local", "password": "wrong"})
        self.assertEqual(st, 401)

        # Unauthenticated admin blocked
        st, _ = self.req("GET", "/api/admin/overview")
        self.assertEqual(st, 401)

        admin_tok = self.login("owner@test.local", "StrongPass!2026")
        # Create Viewer user
        st, _ = self.req(
            "POST",
            "/api/admin/users",
            {"full_name": "Client Viewer", "email": "viewer@test.local", "password": "ViewerPass!2026", "role": "Viewer"},
            token=admin_tok,
        )
        self.assertEqual(st, 201)

        viewer_tok = self.login("viewer@test.local", "ViewerPass!2026")
        # Viewer can read overview
        st, _ = self.req("GET", "/api/admin/overview", token=viewer_tok)
        self.assertEqual(st, 200)
        # Viewer CANNOT create project or export leads
        st, _ = self.req("POST", "/api/admin/projects", {"title_ar": "محاولة غير مصرحة"}, token=viewer_tok)
        self.assertEqual(st, 403)
        st, _ = self.req("GET", "/api/admin/leads/export.csv", token=viewer_tok)
        self.assertEqual(st, 403)

    def test_02_project_draft_to_published_flow(self):
        tok = self.login("owner@test.local", "StrongPass!2026")
        # Initially starter projects are draft, so public bootstrap has 0 published projects
        st, pub = self.req("GET", "/api/public/bootstrap")
        self.assertEqual(st, 200)
        self.assertEqual(len(pub["projects"]), 0)
        self.assertEqual(len(pub["services"]), 8)

        # Create draft project
        st, created = self.req(
            "POST",
            "/api/admin/projects",
            {"title_ar": "حملة قهوة تجريبية", "title_en": "Coffee Campaign", "status": "draft"},
            token=tok,
        )
        self.assertEqual(st, 201)
        pid = created["id"]

        # Publish it
        st, _ = self.req("PUT", f"/api/admin/projects/{pid}", {"status": "published"}, token=tok)
        self.assertEqual(st, 200)

        # Now appears in public bootstrap
        st, pub2 = self.req("GET", "/api/public/bootstrap")
        self.assertEqual(len(pub2["projects"]), 1)
        self.assertEqual(pub2["projects"][0]["id"], pid)

    def test_03_leads_honeypot_notes_and_csv(self):
        # Honeypot blocks spam
        st, _ = self.req("POST", "/api/public/leads", {"name": "Bot", "phone": "123", "website_hp": "http://spam"})
        self.assertEqual(st, 400)

        # Legit lead
        st, res = self.req(
            "POST",
            "/api/public/leads",
            {"name": "أحمد علي", "company": "متجر نور", "phone": "+201000000000", "service_requested": "تصوير المنتجات"},
        )
        self.assertEqual(st, 201)
        lid = res["id"]

        tok = self.login("owner@test.local", "StrongPass!2026")
        st, _ = self.req("PUT", f"/api/admin/leads/{lid}", {"status": "contacted"}, token=tok)
        self.assertEqual(st, 200)
        st, _ = self.req("POST", f"/api/admin/leads/{lid}/notes", {"note": "تم التواصل عبر واتساب"}, token=tok)
        self.assertEqual(st, 201)

        st, csv_text = self.req("GET", "/api/admin/leads/export.csv", token=tok)
        self.assertEqual(st, 200)
        self.assertIn("أحمد علي", csv_text)

    def test_04_media_magic_bytes_and_delete_protection(self):
        tok = self.login("owner@test.local", "StrongPass!2026")
        # Fake image rejected
        fake_b64 = base64.b64encode(b"this is not an image at all").decode("ascii")
        st, _ = self.req("POST", "/api/admin/media", {"display_name": "fake.png", "data_base64": fake_b64}, token=tok)
        self.assertEqual(st, 400)

        # Valid PNG accepted
        st, up = self.req("POST", "/api/admin/media", {"display_name": "cover.png", "data_base64": VALID_PNG_B64}, token=tok)
        self.assertEqual(st, 201)
        media_id, media_url = up["id"], up["url"]

        # Attach to published project -> delete must be blocked (409)
        st, p = self.req("POST", "/api/admin/projects", {"title_ar": "مشروع بصورة", "status": "published", "cover_image": media_url}, token=tok)
        self.assertEqual(st, 201)
        st, _ = self.req("DELETE", f"/api/admin/media/{media_id}", token=tok)
        self.assertEqual(st, 409)

        # Check audit log recorded activity
        st, logs = self.req("GET", "/api/admin/activity", token=tok)
        self.assertEqual(st, 200)
        self.assertGreater(len(logs["activity"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
