#!/usr/bin/env python3
"""
Sorour Mohamed — Personal Portfolio & Admin Dashboard Backend Server.
Zero-dependency Python 3.11+ server using ThreadingHTTPServer + SQLite.
"""

from __future__ import annotations

import base64
import csv
import hmac
import io
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from seed import hash_password, init_db

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"

ALLOWED_IMAGE_MIMES = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}
ALLOWED_VIDEO_MIMES = {"video/mp4": ".mp4", "video/webm": ".webm"}
MAX_IMAGE_BYTES = 10 * 1024 * 1024   # 10 MB
MAX_VIDEO_BYTES = 50 * 1024 * 1024   # 50 MB


def detect_magic_mime(raw: bytes) -> str | None:
    if len(raw) < 12:
        return None
    if raw[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    if raw[4:8] == b"ftyp":
        return "video/mp4"
    if raw[:4] == b"\x1a\x45\xdf\xa3":
        return "video/webm"
    return None


def validate_video_embed_url(url: str) -> bool:
    if not url:
        return True
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        return False
    host = (parsed.hostname or "").lower()
    allowed_hosts = (
        "youtube.com",
        "www.youtube.com",
        "youtu.be",
        "vimeo.com",
        "player.vimeo.com",
    )
    return host in allowed_hosts


def slugify(text: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9\u0600-\u06FF\s-]", "", text).strip().lower()
    cleaned = re.sub(r"[\s_]+", "-", cleaned)
    return cleaned or f"item-{secrets.token_hex(4)}"


class RateLimiter:
    def __init__(self) -> None:
        self.buckets: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        recent = [t for t in self.buckets[key] if t > cutoff]
        if len(recent) >= limit:
            self.buckets[key] = recent
            return False
        recent.append(now)
        self.buckets[key] = recent
        return True


class PortfolioApp:
    def __init__(self, db_path: Path, upload_dir: Path) -> None:
        self.db_path = Path(db_path)
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.rate_limiter = RateLimiter()
        init_db(self.db_path)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def log_activity(
        self,
        conn: sqlite3.Connection,
        user: dict | None,
        action: str,
        entity_type: str,
        entity_id: str = "",
        details: str = "",
    ) -> None:
        conn.execute(
            """
            INSERT INTO activity_logs (user_id, user_email, action, entity_type, entity_id, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"] if user else None,
                user["email"] if user else "public",
                action,
                entity_type,
                str(entity_id),
                details,
            ),
        )


def make_handler(app: PortfolioApp):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args) -> None:
            if os.environ.get("QUIET_LOGS") != "1":
                super().log_message(format, *args)

        def client_ip(self) -> str:
            return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()

        def send_json(self, status: int, payload: dict | list, extra_headers: dict | None = None) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def send_bytes(self, status: int, content_type: str, data: bytes, extra_headers: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def read_json_body(self, max_bytes: int = 15 * 1024 * 1024) -> dict | None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0:
                return {}
            if length > max_bytes:
                self.send_json(413, {"error": "Payload too large"})
                return None
            raw = self.rfile.read(length)
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:
                self.send_json(400, {"error": "Invalid JSON body"})
                return None

        def get_session_token(self) -> str | None:
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                return auth[7:].strip()
            cookie_hdr = self.headers.get("Cookie", "")
            if cookie_hdr:
                c = cookies.SimpleCookie()
                try:
                    c.load(cookie_hdr)
                    if "sm_session" in c:
                        return c["sm_session"].value
                except Exception:
                    pass
            return None

        def get_current_user(self, conn: sqlite3.Connection) -> dict | None:
            token = self.get_session_token()
            if not token:
                return None
            row = conn.execute(
                """
                SELECT u.id, u.full_name, u.email, u.is_active, u.must_change_password,
                       r.name AS role, s.expires_at
                FROM sessions s
                JOIN admin_users u ON u.id = s.user_id
                JOIN roles r ON r.id = u.role_id
                WHERE s.token = ?
                """,
                (token,),
            ).fetchone()
            if not row or not row["is_active"]:
                return None
            if row["expires_at"] < datetime.now(timezone.utc).isoformat():
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
                return None
            return dict(row)

        def require_role(self, conn: sqlite3.Connection, allowed: tuple[str, ...]) -> dict | None:
            user = self.get_current_user(conn)
            if not user:
                self.send_json(401, {"error": "Authentication required"})
                return None
            if user["role"] not in allowed:
                self.send_json(403, {"error": "Insufficient permissions"})
                return None
            return user

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            qs = parse_qs(parsed.query)

            if path == "/robots.txt":
                site_url = os.environ.get("SITE_URL", "http://localhost:8080").rstrip("/")
                body = f"User-agent: *\nAllow: /\nDisallow: /admin\nSitemap: {site_url}/sitemap.xml\n".encode("utf-8")
                self.send_bytes(200, "text/plain; charset=utf-8", body)
                return

            if path == "/sitemap.xml":
                site_url = os.environ.get("SITE_URL", "http://localhost:8080").rstrip("/")
                conn = app.connect()
                try:
                    slugs = [r["slug"] for r in conn.execute("SELECT slug FROM projects WHERE status = 'published'").fetchall()]
                finally:
                    conn.close()
                urls = ["", "/#/about", "/#/services", "/#/portfolio", "/#/contact"] + [f"/#/project/{s}" for s in slugs]
                xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                for u in urls:
                    xml += f"  <url><loc>{site_url}{u}</loc></url>\n"
                xml += "</urlset>\n"
                self.send_bytes(200, "application/xml; charset=utf-8", xml.encode("utf-8"))
                return

            if path.startswith("/uploads/"):
                fname = Path(path).name
                fpath = app.upload_dir / fname
                if fpath.is_file():
                    mime = mimetypes.guess_type(str(fpath))[0] or "application/octet-stream"
                    self.send_bytes(200, mime, fpath.read_bytes())
                else:
                    self.send_json(404, {"error": "File not found"})
                return

            if path == "/api/public/bootstrap":
                self.handle_public_bootstrap()
                return

            if path == "/api/auth/me":
                conn = app.connect()
                try:
                    user = self.get_current_user(conn)
                    if not user:
                        self.send_json(401, {"error": "Not authenticated"})
                    else:
                        self.send_json(200, {"user": user})
                finally:
                    conn.close()
                return

            if path.startswith("/api/admin/"):
                self.handle_admin_get(path, qs)
                return

            # Serve SPA frontend
            index_file = PUBLIC_DIR / "index.html"
            if index_file.is_file():
                self.send_bytes(200, "text/html; charset=utf-8", index_file.read_bytes())
            else:
                self.send_json(404, {"error": "Frontend not built yet"})

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if path == "/api/public/leads":
                self.handle_public_lead()
                return
            if path == "/api/auth/login":
                self.handle_login()
                return
            if path == "/api/auth/logout":
                self.handle_logout()
                return
            if path == "/api/auth/change-password":
                self.handle_change_password()
                return
            if path.startswith("/api/admin/"):
                self.handle_admin_post(path)
                return
            self.send_json(404, {"error": "Not found"})

        def do_PUT(self) -> None:
            path = urlparse(self.path).path
            if path.startswith("/api/admin/"):
                self.handle_admin_put(path)
                return
            self.send_json(404, {"error": "Not found"})

        def do_DELETE(self) -> None:
            path = urlparse(self.path).path
            if path.startswith("/api/admin/"):
                self.handle_admin_delete(path)
                return
            self.send_json(404, {"error": "Not found"})

        # ---------------- Public Handlers ----------------
        def handle_public_bootstrap(self) -> None:
            conn = app.connect()
            try:
                projects = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM projects WHERE status = 'published' ORDER BY sort_order ASC, id DESC"
                    ).fetchall()
                ]
                for p in projects:
                    p["services_used"] = json.loads(p["services_used"] or "[]")
                    p["media"] = [
                        dict(m)
                        for m in conn.execute(
                            "SELECT * FROM project_media WHERE project_id = ? ORDER BY sort_order ASC",
                            (p["id"],),
                        ).fetchall()
                    ]
                services = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM services WHERE is_published = 1 ORDER BY sort_order ASC, id ASC"
                    ).fetchall()
                ]
                for s in services:
                    s["features_ar"] = json.loads(s["features_ar"] or "[]")
                    s["features_en"] = json.loads(s["features_en"] or "[]")

                pages = {}
                for r in conn.execute("SELECT page_key, content_ar, content_en FROM site_pages").fetchall():
                    pages[r["page_key"]] = {
                        "ar": json.loads(r["content_ar"] or "{}"),
                        "en": json.loads(r["content_en"] or "{}"),
                    }

                settings = {}
                for r in conn.execute(
                    "SELECT setting_key, setting_value FROM site_settings WHERE is_public = 1"
                ).fetchall():
                    settings[r["setting_key"]] = r["setting_value"]

                self.send_json(
                    200,
                    {
                        "projects": projects,
                        "services": services,
                        "pages": pages,
                        "settings": settings,
                    },
                )
            finally:
                conn.close()

        def handle_public_lead(self) -> None:
            if not app.rate_limiter.allow(f"lead:{self.client_ip()}", limit=10, window_seconds=300):
                self.send_json(429, {"error": "Too many requests. Please try again later."})
                return
            body = self.read_json_body()
            if body is None:
                return
            # Honeypot check
            if str(body.get("website_hp", "")).strip():
                self.send_json(400, {"error": "Spam detected"})
                return
            name = str(body.get("name", "")).strip()
            phone = str(body.get("phone", "")).strip()
            details = str(body.get("details", "")).strip()
            if not name or not phone:
                self.send_json(400, {"error": "Name and phone/WhatsApp are required"})
                return
            conn = app.connect()
            try:
                cur = conn.execute(
                    """
                    INSERT INTO leads (name, company, phone, email, service_requested, budget, timeline, details, source, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')
                    """,
                    (
                        name,
                        str(body.get("company", "")).strip(),
                        phone,
                        str(body.get("email", "")).strip(),
                        str(body.get("service_requested", "")).strip(),
                        str(body.get("budget", "")).strip(),
                        str(body.get("timeline", "")).strip(),
                        details,
                        str(body.get("source", "contact_form")).strip(),
                    ),
                )
                lead_id = cur.lastrowid
                app.log_activity(conn, None, "lead_created", "lead", str(lead_id), f"New inquiry from {name}")
                conn.commit()
                self.send_json(201, {"id": lead_id, "status": "new"})
            finally:
                conn.close()

        # ---------------- Auth Handlers ----------------
        def handle_login(self) -> None:
            if not app.rate_limiter.allow(f"login:{self.client_ip()}", limit=10, window_seconds=300):
                self.send_json(429, {"error": "Too many login attempts. Wait 5 minutes."})
                return
            body = self.read_json_body()
            if body is None:
                return
            email = str(body.get("email", "")).strip().lower()
            password = str(body.get("password", ""))
            if not email or not password:
                self.send_json(400, {"error": "Email and password required"})
                return
            conn = app.connect()
            try:
                row = conn.execute(
                    """
                    SELECT u.*, r.name AS role
                    FROM admin_users u
                    JOIN roles r ON r.id = u.role_id
                    WHERE lower(u.email) = ?
                    """,
                    (email,),
                ).fetchone()
                if not row or not row["is_active"]:
                    self.send_json(401, {"error": "Invalid credentials"})
                    return
                calc_hash, _ = hash_password(password, row["password_salt"])
                if not hmac.compare_digest(calc_hash, row["password_hash"]):
                    self.send_json(401, {"error": "Invalid credentials"})
                    return
                token = secrets.token_urlsafe(32)
                expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
                conn.execute(
                    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
                    (token, row["id"], expires),
                )
                conn.execute(
                    "UPDATE admin_users SET last_login_at = datetime('now') WHERE id = ?",
                    (row["id"],),
                )
                user_dict = {
                    "id": row["id"],
                    "full_name": row["full_name"],
                    "email": row["email"],
                    "role": row["role"],
                    "must_change_password": bool(row["must_change_password"]),
                }
                app.log_activity(conn, user_dict, "login", "auth", str(row["id"]), "Admin logged in")
                conn.commit()
                self.send_json(
                    200,
                    {"token": token, "user": user_dict},
                    extra_headers={
                        "Set-Cookie": f"sm_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800"
                    },
                )
            finally:
                conn.close()

        def handle_logout(self) -> None:
            token = self.get_session_token()
            if token:
                conn = app.connect()
                try:
                    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                    conn.commit()
                finally:
                    conn.close()
            self.send_json(
                200,
                {"ok": True},
                extra_headers={"Set-Cookie": "sm_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"},
            )

        def handle_change_password(self) -> None:
            conn = app.connect()
            try:
                user = self.require_role(conn, ("Super Admin", "Editor", "Viewer"))
                if not user:
                    return
                body = self.read_json_body()
                if body is None:
                    return
                current_pw = str(body.get("current_password", ""))
                new_pw = str(body.get("new_password", ""))
                if len(new_pw) < 8:
                    self.send_json(400, {"error": "New password must be at least 8 characters"})
                    return
                row = conn.execute(
                    "SELECT password_hash, password_salt FROM admin_users WHERE id = ?",
                    (user["id"],),
                ).fetchone()
                calc_hash, _ = hash_password(current_pw, row["password_salt"])
                if not hmac.compare_digest(calc_hash, row["password_hash"]):
                    self.send_json(400, {"error": "Current password is incorrect"})
                    return
                new_hash, new_salt = hash_password(new_pw)
                conn.execute(
                    """
                    UPDATE admin_users
                    SET password_hash = ?, password_salt = ?, must_change_password = 0, updated_at = datetime('now')
                    WHERE id = ?
                    """,
                    (new_hash, new_salt, user["id"]),
                )
                app.log_activity(conn, user, "password_changed", "admin_user", str(user["id"]), "Updated password")
                conn.commit()
                self.send_json(200, {"ok": True})
            finally:
                conn.close()

        # ---------------- Admin GET ----------------
        def handle_admin_get(self, path: str, qs: dict) -> None:
            conn = app.connect()
            try:
                user = self.require_role(conn, ("Super Admin", "Editor", "Viewer"))
                if not user:
                    return

                if path == "/api/admin/overview":
                    stats = {
                        "published_projects": conn.execute("SELECT COUNT(*) FROM projects WHERE status = 'published'").fetchone()[0],
                        "draft_projects": conn.execute("SELECT COUNT(*) FROM projects WHERE status = 'draft'").fetchone()[0],
                        "new_leads": conn.execute("SELECT COUNT(*) FROM leads WHERE status = 'new'").fetchone()[0],
                        "active_leads": conn.execute("SELECT COUNT(*) FROM leads WHERE status IN ('contacted','meeting','proposal_sent')").fetchone()[0],
                        "total_leads": conn.execute("SELECT COUNT(*) FROM leads").fetchone()[0],
                        "active_services": conn.execute("SELECT COUNT(*) FROM services WHERE is_published = 1").fetchone()[0],
                        "media_count": conn.execute("SELECT COUNT(*) FROM media_assets").fetchone()[0],
                    }
                    leads_series = [
                        dict(r)
                        for r in conn.execute(
                            "SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS count FROM leads GROUP BY day ORDER BY day ASC LIMIT 30"
                        ).fetchall()
                    ]
                    recent_leads = [
                        dict(r)
                        for r in conn.execute("SELECT * FROM leads ORDER BY created_at DESC LIMIT 8").fetchall()
                    ]
                    recent_projects = [
                        dict(r)
                        for r in conn.execute("SELECT id, title_ar, title_en, status, updated_at FROM projects ORDER BY updated_at DESC LIMIT 6").fetchall()
                    ]
                    recent_activity = [
                        dict(r)
                        for r in conn.execute("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 10").fetchall()
                    ]
                    self.send_json(
                        200,
                        {
                            "stats": stats,
                            "leads_series": leads_series,
                            "recent_leads": recent_leads,
                            "recent_projects": recent_projects,
                            "recent_activity": recent_activity,
                            "system_health": {
                                "database": "ok",
                                "storage": "ok" if app.upload_dir.exists() else "error",
                                "smtp_configured": bool(os.environ.get("SMTP_HOST")),
                                "analytics_configured": bool(os.environ.get("GA_MEASUREMENT_ID")),
                            },
                        },
                    )
                    return

                if path == "/api/admin/projects":
                    rows = [dict(r) for r in conn.execute("SELECT * FROM projects ORDER BY sort_order ASC, id DESC").fetchall()]
                    for p in rows:
                        p["services_used"] = json.loads(p["services_used"] or "[]")
                    self.send_json(200, {"projects": rows})
                    return

                if path == "/api/admin/services":
                    rows = [dict(r) for r in conn.execute("SELECT * FROM services ORDER BY sort_order ASC, id ASC").fetchall()]
                    for s in rows:
                        s["features_ar"] = json.loads(s["features_ar"] or "[]")
                        s["features_en"] = json.loads(s["features_en"] or "[]")
                    self.send_json(200, {"services": rows})
                    return

                if path == "/api/admin/leads":
                    status_filter = (qs.get("status") or [""])[0]
                    search = (qs.get("q") or [""])[0].strip()
                    sql = "SELECT * FROM leads WHERE 1=1"
                    params: list = []
                    if status_filter:
                        sql += " AND status = ?"
                        params.append(status_filter)
                    if search:
                        sql += " AND (name LIKE ? OR phone LIKE ? OR company LIKE ?)"
                        like = f"%{search}%"
                        params.extend([like, like, like])
                    sql += " ORDER BY created_at DESC"
                    leads = [dict(r) for r in conn.execute(sql, params).fetchall()]
                    for ld in leads:
                        ld["notes"] = [
                            dict(n)
                            for n in conn.execute(
                                "SELECT * FROM lead_notes WHERE lead_id = ? ORDER BY created_at DESC",
                                (ld["id"],),
                            ).fetchall()
                        ]
                    self.send_json(200, {"leads": leads})
                    return

                if path == "/api/admin/leads/export.csv":
                    if user["role"] not in ("Super Admin", "Editor"):
                        self.send_json(403, {"error": "Only Super Admin or Editor can export leads"})
                        return
                    buf = io.StringIO()
                    writer = csv.writer(buf)
                    writer.writerow(["ID", "Name", "Company", "Phone", "Email", "Service", "Budget", "Timeline", "Status", "Created At"])
                    for r in conn.execute("SELECT * FROM leads ORDER BY created_at DESC").fetchall():
                        writer.writerow([r["id"], r["name"], r["company"], r["phone"], r["email"], r["service_requested"], r["budget"], r["timeline"], r["status"], r["created_at"]])
                    self.send_bytes(
                        200,
                        "text/csv; charset=utf-8",
                        buf.getvalue().encode("utf-8-sig"),
                        extra_headers={"Content-Disposition": 'attachment; filename="leads.csv"'},
                    )
                    return

                if path == "/api/admin/cms":
                    pages = {}
                    for r in conn.execute("SELECT page_key, content_ar, content_en, updated_at FROM site_pages").fetchall():
                        pages[r["page_key"]] = {
                            "ar": json.loads(r["content_ar"] or "{}"),
                            "en": json.loads(r["content_en"] or "{}"),
                            "updated_at": r["updated_at"],
                        }
                    self.send_json(200, {"pages": pages})
                    return

                if path == "/api/admin/media":
                    rows = [dict(r) for r in conn.execute("SELECT * FROM media_assets ORDER BY id DESC").fetchall()]
                    self.send_json(200, {"media": rows})
                    return

                if path == "/api/admin/users":
                    if user["role"] != "Super Admin":
                        self.send_json(403, {"error": "Super Admin only"})
                        return
                    users = [
                        dict(r)
                        for r in conn.execute(
                            """
                            SELECT u.id, u.full_name, u.email, u.is_active, u.last_login_at, u.created_at, r.name AS role
                            FROM admin_users u JOIN roles r ON r.id = u.role_id
                            ORDER BY u.id ASC
                            """
                        ).fetchall()
                    ]
                    roles = [dict(r) for r in conn.execute("SELECT * FROM roles").fetchall()]
                    self.send_json(200, {"users": users, "roles": roles})
                    return

                if path == "/api/admin/settings":
                    rows = [dict(r) for r in conn.execute("SELECT * FROM site_settings").fetchall()]
                    self.send_json(200, {"settings": {r["setting_key"]: r["setting_value"] for r in rows}})
                    return

                if path == "/api/admin/activity":
                    rows = [dict(r) for r in conn.execute("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 100").fetchall()]
                    self.send_json(200, {"activity": rows})
                    return

                self.send_json(404, {"error": "Not found"})
            finally:
                conn.close()

        # ---------------- Admin POST ----------------
        def handle_admin_post(self, path: str) -> None:
            conn = app.connect()
            try:
                # User management is Super Admin only
                if path == "/api/admin/users":
                    user = self.require_role(conn, ("Super Admin",))
                    if not user:
                        return
                    body = self.read_json_body()
                    if body is None:
                        return
                    email = str(body.get("email", "")).strip().lower()
                    full_name = str(body.get("full_name", "")).strip()
                    password = str(body.get("password", ""))
                    role_name = str(body.get("role", "Viewer"))
                    if not email or not full_name or len(password) < 8:
                        self.send_json(400, {"error": "Full name, email, and 8+ char password required"})
                        return
                    role_row = conn.execute("SELECT id FROM roles WHERE name = ?", (role_name,)).fetchone()
                    if not role_row:
                        self.send_json(400, {"error": "Invalid role"})
                        return
                    pw_hash, pw_salt = hash_password(password)
                    try:
                        cur = conn.execute(
                            "INSERT INTO admin_users (role_id, full_name, email, password_hash, password_salt) VALUES (?, ?, ?, ?, ?)",
                            (role_row["id"], full_name, email, pw_hash, pw_salt),
                        )
                    except sqlite3.IntegrityError:
                        self.send_json(409, {"error": "Email already exists"})
                        return
                    app.log_activity(conn, user, "user_created", "admin_user", str(cur.lastrowid), f"Created {email} ({role_name})")
                    conn.commit()
                    self.send_json(201, {"id": cur.lastrowid})
                    return

                # Other POSTs require Super Admin or Editor
                user = self.require_role(conn, ("Super Admin", "Editor"))
                if not user:
                    return
                body = self.read_json_body()
                if body is None:
                    return

                if path == "/api/admin/projects":
                    title_ar = str(body.get("title_ar", "")).strip()
                    if not title_ar:
                        self.send_json(400, {"error": "Arabic title is required"})
                        return
                    video_url = str(body.get("video_url", "")).strip()
                    if not validate_video_embed_url(video_url):
                        self.send_json(400, {"error": "Only YouTube or Vimeo URLs are allowed"})
                        return
                    slug = str(body.get("slug", "")).strip() or slugify(body.get("title_en") or title_ar)
                    status = body.get("status", "draft")
                    if status not in ("draft", "published", "archived", "scheduled"):
                        status = "draft"
                    cur = conn.execute(
                        """
                        INSERT INTO projects (
                            slug, title_ar, title_en, client_name, category, industry,
                            short_desc_ar, short_desc_en, full_desc_ar, full_desc_en,
                            goal_ar, goal_en, result_ar, result_en, services_used,
                            cover_image, video_url, project_date, status, is_featured, sort_order,
                            seo_title_ar, seo_title_en, seo_desc_ar, seo_desc_en
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            slug,
                            title_ar,
                            str(body.get("title_en", "")).strip(),
                            str(body.get("client_name", "")).strip(),
                            str(body.get("category", "video")).strip(),
                            str(body.get("industry", "")).strip(),
                            str(body.get("short_desc_ar", "")).strip(),
                            str(body.get("short_desc_en", "")).strip(),
                            str(body.get("full_desc_ar", "")).strip(),
                            str(body.get("full_desc_en", "")).strip(),
                            str(body.get("goal_ar", "")).strip(),
                            str(body.get("goal_en", "")).strip(),
                            str(body.get("result_ar", "")).strip(),
                            str(body.get("result_en", "")).strip(),
                            json.dumps(body.get("services_used", []), ensure_ascii=False),
                            str(body.get("cover_image", "")).strip(),
                            video_url,
                            str(body.get("project_date", "")).strip(),
                            status,
                            1 if body.get("is_featured") else 0,
                            int(body.get("sort_order", 0) or 0),
                            str(body.get("seo_title_ar", "")).strip(),
                            str(body.get("seo_title_en", "")).strip(),
                            str(body.get("seo_desc_ar", "")).strip(),
                            str(body.get("seo_desc_en", "")).strip(),
                        ),
                    )
                    app.log_activity(conn, user, "project_created", "project", str(cur.lastrowid), title_ar)
                    conn.commit()
                    self.send_json(201, {"id": cur.lastrowid, "slug": slug})
                    return

                if path == "/api/admin/services":
                    title_ar = str(body.get("title_ar", "")).strip()
                    if not title_ar:
                        self.send_json(400, {"error": "Arabic service title required"})
                        return
                    slug = str(body.get("slug", "")).strip() or slugify(body.get("title_en") or title_ar)
                    cur = conn.execute(
                        """
                        INSERT INTO services (
                            slug, title_ar, title_en, short_desc_ar, short_desc_en,
                            full_desc_ar, full_desc_en, features_ar, features_en,
                            icon, cta_label_ar, cta_label_en, is_published, sort_order
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            slug,
                            title_ar,
                            str(body.get("title_en", "")).strip(),
                            str(body.get("short_desc_ar", "")).strip(),
                            str(body.get("short_desc_en", "")).strip(),
                            str(body.get("full_desc_ar", "")).strip(),
                            str(body.get("full_desc_en", "")).strip(),
                            json.dumps(body.get("features_ar", []), ensure_ascii=False),
                            json.dumps(body.get("features_en", []), ensure_ascii=False),
                            str(body.get("icon", "sparkles")).strip(),
                            str(body.get("cta_label_ar", "اطلب هذه الخدمة")).strip(),
                            str(body.get("cta_label_en", "Request This Service")).strip(),
                            1 if body.get("is_published", True) else 0,
                            int(body.get("sort_order", 0) or 0),
                        ),
                    )
                    app.log_activity(conn, user, "service_created", "service", str(cur.lastrowid), title_ar)
                    conn.commit()
                    self.send_json(201, {"id": cur.lastrowid})
                    return

                m_note = re.match(r"^/api/admin/leads/(\d+)/notes$", path)
                if m_note:
                    lead_id = int(m_note.group(1))
                    note_txt = str(body.get("note", "")).strip()
                    if not note_txt:
                        self.send_json(400, {"error": "Note text required"})
                        return
                    cur = conn.execute(
                        "INSERT INTO lead_notes (lead_id, author_id, author_name, note) VALUES (?, ?, ?, ?)",
                        (lead_id, user["id"], user["full_name"], note_txt),
                    )
                    app.log_activity(conn, user, "lead_note_added", "lead", str(lead_id), "Added internal note")
                    conn.commit()
                    self.send_json(201, {"id": cur.lastrowid})
                    return

                if path == "/api/admin/media":
                    b64_data = str(body.get("data_base64", "")).strip()
                    display_name = str(body.get("display_name", "upload")).strip()
                    if not b64_data:
                        self.send_json(400, {"error": "data_base64 is required"})
                        return
                    if "," in b64_data:
                        b64_data = b64_data.split(",", 1)[1]
                    try:
                        raw = base64.b64decode(b64_data)
                    except Exception:
                        self.send_json(400, {"error": "Invalid base64 encoding"})
                        return
                    detected_mime = detect_magic_mime(raw)
                    if detected_mime in ALLOWED_IMAGE_MIMES:
                        if len(raw) > MAX_IMAGE_BYTES:
                            self.send_json(400, {"error": "Image exceeds 10MB limit"})
                            return
                        ext = ALLOWED_IMAGE_MIMES[detected_mime]
                        kind = "image"
                    elif detected_mime in ALLOWED_VIDEO_MIMES:
                        if len(raw) > MAX_VIDEO_BYTES:
                            self.send_json(400, {"error": "Video exceeds 50MB limit"})
                            return
                        ext = ALLOWED_VIDEO_MIMES[detected_mime]
                        kind = "video"
                    else:
                        self.send_json(400, {"error": "Unsupported or invalid file content (allowed: JPG, PNG, WebP, MP4, WebM)"})
                        return
                    filename = f"{int(time.time())}_{secrets.token_hex(6)}{ext}"
                    (app.upload_dir / filename).write_bytes(raw)
                    url = f"/uploads/{filename}"
                    cur = conn.execute(
                        """
                        INSERT INTO media_assets (filename, display_name, url, mime_type, media_kind, size_bytes, alt_text_ar, alt_text_en, uploaded_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            filename,
                            display_name,
                            url,
                            detected_mime,
                            kind,
                            len(raw),
                            str(body.get("alt_text_ar", "")).strip(),
                            str(body.get("alt_text_en", "")).strip(),
                            user["id"],
                        ),
                    )
                    app.log_activity(conn, user, "media_uploaded", "media", str(cur.lastrowid), filename)
                    conn.commit()
                    self.send_json(201, {"id": cur.lastrowid, "url": url, "mime_type": detected_mime, "size_bytes": len(raw)})
                    return

                self.send_json(404, {"error": "Not found"})
            finally:
                conn.close()

        # ---------------- Admin PUT ----------------
        def handle_admin_put(self, path: str) -> None:
            conn = app.connect()
            try:
                if path == "/api/admin/settings":
                    user = self.require_role(conn, ("Super Admin",))
                    if not user:
                        return
                    body = self.read_json_body()
                    if body is None:
                        return
                    for k, v in body.items():
                        conn.execute(
                            "INSERT INTO site_settings (setting_key, setting_value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = datetime('now')",
                            (str(k), str(v)),
                        )
                    app.log_activity(conn, user, "settings_updated", "settings", "global", "Updated site settings")
                    conn.commit()
                    self.send_json(200, {"ok": True})
                    return

                user = self.require_role(conn, ("Super Admin", "Editor"))
                if not user:
                    return
                body = self.read_json_body()
                if body is None:
                    return

                m_proj = re.match(r"^/api/admin/projects/(\d+)$", path)
                if m_proj:
                    pid = int(m_proj.group(1))
                    if "video_url" in body and not validate_video_embed_url(str(body["video_url"])):
                        self.send_json(400, {"error": "Invalid video URL"})
                        return
                    existing = conn.execute("SELECT * FROM projects WHERE id = ?", (pid,)).fetchone()
                    if not existing:
                        self.send_json(404, {"error": "Project not found"})
                        return
                    fields = [
                        "title_ar", "title_en", "client_name", "category", "industry",
                        "short_desc_ar", "short_desc_en", "full_desc_ar", "full_desc_en",
                        "goal_ar", "goal_en", "result_ar", "result_en",
                        "cover_image", "video_url", "project_date", "status",
                        "seo_title_ar", "seo_title_en", "seo_desc_ar", "seo_desc_en",
                    ]
                    updates = []
                    params = []
                    for f in fields:
                        if f in body:
                            updates.append(f"{f} = ?")
                            params.append(str(body[f]).strip())
                    if "services_used" in body:
                        updates.append("services_used = ?")
                        params.append(json.dumps(body["services_used"], ensure_ascii=False))
                    if "is_featured" in body:
                        updates.append("is_featured = ?")
                        params.append(1 if body["is_featured"] else 0)
                    if "sort_order" in body:
                        updates.append("sort_order = ?")
                        params.append(int(body["sort_order"] or 0))
                    if updates:
                        updates.append("updated_at = datetime('now')")
                        params.append(pid)
                        conn.execute(f"UPDATE projects SET {', '.join(updates)} WHERE id = ?", params)
                        app.log_activity(conn, user, "project_updated", "project", str(pid), f"Updated project #{pid}")
                        conn.commit()
                    self.send_json(200, {"ok": True})
                    return

                m_srv = re.match(r"^/api/admin/services/(\d+)$", path)
                if m_srv:
                    sid = int(m_srv.group(1))
                    updates, params = [], []
                    for f in ("title_ar", "title_en", "short_desc_ar", "short_desc_en", "full_desc_ar", "full_desc_en", "icon", "cta_label_ar", "cta_label_en"):
                        if f in body:
                            updates.append(f"{f} = ?")
                            params.append(str(body[f]).strip())
                    for jf in ("features_ar", "features_en"):
                        if jf in body:
                            updates.append(f"{jf} = ?")
                            params.append(json.dumps(body[jf], ensure_ascii=False))
                    if "is_published" in body:
                        updates.append("is_published = ?")
                        params.append(1 if body["is_published"] else 0)
                    if "sort_order" in body:
                        updates.append("sort_order = ?")
                        params.append(int(body["sort_order"] or 0))
                    if updates:
                        updates.append("updated_at = datetime('now')")
                        params.append(sid)
                        conn.execute(f"UPDATE services SET {', '.join(updates)} WHERE id = ?", params)
                        app.log_activity(conn, user, "service_updated", "service", str(sid), f"Updated service #{sid}")
                        conn.commit()
                    self.send_json(200, {"ok": True})
                    return

                m_lead = re.match(r"^/api/admin/leads/(\d+)$", path)
                if m_lead:
                    lid = int(m_lead.group(1))
                    status = str(body.get("status", "")).strip()
                    if status and status not in ("new", "contacted", "meeting", "proposal_sent", "won", "closed"):
                        self.send_json(400, {"error": "Invalid lead status"})
                        return
                    if status:
                        conn.execute(
                            "UPDATE leads SET status = ?, last_contacted_at = datetime('now'), updated_at = datetime('now') WHERE id = ?",
                            (status, lid),
                        )
                        app.log_activity(conn, user, "lead_status_updated", "lead", str(lid), f"Status -> {status}")
                        conn.commit()
                    self.send_json(200, {"ok": True})
                    return

                m_cms = re.match(r"^/api/admin/cms/([a-zA-Z0-9_-]+)$", path)
                if m_cms:
                    page_key = m_cms.group(1)
                    conn.execute(
                        """
                        INSERT INTO site_pages (page_key, content_ar, content_en, updated_at)
                        VALUES (?, ?, ?, datetime('now'))
                        ON CONFLICT(page_key) DO UPDATE SET
                            content_ar = excluded.content_ar,
                            content_en = excluded.content_en,
                            updated_at = datetime('now')
                        """,
                        (
                            page_key,
                            json.dumps(body.get("ar", {}), ensure_ascii=False),
                            json.dumps(body.get("en", {}), ensure_ascii=False),
                        ),
                    )
                    app.log_activity(conn, user, "cms_updated", "site_page", page_key, f"Updated CMS page {page_key}")
                    conn.commit()
                    self.send_json(200, {"ok": True})
                    return

                self.send_json(404, {"error": "Not found"})
            finally:
                conn.close()

        # ---------------- Admin DELETE ----------------
        def handle_admin_delete(self, path: str) -> None:
            conn = app.connect()
            try:
                user = self.require_role(conn, ("Super Admin", "Editor"))
                if not user:
                    return

                m_proj = re.match(r"^/api/admin/projects/(\d+)$", path)
                if m_proj:
                    pid = int(m_proj.group(1))
                    conn.execute("DELETE FROM projects WHERE id = ?", (pid,))
                    app.log_activity(conn, user, "project_deleted", "project", str(pid), f"Deleted project #{pid}")
                    conn.commit()
                    self.send_json(200, {"ok": True})
                    return

                m_srv = re.match(r"^/api/admin/services/(\d+)$", path)
                if m_srv:
                    sid = int(m_srv.group(1))
                    conn.execute("DELETE FROM services WHERE id = ?", (sid,))
                    app.log_activity(conn, user, "service_deleted", "service", str(sid), f"Deleted service #{sid}")
                    conn.commit()
                    self.send_json(200, {"ok": True})
                    return

                m_media = re.match(r"^/api/admin/media/(\d+)$", path)
                if m_media:
                    mid = int(m_media.group(1))
                    asset = conn.execute("SELECT * FROM media_assets WHERE id = ?", (mid,)).fetchone()
                    if not asset:
                        self.send_json(404, {"error": "Media not found"})
                        return
                    in_use = conn.execute(
                        "SELECT id FROM projects WHERE status = 'published' AND cover_image = ?",
                        (asset["url"],),
                    ).fetchone()
                    if in_use:
                        self.send_json(409, {"error": "Media is used by a published project"})
                        return
                    fpath = app.upload_dir / asset["filename"]
                    if fpath.is_file():
                        fpath.unlink()
                    conn.execute("DELETE FROM media_assets WHERE id = ?", (mid,))
                    app.log_activity(conn, user, "media_deleted", "media", str(mid), asset["filename"])
                    conn.commit()
                    self.send_json(200, {"ok": True})
                    return

                self.send_json(404, {"error": "Not found"})
            finally:
                conn.close()

    return Handler


def run_server() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    db_path = Path(os.environ.get("DB_PATH", BASE_DIR / "data" / "portfolio.db"))
    upload_dir = Path(os.environ.get("UPLOAD_DIR", BASE_DIR / "uploads"))
    app = PortfolioApp(db_path=db_path, upload_dir=upload_dir)
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    print(f"Sorour Mohamed Portfolio running at http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    run_server()
