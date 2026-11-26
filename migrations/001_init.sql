-- Sorour Mohamed — Personal Portfolio & Admin Dashboard
-- Migration 001: Core Schema (SQLite / PostgreSQL compatible types)

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_id INTEGER NOT NULL,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    last_login_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    title_ar TEXT NOT NULL,
    title_en TEXT NOT NULL DEFAULT '',
    client_name TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'video',
    industry TEXT NOT NULL DEFAULT '',
    short_desc_ar TEXT NOT NULL DEFAULT '',
    short_desc_en TEXT NOT NULL DEFAULT '',
    full_desc_ar TEXT NOT NULL DEFAULT '',
    full_desc_en TEXT NOT NULL DEFAULT '',
    goal_ar TEXT NOT NULL DEFAULT '',
    goal_en TEXT NOT NULL DEFAULT '',
    result_ar TEXT NOT NULL DEFAULT '',
    result_en TEXT NOT NULL DEFAULT '',
    services_used TEXT NOT NULL DEFAULT '[]',
    cover_image TEXT NOT NULL DEFAULT '',
    video_url TEXT NOT NULL DEFAULT '',
    project_date TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived', 'scheduled')),
    is_featured INTEGER NOT NULL DEFAULT 0,
    sort_order INTEGER NOT NULL DEFAULT 0,
    seo_title_ar TEXT NOT NULL DEFAULT '',
    seo_title_en TEXT NOT NULL DEFAULT '',
    seo_desc_ar TEXT NOT NULL DEFAULT '',
    seo_desc_en TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS project_media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    media_type TEXT NOT NULL CHECK (media_type IN ('image', 'video', 'embed')),
    url TEXT NOT NULL,
    aspect_ratio TEXT NOT NULL DEFAULT '16:9',
    caption_ar TEXT NOT NULL DEFAULT '',
    caption_en TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    title_ar TEXT NOT NULL,
    title_en TEXT NOT NULL DEFAULT '',
    short_desc_ar TEXT NOT NULL DEFAULT '',
    short_desc_en TEXT NOT NULL DEFAULT '',
    full_desc_ar TEXT NOT NULL DEFAULT '',
    full_desc_en TEXT NOT NULL DEFAULT '',
    features_ar TEXT NOT NULL DEFAULT '[]',
    features_en TEXT NOT NULL DEFAULT '[]',
    icon TEXT NOT NULL DEFAULT 'sparkles',
    cta_label_ar TEXT NOT NULL DEFAULT 'اطلب هذه الخدمة',
    cta_label_en TEXT NOT NULL DEFAULT 'Request This Service',
    cta_helper_ar TEXT NOT NULL DEFAULT '',
    cta_helper_en TEXT NOT NULL DEFAULT '',
    is_published INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    company TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    service_requested TEXT NOT NULL DEFAULT '',
    budget TEXT NOT NULL DEFAULT '',
    timeline TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'contact_form',
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'contacted', 'meeting', 'proposal_sent', 'won', 'closed')),
    assigned_to INTEGER,
    last_contacted_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (assigned_to) REFERENCES admin_users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS lead_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lead_id INTEGER NOT NULL,
    author_id INTEGER,
    author_name TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (lead_id) REFERENCES leads(id) ON DELETE CASCADE,
    FOREIGN KEY (author_id) REFERENCES admin_users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS site_pages (
    page_key TEXT PRIMARY KEY,
    content_ar TEXT NOT NULL DEFAULT '{}',
    content_en TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'published',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS site_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL DEFAULT '',
    is_public INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS media_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    display_name TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    mime_type TEXT NOT NULL,
    media_kind TEXT NOT NULL CHECK (media_kind IN ('image', 'video')),
    size_bytes INTEGER NOT NULL DEFAULT 0,
    width INTEGER,
    height INTEGER,
    alt_text_ar TEXT NOT NULL DEFAULT '',
    alt_text_en TEXT NOT NULL DEFAULT '',
    uploaded_by INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (uploaded_by) REFERENCES admin_users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    user_email TEXT NOT NULL DEFAULT 'system',
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_projects_status_order ON projects(status, sort_order);
CREATE INDEX IF NOT EXISTS idx_projects_category ON projects(category);
CREATE INDEX IF NOT EXISTS idx_leads_status_created ON leads(status, created_at);
CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_media_kind ON media_assets(media_kind);
