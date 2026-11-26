#!/usr/bin/env python3
"""Database migration & initial seed script for Sorour Mohamed Portfolio."""

import hashlib
import json
import os
import secrets
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MIGRATION_FILE = BASE_DIR / "migrations" / "001_init.sql"


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120_000,
    ).hex()
    return digest, salt


def init_db(db_path: str | Path | None = None) -> tuple[Path, str | None]:
    path = Path(db_path or os.environ.get("DB_PATH", BASE_DIR / "data" / "portfolio.db"))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")

    with open(MIGRATION_FILE, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    # 1. Roles
    roles = [
        ("Super Admin", "Full system access including users, roles, and settings."),
        ("Editor", "Can manage projects, services, leads, CMS pages, and media."),
        ("Viewer", "Read-only access to dashboard analytics, projects, and leads."),
    ]
    for name, desc in roles:
        conn.execute(
            "INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)",
            (name, desc),
        )

    # 2. Initial Super Admin (from env or generated once)
    generated_password = None
    existing_admin = conn.execute("SELECT id FROM admin_users LIMIT 1").fetchone()
    if not existing_admin:
        super_role = conn.execute(
            "SELECT id FROM roles WHERE name = 'Super Admin'"
        ).fetchone()
        admin_name = os.environ.get("ADMIN_NAME", "Sorour Mohamed")
        admin_email = os.environ.get("ADMIN_EMAIL", "admin@sorourmohamed.com").strip().lower()
        admin_pw = os.environ.get("ADMIN_PASSWORD", "").strip()
        if not admin_pw or admin_pw == "CHANGE_ME_STRONG_INITIAL_PASSWORD":
            admin_pw = secrets.token_urlsafe(14)
            generated_password = admin_pw
        pw_hash, pw_salt = hash_password(admin_pw)
        conn.execute(
            """
            INSERT INTO admin_users (role_id, full_name, email, password_hash, password_salt, is_active, must_change_password)
            VALUES (?, ?, ?, ?, ?, 1, 1)
            """,
            (super_role["id"], admin_name, admin_email, pw_hash, pw_salt),
        )

    # 3. Services (8 core services from Brief Section 3)
    if conn.execute("SELECT COUNT(*) FROM services").fetchone()[0] == 0:
        services_seed = [
            (
                "commercial-video-production",
                "إنتاج الفيديوهات الإعلانية",
                "Commercial Video Production",
                "إنتاج فيديوهات إعلانية احترافية تعكس هوية العلامة التجارية وتبرز تفاصيل المنتج.",
                "Professional commercial video production tailored to showcase brand identity and product details.",
                "نعمل على تخطيط وتصوير وإخراج الفيديوهات الإعلانية بدءاً من الفكرة والسيناريو وحتى التسليم النهائي بمقاسات مناسبة لمنصات العرض والإعلانات.",
                "End-to-end commercial video planning, directing, and production formatted for social platforms and ad campaigns.",
                json.dumps(["تطوير الفكرة والسيناريو", "تصوير احترافي بزاويا إعلانية", "مقاسات 16:9 و 9:16 جاهزة للنشر"], ensure_ascii=False),
                json.dumps(["Concept & script development", "Commercial studio & location shooting", "Ready-to-publish 16:9 & 9:16 masters"]),
                "film",
                1,
            ),
            (
                "product-photography",
                "تصوير المنتجات",
                "Product Photography",
                "صور منتجات نظيفة وجذابة تبرز الخامة والتفاصيل وتناسب المتاجر والسوشيال ميديا.",
                "Clean, studio-grade product photography highlighting textures and details for e-commerce and social media.",
                "جلسات تصوير منتجات وإضاءة مدروسة مع معالجة ألوان احترافية تحافظ على الشكل الحقيقي للمنتج وتزيد من جاذبيته للعميل.",
                "Controlled studio lighting and refined color retouching that preserve true product details while elevating brand perception.",
                json.dumps(["تصوير ستوديو ولايف ستايل", "تعديل ألوان وإضاءة دقيقة", "تسليم بجودة عالية للويب والطباعة"], ensure_ascii=False),
                json.dumps(["Studio & lifestyle compositions", "Accurate color grading & retouching", "High-res web & print exports"]),
                "camera",
                2,
            ),
            (
                "video-editing-post-production",
                "مونتاج الفيديوهات وما بعد الإنتاج",
                "Video Editing & Post-production",
                "مونتاج ديناميكي، تصحيح ألوان سينمائي، ومؤثرات صوتية ترفع جودة الفيديو.",
                "Dynamic editing, cinematic color grading, and crisp sound design that elevate raw footage.",
                "تحويل اللقطات الخام إلى فيديوهات إعلانية متماسكة بإيقاع سريع، تثبيت صورة، تصحيح ألوان، ومكساج صوتي احترافي.",
                "Turning raw footage into cohesive edits with pacing, stabilization, cinematic grading, and audio polish.",
                json.dumps(["تقطيع وإيقاع إعلاني", "تصحيح ألوان سينمائي", "معالجة صوت وإضافة عناوين"], ensure_ascii=False),
                json.dumps(["Ad-ready pacing & structure", "Cinematic color grading", "Audio cleanup & motion titles"]),
                "scissors",
                3,
            ),
            (
                "creative-content-creation",
                "صناعة المحتوى الإبداعي",
                "Creative Content Creation",
                "أفكار محتوى مبتكرة وكاروسيل وريلز تناسب جمهورك المستهدف.",
                "Original content concepts, storytelling carousels, and short-form Reels built for audience engagement.",
                "صياغة أفكار محتوى متجددة وكتابة نصوص إبداعية وتنفيذ ريلز وكاروسيل يعبر عن شخصية البراند.",
                "Developing repeatable content pillars, copywriting, and visual formats aligned with your brand voice.",
                json.dumps(["كتابة أفكار وسكريبتات", "تصميم كاروسيل قصصي", "محتوى ريلز وتيك توك"], ensure_ascii=False),
                json.dumps(["Creative concepts & scripts", "Storytelling carousels", "Reels & TikTok content"]),
                "sparkles",
                4,
            ),
            (
                "social-media-management",
                "إدارة صفحات التواصل الاجتماعي",
                "Social Media Management",
                "تنظيم خطط النشر الشهرية، تنسيق المظهر العام للصفحات، ومتابعة الأداء.",
                "Monthly content calendars, cohesive feed curation, and consistent page management.",
                "إدارة متكاملة لحسابات العلامة التجارية تشمل خطة المحتوى، الجدولة، تنسيق الهوية البصرية، وتقارير الأداء الدورية.",
                "Structured page operations covering planning, scheduling, visual consistency, and regular performance reviews.",
                json.dumps(["خطة محتوى شهرية منظمة", "توحيد الهوية البصرية للصفحة", "متابعة وتحليل الأداء"], ensure_ascii=False),
                json.dumps(["Monthly content calendar", "Cohesive feed aesthetics", "Ongoing performance tracking"]),
                "share-2",
                5,
            ),
            (
                "paid-advertising",
                "إعداد وإدارة الحملات الإعلانية الممولة",
                "Paid Advertising",
                "إعداد الحملات الممولة واختبار المواد الإعلانية للوصول للجمهور المناسب.",
                "Structured paid campaign setup and creative testing to reach qualified audiences.",
                "إعداد وهيكلة الحملات الإعلانية على منصات التواصل، اختبار الزوايا الإعلانية، وتحسين الميزانية بناءً على البيانات الفعلية.",
                "Campaign structuring, audience targeting, creative A/B testing, and data-driven optimization.",
                json.dumps(["تجهيز وهيكلة الحملات", "اختبار المواد الإعلانية", "تحليل وتقارير دورية"], ensure_ascii=False),
                json.dumps(["Campaign architecture setup", "Ad creative testing", "Periodic performance reporting"]),
                "trending-up",
                6,
            ),
            (
                "graphic-social-design",
                "تصميمات السوشيال ميديا والمواد البصرية",
                "Graphic & Social Design",
                "تصاميم إعلانية، منيو، كوفرات، ومواد بصرية متسقة مع هوية العلامة.",
                "Cohesive social media visuals, menus, covers, and campaign graphics aligned with your brand.",
                "تصميم البوستات الإعلانية، أغلفة المنصات، وقوائم المنتجات بأسلوب عصري واضح وسهل القراءة على الهاتف.",
                "Ad creatives, profile covers, print menus, and digital assets designed for clarity on mobile and desktop.",
                json.dumps(["بوستات وحملات سوشيال ميديا", "تصميم منيو وبروشور", "قوالب بصرية متناسقة"], ensure_ascii=False),
                json.dumps(["Social campaign graphics", "Menus & print layouts", "Consistent visual templates"]),
                "palette",
                7,
            ),
            (
                "ai-powered-visual-production",
                "إنتاج بصري مدعوم بأدوات الذكاء الاصطناعي",
                "AI-powered Visual Production",
                "دمج الأدوات الحديثة لتطوير مشاهد إعلانية ومفاهيم بصرية سريعة التنفيذ.",
                "Combining modern AI visual workflows with art direction for rapid commercial concepts and scenes.",
                "توظيف أدوات الإنتاج البصري الحديثة لتوليد مشاهد إعلانية وخلفيات متقنة مع الحفاظ الدقيق على هوية المنتج الأصلي.",
                "Art-directed AI-assisted scenes and product environments that preserve real product details.",
                json.dumps(["مشاهد إعلانية مبتكرة", "الحفاظ على تفاصيل المنتج", "سرعة تنفيذ واختبار الأفكار"], ensure_ascii=False),
                json.dumps(["Custom commercial scenes", "Authentic product fidelity", "Rapid concept iteration"]),
                "cpu",
                8,
            ),
        ]
        for s in services_seed:
            conn.execute(
                """
                INSERT INTO services (
                    slug, title_ar, title_en, short_desc_ar, short_desc_en,
                    full_desc_ar, full_desc_en, features_ar, features_en, icon, sort_order
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                s,
            )

    # 4. Initial Sample Draft Projects (Al Andalus Coffee & Clear Eyewear per Brief Section 3)
    if conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 0:
        projects_seed = [
            (
                "al-andalus-coffee",
                "مطحن الأندلس — محتوى وتصوير وإعلانات لمنتجات البن",
                "Al Andalus Coffee — Content, Photography & Ads",
                "Al Andalus Coffee (نموذج مبدئي قابل للتعديل)",
                "photography",
                "الأغذية والمشروبات",
                "محتوى وتصوير وإعلانات لمنتجات البن بروح بصرية فاخرة تجمع بين التفاصيل الأصيلة والعرض العصري.",
                "Content, product photography, and ad visuals for specialty coffee blends.",
                "مشروع تجريبي مبدئي لعرض هيكل دراسة الحالة: يشمل تصوير عبوات البن، تحسين صور المحل، تصميم المنيو، ومحتوى السوشيال ميديا. يرجى استبدال الملفات بالمواد الحقيقية قبل النشر.",
                "Editable starter case study covering coffee packaging photography, shop visuals, menu design, and social content. Replace with approved real media before publishing.",
                "تقديم منتجات البن بصورة احترافية موحدة تعكس جودة التحميص وتسهل عرض الأصناف للعملاء.",
                "Present coffee products with a unified visual identity that highlights roast quality.",
                "يتم إضافة النتائج الموثقة فقط بعد اعتمادها من صاحب المشروع.",
                "Verified results will be added only once confirmed by the project owner.",
                json.dumps(["تصوير المنتجات", "تصميمات السوشيال ميديا", "صناعة المحتوى الإبداعي"], ensure_ascii=False),
                "",
                "",
                "2026-11",
                "draft",
                1,
                1,
            ),
            (
                "clear-eyewear",
                "Clear Eyewear — محتوى وعروض وإعلانات للنظارات",
                "Clear Eyewear — Content, Offers & Ads",
                "Clear Eyewear (نموذج مبدئي قابل للتعديل)",
                "video",
                "الأزياء والنظارات",
                "محتوى بصري وعروض وإعلانات لنظارات عصرية مع تركيز على التفاصيل والإضاءة الهادئة.",
                "Visual content, promotional offers, and ad creatives for modern eyewear.",
                "مشروع تجريبي مبدئي لعرض هيكل دراسة الحالة لقطاع النظارات: يشمل تصوير المنتجات، ريلز العروض، وتصاميم الحملات الممولة. يرجى رفع الملفات الحقيقية قبل النشر.",
                "Editable starter case study for eyewear campaigns: product photography, promotional Reels, and ad creatives. Upload approved files before publishing.",
                "إبراز تصميم الإطارات والعدسات بشكل واضح وجذاب يدعم الحملات الترويجية.",
                "Highlight frame craftsmanship and lens clarity to support promotional campaigns.",
                "يتم إضافة النتائج الموثقة فقط بعد اعتمادها من صاحب المشروع.",
                "Verified results will be added only once confirmed by the project owner.",
                json.dumps(["إنتاج الفيديوهات الإعلانية", "تصوير المنتجات", "إدارة الحملات الإعلانية"], ensure_ascii=False),
                "",
                "",
                "2026-11",
                "draft",
                1,
                2,
            ),
        ]
        for p in projects_seed:
            conn.execute(
                """
                INSERT INTO projects (
                    slug, title_ar, title_en, client_name, category, industry,
                    short_desc_ar, short_desc_en, full_desc_ar, full_desc_en,
                    goal_ar, goal_en, result_ar, result_en, services_used,
                    cover_image, video_url, project_date, status, is_featured, sort_order
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                p,
            )

    # 5. CMS Site Pages (Bilingual AR/EN using Brief Section 10 starter copy)
    if conn.execute("SELECT COUNT(*) FROM site_pages").fetchone()[0] == 0:
        pages_seed = [
            (
                "home",
                json.dumps(
                    {
                        "brand_name": "SOROUR MOHAMED",
                        "tagline": "WE CREATE WHAT YOU IMAGINE",
                        "hero_title": "نحول أفكارك إلى محتوى بصري يلفت الانتباه.",
                        "hero_subtitle": "في Sorour Mohamed بنقدم حلولاً إبداعية متكاملة للعلامات التجارية، من الفكرة والتصوير والإنتاج إلى صناعة المحتوى وإدارة الحملات الرقمية.",
                        "primary_cta": "ابدأ مشروعك",
                        "secondary_cta": "شاهد أعمالنا",
                        "trust_label": "القطاعات التي نعمل معها",
                        "sectors": ["المطاعم والكافيهات", "النظارات والأزياء", "العلامات التجارية المحلية", "المتاجر الإلكترونية", "الخدمات والشركات"],
                        "why_title": "لماذا Sorour Mohamed؟",
                        "why_items": [
                            {"title": "رؤية إبداعية متكاملة", "desc": "نجمع بين الفكرة والتصوير والمونتاج والتسويق في مكان واحد لضمان اتساق الهوية."},
                            {"title": "جودة بصرية تناسب المنصات", "desc": "إنتاج مصمم خصيصاً لسرعة جذب الانتباه على الهاتف ومنصات التواصل."},
                            {"title": "التزام ووضوح في التنفيذ", "desc": "خطوات عمل منظمة ومواعيد تسليم واضحة بدون تعقيد."}
                        ],
                        "process_steps": [
                            {"step": "01", "title": "اكتشاف الفكرة", "desc": "فهم البراند، الجمهور، والهدف من الحملة أو المحتوى."},
                            {"step": "02", "title": "التخطيط", "desc": "كتابة السيناريو وتحديد الاتجاه البصري ومقاسات العرض."},
                            {"step": "03", "title": "الإنتاج", "desc": "التصوير أو التصميم وتنفيذ المواد البصرية بأعلى جودة."},
                            {"step": "04", "title": "المونتاج", "desc": "التحرير، تصحيح الألوان، ومعالجة الصوت والمراجعة."},
                            {"step": "05", "title": "التسليم والنشر", "desc": "تسليم الملفات النهائية جاهزة للنشر والإعلانات."}
                        ]
                    },
                    ensure_ascii=False,
                ),
                json.dumps(
                    {
                        "brand_name": "SOROUR MOHAMED",
                        "tagline": "WE CREATE WHAT YOU IMAGINE",
                        "hero_title": "Turning Your Ideas Into High-Impact Visual Content.",
                        "hero_subtitle": "At Sorour Mohamed, we deliver integrated creative solutions for brands — from concept, photography, and video production to content creation and digital campaigns.",
                        "primary_cta": "Start Your Project",
                        "secondary_cta": "View Our Work",
                        "trust_label": "Industries We Serve",
                        "sectors": ["Cafes & Food Brands", "Eyewear & Fashion", "Local Brands", "E-Commerce Stores", "Services & Businesses"],
                        "why_title": "Why Sorour Mohamed?",
                        "why_items": [
                            {"title": "Unified Creative Direction", "desc": "Concept, production, post-production, and digital marketing aligned under one roof."},
                            {"title": "Platform-Ready Quality", "desc": "Visuals crafted to capture attention cleanly across mobile feeds and campaigns."},
                            {"title": "Structured & Reliable", "desc": "Transparent milestones, clear communication, and on-time delivery."}
                        ],
                        "process_steps": [
                            {"step": "01", "title": "Discovery", "desc": "Understanding your brand, audience, and core objective."},
                            {"step": "02", "title": "Planning", "desc": "Scripting, visual direction, and format planning."},
                            {"step": "03", "title": "Production", "desc": "Shooting, designing, and producing core visual assets."},
                            {"step": "04", "title": "Post-Production", "desc": "Editing, color grading, sound design, and review."},
                            {"step": "05", "title": "Delivery & Launch", "desc": "Delivering polished masters ready for publishing and ads."}
                        ]
                    },
                    ensure_ascii=False,
                ),
            ),
            (
                "about",
                json.dumps(
                    {
                        "headline": "من نحن",
                        "intro": "Sorour Mohamed فريق إنتاج إبداعي يساعد العلامات التجارية على تقديم منتجاتها وخدماتها بصورة احترافية من خلال الفيديو والتصوير والمحتوى والحلول الرقمية.",
                        "founder_name": "Sorour Mohamed",
                        "founder_role": "Creative Content & Digital Marketing Specialist",
                        "founder_bio": "متخصص في صناعة المحتوى البصري والتسويق الرقمي، يركز على بناء حضور بصري متناسق وعملي للعلامات التجارية.",
                        "values": [
                            {"title": "الفكرة أولاً", "desc": "كل قطعة محتوى تبدأ برسالة واضحة تخدم هدف البراند."},
                            {"title": "الجودة والاتقان", "desc": "اهتمام بأدق تفاصيل الإضاءة والألوان والتكوين."},
                            {"title": "فهم هوية العميل", "desc": "تصميم حلول تناسب طبيعة كل علامة تجارية بدون قوالب مكررة."}
                        ],
                        "team": []
                    },
                    ensure_ascii=False,
                ),
                json.dumps(
                    {
                        "headline": "About Us",
                        "intro": "Sorour Mohamed is a creative production studio helping brands present their products and services professionally through video, photography, content, and digital solutions.",
                        "founder_name": "Sorour Mohamed",
                        "founder_role": "Creative Content & Digital Marketing Specialist",
                        "founder_bio": "Focused on creative visual storytelling and digital marketing that helps brands stand out cleanly and consistently.",
                        "values": [
                            {"title": "Idea First", "desc": "Every visual starts with a clear message aligned to brand goals."},
                            {"title": "Craft & Quality", "desc": "Careful attention to lighting, color, pacing, and composition."},
                            {"title": "Brand Understanding", "desc": "Tailored solutions built around each client's distinct identity."}
                        ],
                        "team": []
                    },
                    ensure_ascii=False,
                ),
            ),
            (
                "legal",
                json.dumps(
                    {
                        "privacy_title": "سياسة الخصوصية",
                        "privacy_body": "نجمع البيانات التي تدخلها طوعاً في نموذج التواصل (مثل الاسم، اسم النشاط، رقم الهاتف أو واتساب، والبريد الإلكتروني وتفاصيل المشروع) فقط لغرض الرد على استفسارك وتقديم عرض مناسب لمشروعك. لا نبيع أو نشارك بياناتك مع أي طرف ثالث، ولا نعرض بيانات العملاء أو ملاحظاتهم الداخلية على الواجهة العامة للموقع.",
                        "terms_title": "الشروط والأحكام",
                        "terms_body": "جميع المواد البصرية والنصوص المعروضة في هذا الموقع مملوكة لـ Sorour Mohamed أو للعملاء المذكورين بإذنهم. يتم الاتفاق على نطاق العمل والمواعيد والتكلفة لكل مشروع بشكل منفصل وواضح قبل بدء التنفيذ."
                    },
                    ensure_ascii=False,
                ),
                json.dumps(
                    {
                        "privacy_title": "Privacy Policy",
                        "privacy_body": "We collect only the details you voluntarily submit through the contact form (name, business name, phone/WhatsApp, email, and project details) solely to respond to your inquiry and prepare a proposal. We never sell your information or display private client leads on the public website.",
                        "terms_title": "Terms & Conditions",
                        "terms_body": "All visual materials and copy showcased on this site belong to Sorour Mohamed or are displayed with client permission. Scope, timelines, and pricing are agreed upon separately before production begins."
                    },
                    ensure_ascii=False,
                ),
            ),
        ]
        for key, ar_json, en_json in pages_seed:
            conn.execute(
                "INSERT INTO site_pages (page_key, content_ar, content_en) VALUES (?, ?, ?)",
                (key, ar_json, en_json),
            )

    # 6. Site Settings
    settings_seed = [
        ("site_name", "Sorour Mohamed — Creative Production Studio", 1),
        ("tagline", "WE CREATE WHAT YOU IMAGINE", 1),
        ("default_language", "ar", 1),
        ("accent_color", "#D5A34A", 1),
        ("contact_email", "", 1),
        ("whatsapp_number", os.environ.get("WHATSAPP_NUMBER", ""), 1),
        ("location_ar", "مصر", 1),
        ("location_en", "Egypt", 1),
        ("social_instagram", "", 1),
        ("social_facebook", "", 1),
        ("social_tiktok", "", 1),
        ("social_youtube", "", 1),
        ("seo_title_ar", "Sorour Mohamed | صناعة المحتوى والتسويق الرقمي", 1),
        ("seo_title_en", "Sorour Mohamed | Creative Content & Digital Marketing", 1),
        ("seo_desc_ar", "حلول إبداعية متكاملة للعلامات التجارية: إنتاج الفيديو، تصوير المنتجات، صناعة المحتوى، وإدارة الحملات الرقمية.", 1),
        ("seo_desc_en", "Integrated creative production studio for brands: commercial video, product photography, content creation, and paid campaigns.", 1),
        ("ga_measurement_id", os.environ.get("GA_MEASUREMENT_ID", ""), 0),
        ("meta_pixel_id", os.environ.get("META_PIXEL_ID", ""), 0),
    ]
    for k, v, is_pub in settings_seed:
        conn.execute(
            "INSERT OR IGNORE INTO site_settings (setting_key, setting_value, is_public) VALUES (?, ?, ?)",
            (k, v, is_pub),
        )

    conn.commit()
    conn.close()
    return path, generated_password


if __name__ == "__main__":
    db_path, gen_pw = init_db()
    print(f"Database initialized at: {db_path}")
    if gen_pw:
        admin_email = os.environ.get("ADMIN_EMAIL", "admin@sorourmohamed.com")
        print("=" * 60)
        print("INITIAL SUPER ADMIN CREDENTIALS (CHANGE IMMEDIATELY):")
        print(f"  Email:    {admin_email}")
        print(f"  Password: {gen_pw}")
        print("=" * 60)
