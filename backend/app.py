from gevent import monkey
monkey.patch_all()

import base64
import io
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import time
import secrets
import uuid
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

import anthropic
import requests
import stripe
from dotenv import load_dotenv
from flask import Flask, g, jsonify, render_template, request, session, send_from_directory, send_file
from flask_socketio import SocketIO, join_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import shipping

BASE_DIR = Path(__file__).resolve().parent
SITE_DIR = BASE_DIR.parent

DATA_DIR = Path(os.environ.get("DATA_DIR", str(SITE_DIR)))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "msaniihalisi.db"

load_dotenv(BASE_DIR / ".env")

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "").strip()
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "").strip()
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()
stripe.api_key = STRIPE_SECRET_KEY

# AI-assisted apparel descriptions (admin "Add Item" flow) -- gracefully degrades to
# manual entry when unset, see describe_apparel_image() below.
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()

IS_PRODUCTION = os.environ.get("FLASK_ENV", "development").strip().lower() == "production"

app = Flask(__name__, static_folder=str(SITE_DIR), static_url_path="")
app.secret_key = os.environ.get("MH_SECRET_KEY") or secrets.token_hex(32)
if IS_PRODUCTION and not os.environ.get("MH_SECRET_KEY"):
    raise RuntimeError(
        "Set MH_SECRET_KEY in backend/.env before running with FLASK_ENV=production — "
        "an auto-generated key would log every admin out on each restart/deploy."
    )
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    MAX_CONTENT_LENGTH=300 * 1024 * 1024,
)

# Pure signaling relay for live streaming (chat + WebRTC offer/answer/ICE forwarding) —
# the server never touches media, only forwards JSON between socket ids. See the
# "Socket.IO" section near the bottom of this file for the handlers.
socketio = SocketIO(app, async_mode="gevent", max_http_buffer_size=300 * 1024 * 1024)

VIDEOS_DIR = DATA_DIR / "videos"
VIDEOS_DIR.mkdir(exist_ok=True)
ALLOWED_VIDEO_EXTENSIONS = {"mp4", "mov", "m4v", "webm"}

AUDIO_DIR = DATA_DIR / "audio"
AUDIO_DIR.mkdir(exist_ok=True)
ALLOWED_AUDIO_EXTENSIONS = {"mp3", "wav", "m4a"}
MAX_AUDIO_BYTES = 60 * 1024 * 1024  # generous for a full song at a reasonable bitrate;
                                    # still well under the global 300MB request cap.
_AUDIO_EXT_TO_KIND = {"mp3": "mp3", "wav": "wav", "m4a": "m4a"}

ARTWORK_DIR = SITE_DIR / "images" / "artwork"
ARTWORK_DIR.mkdir(parents=True, exist_ok=True)

APPAREL_DIR = SITE_DIR / "images" / "apparel"
APPAREL_DIR.mkdir(parents=True, exist_ok=True)

ALBUMS_DIR = SITE_DIR / "images" / "albums"
ALBUMS_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "gif"}
MAX_IMAGE_BYTES = 8 * 1024 * 1024  # 8MB is plenty for a product photo; keeps this endpoint
                                    # from doubling as a general-purpose large-file upload.
_EXT_TO_KIND = {"jpg": "jpeg", "jpeg": "jpeg", "png": "png", "webp": "webp", "gif": "gif"}
_KIND_TO_MEDIA_TYPE = {
    "jpeg": "image/jpeg", "png": "image/png", "webp": "image/webp", "gif": "image/gif",
}


def _sniff_image_kind(header):
    """Cheap magic-byte check -- the actual defense against a renamed non-image file,
    since a client-supplied extension/Content-Type can't be trusted on its own."""
    if header[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if header[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if header[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "webp"
    return None


def _read_and_validate_image(file):
    """Validates an uploaded image (extension + size + magic-byte sniff).
    Returns (bytes, media_type, None) on success, or (None, None, (response, status)) on failure."""
    if not file or not file.filename:
        return None, None, (jsonify({"error": "No image file uploaded."}), 400)
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        return None, None, (jsonify({
            "error": f"Unsupported file type .{ext}. Allowed: {', '.join(sorted(ALLOWED_IMAGE_EXTENSIONS))}"
        }), 400)
    data = file.read()
    if len(data) > MAX_IMAGE_BYTES:
        return None, None, (jsonify({
            "error": f"That image is too large ({MAX_IMAGE_BYTES // (1024*1024)}MB limit)."
        }), 413)
    kind = _sniff_image_kind(data[:16])
    if not kind or kind != _EXT_TO_KIND.get(ext):
        return None, None, (jsonify({"error": "That file doesn't look like a valid image."}), 400)
    return data, _KIND_TO_MEDIA_TYPE[kind], None


def _sniff_audio_kind(header):
    """Cheap magic-byte check for uploaded audio -- mirrors _sniff_image_kind's rigor
    (a client-supplied extension/Content-Type can't be trusted on its own)."""
    if header[:3] == b"ID3":
        return "mp3"
    if len(header) >= 2 and header[0] == 0xFF and (header[1] & 0xE0) == 0xE0:
        return "mp3"  # MPEG audio frame sync, no ID3 tag present
    if header[:4] == b"RIFF" and header[8:12] == b"WAVE":
        return "wav"
    if header[4:8] == b"ftyp":
        return "m4a"  # ISO base media container box, used by m4a/mp4 family files
    return None


def _read_and_validate_audio(file):
    """Validates an uploaded song file (extension + size + magic-byte sniff),
    mirroring _read_and_validate_image's rigor for a different media type.
    Returns (bytes, None) on success, or (None, (response, status)) on failure."""
    if not file or not file.filename:
        return None, (jsonify({"error": "No audio file uploaded."}), 400)
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_AUDIO_EXTENSIONS:
        return None, (jsonify({
            "error": f"Unsupported file type .{ext}. Allowed: {', '.join(sorted(ALLOWED_AUDIO_EXTENSIONS))}"
        }), 400)
    data = file.read()
    if len(data) > MAX_AUDIO_BYTES:
        return None, (jsonify({
            "error": f"That audio file is too large ({MAX_AUDIO_BYTES // (1024*1024)}MB limit)."
        }), 413)
    kind = _sniff_audio_kind(data[:16])
    if not kind or kind != _AUDIO_EXT_TO_KIND.get(ext):
        return None, (jsonify({"error": "That file doesn't look like a valid audio file."}), 400)
    return data, None

_login_attempts = {}
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60


def _rate_limited(ip):
    count, first = _login_attempts.get(ip, (0, time.time()))
    if time.time() - first > WINDOW_SECONDS:
        _login_attempts[ip] = (0, time.time())
        return False
    return count >= MAX_ATTEMPTS


def _register_failure(ip):
    count, first = _login_attempts.get(ip, (0, time.time()))
    if time.time() - first > WINDOW_SECONDS:
        _login_attempts[ip] = (1, time.time())
    else:
        _login_attempts[ip] = (count + 1, first)


def _register_success(ip):
    _login_attempts.pop(ip, None)


def parse_price_to_cents(value):
    try:
        if isinstance(value, (int, float)):
            dollars = float(value)
        else:
            dollars = float(str(value).replace("$", "").replace(",", "").strip())
        if dollars < 0:
            return None
        return int(round(dollars * 100))
    except (ValueError, TypeError):
        return None


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


DEFAULT_MARQUEE_TEXT = (
    "Small-batch, made with intention · New pieces drop as they're ready · "
    "Find your frequency · Customize yours, no rush required"
)


def get_setting(key, default=""):
    conn = get_db()
    row = conn.execute("SELECT value FROM site_settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key, value):
    conn = get_db()
    conn.execute(
        "INSERT INTO site_settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()
    conn.close()


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tracks (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            artist TEXT NOT NULL,
            len TEXT NOT NULL,
            seconds INTEGER NOT NULL,
            src TEXT,
            type TEXT,
            embed_id TEXT,
            embed_url TEXT,
            artwork TEXT,
            sort_order INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS subscribers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            source TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS products (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            type_label TEXT NOT NULL,
            price TEXT NOT NULL,
            price_cents INTEGER NOT NULL DEFAULT 0,
            is_physical INTEGER NOT NULL DEFAULT 0,
            preview_track_id TEXT,
            sort_order INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS apparel (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price TEXT NOT NULL,
            price_cents INTEGER NOT NULL DEFAULT 0,
            image_path TEXT NOT NULL,
            sort_order INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            stripe_session_id TEXT UNIQUE,
            customer_email TEXT,
            items TEXT NOT NULL,
            amount_total INTEGER NOT NULL DEFAULT 0,
            currency TEXT NOT NULL DEFAULT 'usd',
            status TEXT NOT NULL DEFAULT 'pending',
            shipping_name TEXT,
            shipping_address TEXT,
            carrier TEXT,
            tracking_number TEXT,
            shipping_label_url TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS live_sessions (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            host_name TEXT NOT NULL DEFAULT '',
            room_code TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'scheduled',
            recording_path TEXT NOT NULL DEFAULT '',
            started_at TEXT,
            ended_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            live_session_id TEXT NOT NULL REFERENCES live_sessions(id),
            sender_name TEXT NOT NULL,
            message TEXT NOT NULL,
            sent_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS camera_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            live_session_id TEXT NOT NULL REFERENCES live_sessions(id),
            viewer_name TEXT NOT NULL,
            socket_id TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            requested_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        -- Analytics: one row per real page load. NOT written for API polling
        -- endpoints, static assets, or the analytics endpoints themselves, so
        -- this table reflects actual visits, not client "chatter".
        CREATE TABLE IF NOT EXISTS page_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            ip_address TEXT,
            country TEXT,
            city TEXT,
            device_type TEXT,
            browser TEXT,
            referrer TEXT,
            visitor_id TEXT,
            user_agent TEXT,
            is_bot INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_page_views_created_at ON page_views(created_at);
        CREATE INDEX IF NOT EXISTS idx_page_views_visitor ON page_views(visitor_id);

        -- Analytics: everything that isn't a page load -- track/video plays,
        -- apparel quick-view opens, checkout starts, and completed purchases
        -- (the last one written from the Stripe webhook, not the browser).
        CREATE TABLE IF NOT EXISTS analytics_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            item_id TEXT,
            item_label TEXT,
            visitor_id TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_analytics_events_type_item ON analytics_events(event_type, item_id);
        CREATE INDEX IF NOT EXISTS idx_analytics_events_created_at ON analytics_events(created_at);

        -- Small admin-editable key/value store for site copy that isn't tied to a
        -- specific product/track -- e.g. the scrolling announcement strip text.
        CREATE TABLE IF NOT EXISTS site_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        );

        -- A purchasable bundle of existing uploaded tracks (any track with a real
        -- local file -- tracks.src under audio/ or videos/; embed-only
        -- YouTube/TikTok/Apple links have no downloadable file so can't be
        -- bundled). Albums
        -- never duplicate or move the underlying track rows -- see album_tracks,
        -- a join table, so one song could in principle belong to more than one
        -- album and deleting an album never touches the tracks table.
        CREATE TABLE IF NOT EXISTS albums (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            artist TEXT NOT NULL,
            price TEXT NOT NULL,
            price_cents INTEGER NOT NULL DEFAULT 0,
            cover_path TEXT NOT NULL,
            sort_order INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS album_tracks (
            album_id TEXT NOT NULL REFERENCES albums(id),
            track_id TEXT NOT NULL REFERENCES tracks(id),
            sort_order INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (album_id, track_id)
        );
        """
    )
    conn.commit()

    # Safe idempotent migration: orders predates album purchases, which need a
    # per-order secret so the post-purchase success page can hand back a
    # download link that can't be guessed from the order id alone.
    existing_order_cols = {row["name"] for row in conn.execute("PRAGMA table_info(orders)").fetchall()}
    if "download_token" not in existing_order_cols:
        conn.execute("ALTER TABLE orders ADD COLUMN download_token TEXT")
        conn.commit()

    # Safe idempotent migration: apparel predates having a description field,
    # so existing databases need it added rather than recreated.
    existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(apparel)").fetchall()}
    if "description" not in existing_cols:
        conn.execute("ALTER TABLE apparel ADD COLUMN description TEXT NOT NULL DEFAULT ''")
        conn.commit()

    # Safe idempotent migration: tracks predates song-with-artwork uploads, so
    # existing databases need the column added rather than recreated. Nullable --
    # existing video/embed tracks are unaffected and just have no artwork.
    existing_track_cols = {row["name"] for row in conn.execute("PRAGMA table_info(tracks)").fetchall()}
    if "artwork" not in existing_track_cols:
        conn.execute("ALTER TABLE tracks ADD COLUMN artwork TEXT")
        conn.commit()

    # Safe idempotent migration: page_views predates bot/crawler filtering, so
    # existing databases need these columns added rather than recreated.
    # user_agent is stored raw going forward so rows can always be
    # reclassified later without another migration; is_bot is computed at
    # insert time from is_bot_user_agent(). Historical rows (before this
    # migration ran) have no stored User-Agent to reclassify from, so they
    # stay is_bot=0 (unclassified, best-effort) -- see log_page_view().
    existing_pv_cols = {row["name"] for row in conn.execute("PRAGMA table_info(page_views)").fetchall()}
    if "user_agent" not in existing_pv_cols:
        conn.execute("ALTER TABLE page_views ADD COLUMN user_agent TEXT")
        conn.commit()
    if "is_bot" not in existing_pv_cols:
        conn.execute("ALTER TABLE page_views ADD COLUMN is_bot INTEGER NOT NULL DEFAULT 0")
        conn.commit()

    if conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0:
        default_user = os.environ.get("MH_ADMIN_USER", "admin")
        default_pass = os.environ.get("MH_ADMIN_PASS") or secrets.token_urlsafe(9)
        conn.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
            (default_user, generate_password_hash(default_pass, method="pbkdf2:sha256")),
        )
        conn.commit()
        (BASE_DIR / "INITIAL_ADMIN_CREDENTIALS.txt").write_text(
            f"username: {default_user}\npassword: {default_pass}\n"
            "Delete this file after you've noted the password (or change it — see README).\n"
        )

    # Opt-in recovery/change path: if MH_ADMIN_RESET_PASSWORD is set, upsert that
    # password for the admin user on startup. The auto-generated password from first
    # boot only lives on the app container's ephemeral filesystem, not the persistent
    # disk, so this is how access gets restored (or the password changed) in production.
    reset_pass = os.environ.get("MH_ADMIN_RESET_PASSWORD")
    if reset_pass:
        reset_user = os.environ.get("MH_ADMIN_USER", "admin")
        conn.execute(
            "UPDATE admins SET password_hash = ? WHERE username = ?",
            (generate_password_hash(reset_pass, method="pbkdf2:sha256"), reset_user),
        )
        conn.commit()

    conn.close()


def login_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)

    return wrapper


# ==================================================================
# Analytics — visitor identity, IP/UA parsing, geolocation, logging
#
# Design notes (read this before porting to the sister sites):
#   - Uniques are tracked via an anonymous `mh_visitor` cookie (random UUID,
#     ~1yr expiry, httponly), NOT login/email -- most visitors never create
#     an account, so this is the only realistic way to count "people" vs
#     "page loads" without requiring a login wall.
#   - "Demographics" here means location + device/browser + referrer + time
#     patterns -- NOT age/gender/income, which simply isn't derivable from
#     server logs without visitors self-reporting. See the report for how
#     this should be communicated to the site owner.
#   - Geolocation is best-effort and free (ip-api.com, no key, ~45 req/min).
#     Private/loopback IPs are never sent out -- they're labeled "Local/Dev".
#     Results are cached in-process per IP so repeat visits don't re-hit the
#     API and don't risk the free-tier rate limit.
# ==================================================================

_geo_cache = {}  # ip_address -> (country, city), process-lifetime cache


def get_client_ip():
    """Prefer X-Forwarded-For (set by a reverse proxy, or by a test harness
    simulating one) over the raw socket address, since this app is expected
    to run behind a proxy in production. NOTE: if this app is ever exposed
    directly to the internet without a trusted proxy in front of it, this
    header is attacker-controlled -- fine for internal analytics, but don't
    use get_client_ip() for security decisions (rate limiting already uses
    request.remote_addr directly, on purpose)."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def _is_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable -> treat as non-routable, don't call out to ip-api
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def get_geo(ip):
    """Returns (country, city). Never calls out for private/loopback/unparseable
    IPs -- those are labeled "Local/Dev" per the no-geolocation-for-localhost
    requirement. Caches every result (including failures) per IP for the life
    of the process."""
    if not ip or _is_private_ip(ip):
        return ("Local/Dev", "Local/Dev")
    if ip in _geo_cache:
        return _geo_cache[ip]
    result = ("Unknown", "Unknown")
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city"},
            timeout=2,
        )
        data = resp.json()
        if data.get("status") == "success":
            result = (data.get("country") or "Unknown", data.get("city") or "Unknown")
    except (requests.RequestException, ValueError):
        pass
    _geo_cache[ip] = result
    return result


# Lightweight, dependency-free User-Agent parsing. Good enough for
# mobile/tablet/desktop + top-browser breakdowns -- not meant to be a
# bulletproof UA database.
def parse_user_agent(ua):
    ua_l = (ua or "").lower()

    if "ipad" in ua_l or "tablet" in ua_l or "kindle" in ua_l or "playbook" in ua_l or \
       ("android" in ua_l and "mobile" not in ua_l):
        device_type = "tablet"
    elif any(tok in ua_l for tok in ("mobi", "iphone", "ipod", "android", "windows phone")):
        device_type = "mobile"
    else:
        device_type = "desktop"

    # Order matters: many browsers spoof "Safari"/"Chrome" tokens in their UA
    # string, so check the more specific tokens first.
    if "edg/" in ua_l or "edga/" in ua_l or "edgios/" in ua_l:
        browser = "Edge"
    elif "opr/" in ua_l or "opera" in ua_l:
        browser = "Opera"
    elif "crios" in ua_l:
        browser = "Chrome"
    elif "fxios" in ua_l or "firefox" in ua_l:
        browser = "Firefox"
    elif "chrome" in ua_l or "chromium" in ua_l:
        browser = "Chrome"
    elif "safari" in ua_l:
        browser = "Safari"
    elif not ua_l:
        browser = "Unknown"
    else:
        browser = "Other"

    return device_type, browser


# Known bot/crawler/monitoring/script User-Agent substrings, lowercase. This is
# intentionally UA-string-only (no IP/ASN lookup, no paid service) -- low
# maintenance, good enough to strip the overwhelming majority of non-human
# traffic (search crawlers, SEO bots, social link-preview fetchers, uptime
# monitors, and bare HTTP-client libraries) out of the analytics dashboard.
# Not meant to catch every sophisticated scraper that spoofs a real browser UA.
_BOT_UA_SUBSTRINGS = (
    # Search engine crawlers
    "googlebot", "bingbot", "duckduckbot", "baiduspider", "yandexbot",
    "slurp", "sogou", "exabot", "applebot", "ia_archiver",
    # SEO / marketing crawlers
    "ahrefsbot", "semrushbot", "mj12bot", "dotbot", "rogerbot", "blexbot",
    "seznambot", "dataforseobot",
    # Social link-preview bots
    "facebookexternalhit", "twitterbot", "slackbot", "discordbot",
    "whatsapp", "telegrambot", "linkedinbot", "pinterest", "redditbot",
    "skypeuripreview",
    # Uptime / monitoring services
    "uptimerobot", "pingdom", "statuscake", "better uptime", "betteruptime",
    "site24x7", "newrelicpinger", "datadog",
    # Generic script / HTTP-client libraries
    "python-requests", "python-urllib", "curl/", "wget/", "go-http-client",
    "axios/", "node-fetch", "scrapy", "java/", "okhttp", "apache-httpclient",
    "postmanruntime", "libwww-perl", "httpclient",
)


def is_bot_user_agent(ua):
    """True if this User-Agent is a known crawler/monitor/script, or missing
    entirely (real browsers always send one; many simple scripts don't)."""
    ua_l = (ua or "").strip().lower()
    if not ua_l:
        return True
    if any(tok in ua_l for tok in _BOT_UA_SUBSTRINGS):
        return True
    # Catch-all for anything self-identifying as a bot that isn't explicitly
    # listed above.
    return any(tok in ua_l for tok in ("bot", "spider", "crawler", "crawl"))


@app.before_request
def _assign_visitor_id():
    existing = request.cookies.get("mh_visitor")
    g.visitor_id = existing or str(uuid.uuid4())
    g.visitor_id_is_new = not existing


@app.after_request
def _persist_visitor_cookie(response):
    if getattr(g, "visitor_id_is_new", False):
        response.set_cookie(
            "mh_visitor", g.visitor_id,
            max_age=60 * 60 * 24 * 365, httponly=True,
            samesite="Lax", secure=IS_PRODUCTION,
        )
    return response


def log_page_view(path):
    """Call this from real page routes only -- never from API polling
    endpoints, static assets, or the analytics endpoints themselves."""
    ip = get_client_ip()
    country, city = get_geo(ip)
    ua = request.headers.get("User-Agent", "")
    device_type, browser = parse_user_agent(ua)
    is_bot = 1 if is_bot_user_agent(ua) else 0
    referrer = (request.headers.get("Referer", "") or "")[:500]
    conn = get_db()
    conn.execute(
        """INSERT INTO page_views (path, ip_address, country, city, device_type, browser, referrer, visitor_id, user_agent, is_bot)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (path, ip, country, city, device_type, browser, referrer, g.visitor_id, ua, is_bot),
    )
    conn.commit()
    conn.close()


ANALYTICS_EVENT_TYPES = {"track_play", "apparel_quickview", "checkout_start"}


@app.post("/api/analytics/event")
def log_analytics_event():
    """Frontend-driven analytics events -- track/video plays, apparel
    quick-view opens, and checkout starts. Completed purchases are logged
    server-side from the Stripe webhook instead (see stripe_webhook()),
    since that's the only place we can trust a purchase actually happened."""
    data = request.get_json(silent=True) or {}
    event_type = (data.get("event_type") or "").strip()
    if event_type not in ANALYTICS_EVENT_TYPES:
        return jsonify({"error": "invalid event_type"}), 400
    item_id = (data.get("item_id") or "").strip()[:120]
    item_label = (data.get("item_label") or "").strip()[:200]
    conn = get_db()
    conn.execute(
        "INSERT INTO analytics_events (event_type, item_id, item_label, visitor_id) VALUES (?,?,?,?)",
        (event_type, item_id, item_label, g.visitor_id),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/")
def index():
    log_page_view("/")
    return send_from_directory(app.static_folder, "index.html")


@app.route("/videos/<path:filename>")
def serve_video(filename):
    return send_from_directory(VIDEOS_DIR, filename)


@app.post("/api/login")
def login():
    ip = request.remote_addr or "unknown"
    if _rate_limited(ip):
        return jsonify({"error": "Too many attempts. Try again in a minute."}), 429

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    conn = get_db()
    row = conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
    conn.close()

    if not row or not check_password_hash(row["password_hash"], password):
        _register_failure(ip)
        return jsonify({"error": "Invalid username or password"}), 401

    _register_success(ip)
    session.clear()
    session["admin_id"] = row["id"]
    session["username"] = row["username"]
    return jsonify({"ok": True, "username": row["username"]})


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/me")
def me():
    if session.get("admin_id"):
        return jsonify({"loggedIn": True, "username": session.get("username")})
    return jsonify({"loggedIn": False})


# Give every active track/video fair rotation in the featured/top slot instead
# of always leading with whatever has the lowest sort_order. Deterministic and
# stateless -- the offset is derived purely from wall-clock time, so it's the
# same for every visitor at a given moment and doesn't rely on a cron job,
# background worker, or any persisted state that a Render restart could reset
# or desync. sort_order still defines the stable base sequence; this only
# rotates *presentation* order (list is cyclically shifted, not shuffled).
TRACK_ROTATION_PERIOD_SECONDS = 24 * 3600  # rotate once every 24 hours


def build_rotated_tracks(rows):
    items = [dict(r) for r in rows]
    n = len(items)
    if n == 0:
        return items
    offset = int(time.time() // TRACK_ROTATION_PERIOD_SECONDS) % n
    return items[offset:] + items[:offset]


@app.get("/api/tracks")
def list_tracks():
    conn = get_db()
    rows = conn.execute("SELECT * FROM tracks WHERE active = 1 ORDER BY sort_order ASC").fetchall()
    conn.close()
    return jsonify(build_rotated_tracks(rows))


@app.delete("/api/tracks/<track_id>")
@login_required
def delete_track(track_id):
    conn = get_db()
    row = conn.execute("SELECT src, artwork FROM tracks WHERE id = ?", (track_id,)).fetchone()
    conn.execute("UPDATE tracks SET active = 0 WHERE id = ?", (track_id,))
    conn.commit()
    conn.close()
    # Uploaded videos/songs/artwork are stored under unique-per-upload filenames, so
    # it's safe to remove the file from disk once its track is delisted — nothing else
    # references it. (Soft-delete only flips `active`; without this the persistent
    # disk fills up with orphaned files from every replaced/removed upload.)
    if row and row["src"]:
        if row["src"].startswith("videos/"):
            _delete_video_file_if_unreferenced(row["src"])
        elif row["src"].startswith("audio/"):
            _delete_track_file_if_unreferenced("src", row["src"], AUDIO_DIR)
    if row and row["artwork"] and row["artwork"].startswith("images/artwork/"):
        _delete_track_file_if_unreferenced("artwork", row["artwork"], ARTWORK_DIR)
    return jsonify({"ok": True})


@app.patch("/api/tracks/<track_id>")
@login_required
def edit_track(track_id):
    conn = get_db()
    row = conn.execute("SELECT id FROM tracks WHERE id = ? AND active = 1", (track_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Track not found."}), 404
    data = request.get_json(silent=True) or {}
    fields, values = [], []
    for key in ("title", "artist"):
        if key in data:
            value = (data.get(key) or "").strip()
            if not value:
                conn.close()
                return jsonify({"error": f"{key} cannot be empty."}), 400
            fields.append(f"{key} = ?")
            values.append(value)
    if not fields:
        conn.close()
        return jsonify({"error": "Nothing to update."}), 400
    values.append(track_id)
    conn.execute(f"UPDATE tracks SET {', '.join(fields)} WHERE id = ?", values)
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


def _delete_video_file_if_unreferenced(src):
    conn = get_db()
    still_used = conn.execute(
        "SELECT COUNT(*) FROM tracks WHERE src = ? AND active = 1", (src,)
    ).fetchone()[0]
    conn.close()
    if still_used:
        return
    filename = src.split("/", 1)[-1]
    path = VIDEOS_DIR / filename
    try:
        if path.is_file():
            path.unlink()
    except OSError:
        pass


def _delete_track_file_if_unreferenced(column, value, base_dir):
    """Generic version of _delete_video_file_if_unreferenced, for the newer
    audio (`src`, under audio/) and artwork (`artwork`, under images/artwork/)
    uploads -- same "only remove if no active track still points at it" logic."""
    if not value:
        return
    conn = get_db()
    still_used = conn.execute(
        f"SELECT COUNT(*) FROM tracks WHERE {column} = ? AND active = 1", (value,)
    ).fetchone()[0]
    conn.close()
    if still_used:
        return
    filename = value.rsplit("/", 1)[-1]  # last path segment -- value may be "videos/x"
                                          # or the two-level "images/artwork/x"
    path = base_dir / filename
    try:
        if path.is_file():
            path.unlink()
    except OSError:
        pass


@app.post("/api/tracks")
@login_required
def add_track():
    data = request.get_json(silent=True) or {}
    track_type = data.get("type")
    if track_type not in ("youtube", "tiktok", "apple"):
        return jsonify({"error": "unsupported type"}), 400

    conn = get_db()
    next_order = conn.execute("SELECT COALESCE(MAX(sort_order),0)+1 FROM tracks").fetchone()[0]
    new_id = f"{track_type}-{secrets.token_hex(4)}"
    conn.execute(
        "INSERT INTO tracks (id, title, artist, len, seconds, type, embed_id, embed_url, sort_order) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (new_id, data.get("title", "Imported Track"), data.get("artist", "Imported Link"),
         "--:--", 0, track_type, data.get("id"), data.get("embedUrl"), next_order),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": new_id})


def _video_duration_seconds(path, attempts=6, delay=0.5):
    for _ in range(attempts):
        try:
            out = subprocess.run(
                ["mdls", "-name", "kMDItemDurationSeconds", "-raw", str(path)],
                capture_output=True, text=True, timeout=10,
            ).stdout.strip()
            if out and out != "(null)":
                return float(out)
        except (subprocess.SubprocessError, ValueError, FileNotFoundError):
            pass
        time.sleep(delay)
    return 0


def _format_len(seconds):
    if not seconds or seconds <= 0:
        return "--:--"
    seconds = int(round(seconds))
    return f"{seconds // 60}:{seconds % 60:02d}"


@app.post("/api/tracks/upload")
@login_required
def upload_track():
    """Uploads a track either as a local video file (multipart field 'video', the
    original behavior) or as a song/audio file (multipart field 'audio'), optionally
    paired with cover art (multipart field 'artwork', image only -- validated the same
    way as /api/apparel/upload-image). Exactly one of video/audio is required."""
    video_file = request.files.get("video")
    audio_file = request.files.get("audio")
    has_video = bool(video_file and video_file.filename)
    has_audio = bool(audio_file and audio_file.filename)

    if has_video and has_audio:
        return jsonify({"error": "Upload either a video file or a song file, not both."}), 400
    if not has_video and not has_audio:
        return jsonify({"error": "No audio or video file uploaded."}), 400

    artwork_path = None
    artwork_file = request.files.get("artwork")
    if artwork_file and artwork_file.filename:
        art_data, _media_type, err = _read_and_validate_image(artwork_file)
        if err:
            response, status = err
            return response, status
        art_ext = artwork_file.filename.rsplit(".", 1)[-1].lower()
        art_base = secure_filename(artwork_file.filename.rsplit(".", 1)[0]) or "artwork"
        art_filename = f"{art_base}-{secrets.token_hex(4)}.{art_ext}"
        art_dest = ARTWORK_DIR / art_filename
        try:
            art_dest.write_bytes(art_data)
        except OSError:
            art_dest.unlink(missing_ok=True)
            return jsonify({
                "error": "Upload failed: the server ran out of storage space. "
                         "An admin needs to free up disk space or increase the disk size."
            }), 507
        artwork_path = f"images/artwork/{art_filename}"

    if has_video:
        ext = video_file.filename.rsplit(".", 1)[-1].lower() if "." in video_file.filename else ""
        if ext not in ALLOWED_VIDEO_EXTENSIONS:
            return jsonify({"error": f"Unsupported file type .{ext}. Allowed: {', '.join(sorted(ALLOWED_VIDEO_EXTENSIONS))}"}), 400

        base_name = secure_filename(video_file.filename.rsplit(".", 1)[0]) or "video"
        filename = f"{base_name}-{secrets.token_hex(4)}.{ext}"
        dest = VIDEOS_DIR / filename
        try:
            video_file.save(dest)
        except OSError:
            # e.g. errno 28 "No space left on device" if the persistent disk is full.
            dest.unlink(missing_ok=True)
            return jsonify({
                "error": "Upload failed: the server ran out of storage space. "
                         "An admin needs to free up disk space (delete old videos) or increase the disk size."
            }), 507

        seconds = _video_duration_seconds(dest)
        track_type = "video"
        src = f"videos/{filename}"
        id_prefix = "video"
    else:
        data, err = _read_and_validate_audio(audio_file)
        if err:
            response, status = err
            return response, status

        ext = audio_file.filename.rsplit(".", 1)[-1].lower()
        base_name = secure_filename(audio_file.filename.rsplit(".", 1)[0]) or "song"
        filename = f"{base_name}-{secrets.token_hex(4)}.{ext}"
        dest = AUDIO_DIR / filename
        try:
            dest.write_bytes(data)
        except OSError:
            dest.unlink(missing_ok=True)
            return jsonify({
                "error": "Upload failed: the server ran out of storage space. "
                         "An admin needs to free up disk space (delete old songs) or increase the disk size."
            }), 507

        seconds = _video_duration_seconds(dest)  # mdls reads duration metadata for audio too
        track_type = "audio"
        src = f"audio/{filename}"
        id_prefix = "song"

    title = (request.form.get("title") or base_name.replace("-", " ").replace("_", " ").title()).strip()
    artist = (request.form.get("artist") or "Msanii Halisi").strip()

    conn = get_db()
    next_order = conn.execute("SELECT COALESCE(MAX(sort_order),0)+1 FROM tracks").fetchone()[0]
    new_id = f"{id_prefix}-{secrets.token_hex(4)}"
    conn.execute(
        "INSERT INTO tracks (id, title, artist, len, seconds, src, type, artwork, sort_order) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (new_id, title, artist, _format_len(seconds), int(seconds), src, track_type, artwork_path, next_order),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": new_id, "title": title, "artist": artist, "artwork": artwork_path})


# Site assets (e.g. the homepage hero background loop) are referenced by a fixed
# filename directly in index.html markup -- they are not catalog items, so they
# don't belong in the tracks table the way /api/tracks/upload's videos do (that
# endpoint always inserts a track row, and delete_track() deletes the underlying
# file once its row is gone -- both wrong for an asset the homepage always expects
# to find at a stable path). This writes straight to VIDEOS_DIR under a fixed,
# allow-listed filename instead, reusing the same on-disk location (the Render
# persistent disk mounted at DATA_DIR) as every other upload endpoint.
ALLOWED_SITE_ASSET_NAMES = {"hero-loop.mov", "hero-loop.mp4", "hero-loop.webm"}


@app.post("/api/admin/site-asset")
@login_required
def upload_site_asset():
    """Admin-only: place a fixed-name video asset (e.g. the hero background loop)
    directly on the persistent disk at videos/<name>, overwriting any existing file
    of that name. Field 'video' is the file; field 'name' must be one of
    ALLOWED_SITE_ASSET_NAMES and match the path index.html actually references."""
    name = (request.form.get("name") or "").strip()
    if name not in ALLOWED_SITE_ASSET_NAMES:
        return jsonify({"error": f"name must be one of: {', '.join(sorted(ALLOWED_SITE_ASSET_NAMES))}"}), 400

    video_file = request.files.get("video")
    if not video_file or not video_file.filename:
        return jsonify({"error": "No video file uploaded."}), 400
    ext = video_file.filename.rsplit(".", 1)[-1].lower() if "." in video_file.filename else ""
    if ext not in ALLOWED_VIDEO_EXTENSIONS:
        return jsonify({"error": f"Unsupported file type .{ext}. Allowed: {', '.join(sorted(ALLOWED_VIDEO_EXTENSIONS))}"}), 400
    if not name.endswith(f".{ext}"):
        return jsonify({"error": f"name '{name}' doesn't match uploaded file extension .{ext}"}), 400

    dest = VIDEOS_DIR / name
    tmp_dest = VIDEOS_DIR / f".{name}.uploading"
    try:
        video_file.save(tmp_dest)
        tmp_dest.replace(dest)
    except OSError:
        tmp_dest.unlink(missing_ok=True)
        return jsonify({
            "error": "Upload failed: the server ran out of storage space. "
                     "An admin needs to free up disk space (delete old videos) or increase the disk size."
        }), 507

    return jsonify({"ok": True, "name": name, "bytes": dest.stat().st_size})


# Give the homepage hero background video weekly rotation through the same
# catalog of uploaded videos /api/tracks already serves (DJ Kingdom Refix,
# NILE, Maajab, Amalaki, Kalkouta, Roke, etc.), instead of depending solely on
# the fixed hero-loop.mov manual-upload slot above -- that file doesn't exist
# on production yet (404s) and even once uploaded would otherwise sit in the
# hero slot indefinitely while the rest of the catalog gets no exposure there.
# Same stateless wall-clock-time-bucket approach as TRACK_ROTATION_PERIOD_SECONDS
# above, but its own independent period/offset -- this rotates which single
# video fills the hero background, not the display order of the full catalog
# list, so it deliberately does not reuse that computed offset.
HERO_ROTATION_PERIOD_SECONDS = 7 * 24 * 3600  # rotate the hero video once a week


def select_hero_video(rows):
    """rows: active type='video' tracks with a real on-disk src, ordered by
    sort_order ASC (the same stable base sequence build_rotated_tracks uses).
    Deterministically picks one based on the current wall-clock week bucket --
    same value for every visitor at a given moment, no DB writes, no cron."""
    items = [dict(r) for r in rows]
    n = len(items)
    if n == 0:
        return None
    offset = int(time.time() // HERO_ROTATION_PERIOD_SECONDS) % n
    return items[offset]


@app.get("/api/hero-video")
def hero_video():
    """Public: which video should currently fill the homepage hero background.
    Prefers a manually-uploaded override at videos/hero-loop.(mov|mp4|webm) --
    placed via the admin "UPLOAD HERO VIDEO" control / /api/admin/site-asset,
    unchanged by this endpoint -- if an admin has placed one; otherwise falls
    back to the weekly-rotating catalog pick above, so the hero slot always has
    a real video to show instead of 404ing on a file nobody uploaded."""
    for name in ("hero-loop.mov", "hero-loop.mp4", "hero-loop.webm"):
        if (VIDEOS_DIR / name).exists():
            return jsonify({"src": f"videos/{name}", "source": "override"})

    conn = get_db()
    rows = conn.execute(
        "SELECT id, title, src FROM tracks "
        "WHERE active = 1 AND type = 'video' AND src IS NOT NULL AND src != '' "
        "ORDER BY sort_order ASC"
    ).fetchall()
    conn.close()
    choice = select_hero_video(rows)
    if not choice:
        return jsonify({"src": None})
    return jsonify({"src": choice["src"], "title": choice["title"], "source": "rotation"})


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "That file is too large (300MB limit)."}), 413


@app.get("/api/admin/disk-report")
@login_required
def disk_report():
    """Diagnostic: which video files on disk are/aren't referenced by a track row,
    and by an *active* track row. Read-only, admin-only."""
    conn = get_db()
    rows = conn.execute("SELECT id, title, active, src FROM tracks").fetchall()
    conn.close()

    referenced = {r["src"] for r in rows if r["src"]}
    referenced_active = {r["src"] for r in rows if r["src"] and r["active"]}

    files = []
    total_bytes = 0
    if VIDEOS_DIR.exists():
        for p in sorted(VIDEOS_DIR.iterdir()):
            if not p.is_file():
                continue
            size = p.stat().st_size
            total_bytes += size
            rel = f"videos/{p.name}"
            files.append({
                "name": p.name,
                "size_mb": round(size / 1024 / 1024, 2),
                "referenced": rel in referenced,
                "referenced_by_active_track": rel in referenced_active,
            })
    files.sort(key=lambda f: -f["size_mb"])

    return jsonify({
        "video_file_count": len(files),
        "video_dir_total_mb": round(total_bytes / 1024 / 1024, 2),
        "tracks": [dict(r) for r in rows],
        "files": files,
    })


@app.post("/api/admin/cleanup-orphaned-videos")
@login_required
def cleanup_orphaned_videos():
    """Free disk space by deleting video files that no *active* track references —
    i.e. files left behind by past uploads that were later replaced/delisted (soft
    delete never removed the file) or that never finished being recorded in the DB.
    Never touches a file referenced by a currently-active track."""
    conn = get_db()
    rows = conn.execute("SELECT src FROM tracks WHERE active = 1 AND src IS NOT NULL").fetchall()
    conn.close()
    active_files = {r["src"].split("/", 1)[-1] for r in rows if r["src"] and r["src"].startswith("videos/")}

    deleted = []
    freed_bytes = 0
    if VIDEOS_DIR.exists():
        for p in VIDEOS_DIR.iterdir():
            if not p.is_file() or p.name in active_files:
                continue
            size = p.stat().st_size
            try:
                p.unlink()
            except OSError:
                continue
            deleted.append(p.name)
            freed_bytes += size

    return jsonify({
        "ok": True,
        "deleted_files": deleted,
        "freed_mb": round(freed_bytes / 1024 / 1024, 2),
    })


# ==================================================================
# Live streaming — data access
# ==================================================================

def create_live_session(title, host_name):
    room_code = secrets.token_urlsafe(6).replace("_", "").replace("-", "")[:8]
    new_id = f"live-{secrets.token_hex(4)}"
    conn = get_db()
    conn.execute(
        "INSERT INTO live_sessions (id, title, host_name, room_code) VALUES (?,?,?,?)",
        (new_id, title, host_name, room_code),
    )
    conn.commit()
    conn.close()
    return new_id, room_code


def get_live_session(session_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM live_sessions WHERE id = ?", (session_id,)).fetchone()
    conn.close()
    return row


def get_live_session_by_room(room_code):
    conn = get_db()
    row = conn.execute("SELECT * FROM live_sessions WHERE room_code = ?", (room_code,)).fetchone()
    conn.close()
    return row


def list_live_sessions(status=None):
    conn = get_db()
    if status:
        rows = conn.execute(
            "SELECT * FROM live_sessions WHERE status = ? ORDER BY created_at DESC", (status,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM live_sessions ORDER BY created_at DESC").fetchall()
    conn.close()
    return rows


def set_live_status(session_id, status):
    conn = get_db()
    if status == "live":
        conn.execute(
            "UPDATE live_sessions SET status = ?, started_at = datetime('now') WHERE id = ?",
            (status, session_id),
        )
    elif status == "ended":
        conn.execute(
            "UPDATE live_sessions SET status = ?, ended_at = datetime('now') WHERE id = ?",
            (status, session_id),
        )
    else:
        conn.execute("UPDATE live_sessions SET status = ? WHERE id = ?", (status, session_id))
    conn.commit()
    conn.close()


def set_live_recording(session_id, recording_path):
    conn = get_db()
    conn.execute("UPDATE live_sessions SET recording_path = ? WHERE id = ?", (recording_path, session_id))
    conn.commit()
    conn.close()


def update_live_session(session_id, title=None, host_name=None):
    conn = get_db()
    if title is not None:
        conn.execute("UPDATE live_sessions SET title = ? WHERE id = ?", (title, session_id))
    if host_name is not None:
        conn.execute("UPDATE live_sessions SET host_name = ? WHERE id = ?", (host_name, session_id))
    conn.commit()
    conn.close()


def delete_live_session(session_id):
    conn = get_db()
    conn.execute("DELETE FROM chat_messages WHERE live_session_id = ?", (session_id,))
    conn.execute("DELETE FROM camera_requests WHERE live_session_id = ?", (session_id,))
    conn.execute("DELETE FROM live_sessions WHERE id = ?", (session_id,))
    conn.commit()
    conn.close()


def add_chat_message(session_id, sender_name, message):
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO chat_messages (live_session_id, sender_name, message) VALUES (?,?,?)",
        (session_id, sender_name, message),
    )
    conn.commit()
    conn.close()
    return cur.lastrowid


def list_chat_messages(session_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM chat_messages WHERE live_session_id = ? ORDER BY id ASC", (session_id,)
    ).fetchall()
    conn.close()
    return rows


def create_camera_request(session_id, viewer_name, socket_id):
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO camera_requests (live_session_id, viewer_name, socket_id) VALUES (?,?,?)",
        (session_id, viewer_name, socket_id),
    )
    conn.commit()
    conn.close()
    return cur.lastrowid


def get_camera_request(request_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM camera_requests WHERE id = ?", (request_id,)).fetchone()
    conn.close()
    return row


def set_camera_request_status(request_id, status):
    conn = get_db()
    conn.execute("UPDATE camera_requests SET status = ? WHERE id = ?", (status, request_id))
    conn.commit()
    conn.close()


# ==================================================================
# Live streaming — pages & admin API
# ==================================================================

@app.get("/live")
def live_list():
    log_page_view("/live")
    live_now = list_live_sessions(status="live")
    scheduled = list_live_sessions(status="scheduled")
    ended = [s for s in list_live_sessions(status="ended") if s["recording_path"]]
    # Snapshot of id -> status at render time, handed to the page's JS so it
    # can tell "this session's status just changed since I loaded" (to show
    # the "just went live" banner) apart from "this is just how it already
    # was when I opened the page".
    initial_state = [
        {"id": s["id"], "status": s["status"]}
        for s in (list(live_now) + list(scheduled) + list(ended))
    ]
    return render_template(
        "live_list.html", live_now=live_now, scheduled=scheduled, ended=ended,
        initial_state=initial_state,
    )


@app.get("/live/<room_code>/replay")
def live_replay(room_code):
    log_page_view("/live/<room_code>/replay")
    live_session = get_live_session_by_room(room_code)
    if not live_session or not live_session["recording_path"]:
        return jsonify({"error": "Replay not found."}), 404
    return render_template("live_replay.html", live_session=live_session)


@app.get("/live/<room_code>/host")
@login_required
def live_host(room_code):
    live_session = get_live_session_by_room(room_code)
    if not live_session:
        return jsonify({"error": "Live session not found."}), 404
    return render_template("live_host.html", live_session=live_session)


@app.get("/live/<room_code>")
def live_room(room_code):
    log_page_view("/live/<room_code>")
    live_session = get_live_session_by_room(room_code)
    if not live_session:
        return jsonify({"error": "Live session not found."}), 404
    return render_template("live_room.html", live_session=live_session)


LIVE_RECORDING_TMP_DIR = DATA_DIR / "live_recording_tmp"
LIVE_RECORDING_TMP_DIR.mkdir(parents=True, exist_ok=True)


def _live_recording_tmp_path(room_code):
    # room_code is per-session (never reused), so it alone is a safe unique key.
    safe = secure_filename(room_code) or "room"
    return LIVE_RECORDING_TMP_DIR / f"{safe}.webm.part"


@app.post("/live/<room_code>/upload-chunk")
@login_required
def upload_recording_chunk(room_code):
    # The old design buffered the ENTIRE recording in the browser's memory and
    # uploaded it as one giant request only at the end of the live session --
    # which silently lost real footage in production: a long session's blob
    # exceeded MAX_CONTENT_LENGTH (or just hit a network hiccup) on that one
    # all-or-nothing upload, the connection was cut, fetch() threw, and there
    # was nothing recoverable server-side (not even a partial file) once the
    # browser tab closed. Fixed by uploading each ~1s MediaRecorder chunk to
    # disk as it's produced (appended in order to one growing .part file) --
    # a single dropped chunk-sized request can be retried or simply costs a
    # second of footage, never the whole session, and most of the recording
    # is already safely on disk well before "end live" is ever clicked.
    live_session = get_live_session_by_room(room_code)
    if not live_session:
        return jsonify({"error": "Live session not found."}), 404
    chunk = request.files.get("chunk")
    if not chunk:
        return jsonify({"error": "no chunk"}), 400
    dest = _live_recording_tmp_path(room_code)
    try:
        with open(dest, "ab") as f:
            f.write(chunk.read())
    except OSError:
        return jsonify({"error": "Upload failed: the server ran out of storage space."}), 507
    return jsonify({"ok": True})


@app.post("/live/<room_code>/finalize-recording")
@login_required
def finalize_recording(room_code):
    live_session = get_live_session_by_room(room_code)
    if not live_session:
        return jsonify({"error": "Live session not found."}), 404
    tmp_path = _live_recording_tmp_path(room_code)
    if not tmp_path.exists() or tmp_path.stat().st_size == 0:
        return jsonify({"error": "No recorded chunks were received."}), 400
    filename = f"live-{room_code}-{secrets.token_hex(4)}.webm"
    dest = VIDEOS_DIR / filename
    try:
        tmp_path.rename(dest)
    except OSError:
        return jsonify({"error": "Upload failed: the server ran out of storage space."}), 507
    rel_path = f"videos/{filename}"
    set_live_recording(live_session["id"], rel_path)
    return jsonify({"ok": True, "path": rel_path})


@app.get("/api/live")
def api_list_live():
    rows = list_live_sessions()
    return jsonify([dict(r) for r in rows])


@app.get("/api/live/status")
def api_live_status():
    """Lightweight JSON used by the /live listing page to poll for status
    changes (e.g. a session moving from "scheduled" to "live") without a
    manual reload. Intentionally small — just enough to redraw a card."""
    rows = list_live_sessions()
    return jsonify([
        {
            "id": r["id"],
            "room_code": r["room_code"],
            "title": r["title"],
            "host_name": r["host_name"],
            "status": r["status"],
            "has_replay": bool(r["recording_path"]),
        }
        for r in rows
    ])


@app.post("/api/live")
@login_required
def api_create_live():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "Session title is required."}), 400
    host_name = (data.get("host_name") or "").strip() or session.get("username", "Msanii Halisi")
    session_id, room_code = create_live_session(title, host_name)
    return jsonify({"ok": True, "id": session_id, "room_code": room_code})


@app.patch("/api/live/<session_id>")
@login_required
def api_edit_live(session_id):
    live_session = get_live_session(session_id)
    if not live_session:
        return jsonify({"error": "Live session not found."}), 404
    data = request.get_json(silent=True) or {}
    title = data.get("title")
    host_name = data.get("host_name")
    if title is not None:
        title = title.strip()
        if not title:
            return jsonify({"error": "Session title is required."}), 400
    if host_name is not None:
        host_name = host_name.strip()
    update_live_session(session_id, title=title, host_name=host_name)
    return jsonify({"ok": True})


@app.delete("/api/live/<session_id>")
@login_required
def api_delete_live(session_id):
    live_session = get_live_session(session_id)
    if not live_session:
        return jsonify({"error": "Live session not found."}), 404
    # A saved recording's file is unique to this session (never shared, unlike
    # uploaded tracks) -- safe to remove from disk unconditionally once the
    # session row referencing it is gone.
    if live_session["recording_path"] and live_session["recording_path"].startswith("videos/"):
        filename = live_session["recording_path"].split("/", 1)[-1]
        path = VIDEOS_DIR / filename
        try:
            if path.is_file():
                path.unlink()
        except OSError:
            pass
    delete_live_session(session_id)
    return jsonify({"ok": True})


@app.get("/api/products")
def list_products():
    conn = get_db()
    rows = conn.execute("SELECT * FROM products WHERE active = 1 ORDER BY sort_order ASC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.delete("/api/products/<product_id>")
@login_required
def delete_product(product_id):
    conn = get_db()
    conn.execute("UPDATE products SET active = 0 WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.patch("/api/products/<product_id>/price")
@login_required
def update_product_price(product_id):
    data = request.get_json(silent=True) or {}
    cents = parse_price_to_cents(data.get("price"))
    if cents is None:
        return jsonify({"error": "Enter a valid, non-negative price."}), 400
    conn = get_db()
    row = conn.execute("SELECT id FROM products WHERE id = ?", (product_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Product not found."}), 404
    display = f"${cents / 100:,.2f}"
    conn.execute("UPDATE products SET price = ?, price_cents = ? WHERE id = ?", (display, cents, product_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "price": display, "price_cents": cents})


@app.get("/api/apparel")
def list_apparel():
    conn = get_db()
    rows = conn.execute("SELECT * FROM apparel WHERE active = 1 ORDER BY category ASC, sort_order ASC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.post("/api/apparel")
@login_required
def add_apparel():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    category = (data.get("category") or "").strip().lower()
    image_path = (data.get("image_path") or "").strip()
    if not name or category not in ("tshirt", "hoodie", "hat") or not image_path:
        return jsonify({"error": "name, category (tshirt/hoodie/hat), and image_path are required."}), 400
    cents = parse_price_to_cents(data.get("price", "0"))
    if cents is None:
        return jsonify({"error": "Enter a valid, non-negative price."}), 400
    description = (data.get("description") or "").strip()
    conn = get_db()
    next_order = conn.execute("SELECT COALESCE(MAX(sort_order),0)+1 FROM apparel").fetchone()[0]
    new_id = f"{category}-{secrets.token_hex(4)}"
    conn.execute(
        "INSERT INTO apparel (id, name, category, price, price_cents, image_path, sort_order, description) VALUES (?,?,?,?,?,?,?,?)",
        (new_id, name, category, f"${cents / 100:,.2f}", cents, image_path, next_order, description),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": new_id})


@app.post("/api/apparel/upload-image")
@login_required
def upload_apparel_image():
    """Uploads a real product photo for a new apparel listing and returns the
    relative path to hand to POST /api/apparel as image_path. Mirrors the
    validation shape of /api/tracks/upload (extension check + size cap), plus a
    magic-byte sniff since this accepts images rather than admin-only video files."""
    file = request.files.get("image")
    data, _media_type, err = _read_and_validate_image(file)
    if err:
        response, status = err
        return response, status

    ext = file.filename.rsplit(".", 1)[-1].lower()
    base_name = secure_filename(file.filename.rsplit(".", 1)[0]) or "apparel"
    filename = f"{base_name}-{secrets.token_hex(4)}.{ext}"
    dest = APPAREL_DIR / filename
    try:
        dest.write_bytes(data)
    except OSError:
        dest.unlink(missing_ok=True)
        return jsonify({
            "error": "Upload failed: the server ran out of storage space. "
                     "An admin needs to free up disk space or increase the disk size."
        }), 507

    return jsonify({"ok": True, "image_path": f"images/apparel/{filename}"})


@app.get("/api/apparel/ai-status")
@login_required
def apparel_ai_status():
    """Lets the Add Item form decide upfront whether to show the "Suggest with AI"
    button or a not-configured note, instead of only finding out after a failed call."""
    return jsonify({"configured": bool(ANTHROPIC_API_KEY)})


@app.post("/api/apparel/describe")
@login_required
def describe_apparel_image():
    """Vision-assisted name/description suggestion for a new apparel listing.
    Accepts either a multipart 'image' file (used by the Add Item form before the
    photo has been permanently uploaded) or a JSON/form 'image_path' referencing an
    already-uploaded file under images/apparel/. Degrades gracefully -- returns a
    structured "not configured" response instead of a 500 -- when ANTHROPIC_API_KEY
    isn't set, so the rest of the Add Item flow never depends on this working."""
    if not ANTHROPIC_API_KEY:
        return jsonify({
            "configured": False,
            "error": "AI suggestions aren't configured yet — add ANTHROPIC_API_KEY to backend/.env to enable this.",
        }), 501

    file = request.files.get("image")
    if file and file.filename:
        data, media_type, err = _read_and_validate_image(file)
        if err:
            response, status = err
            return response, status
    else:
        body = request.get_json(silent=True) or {}
        rel_path = (body.get("image_path") or request.form.get("image_path") or "").strip()
        if not rel_path.startswith("images/apparel/"):
            return jsonify({"error": "Provide an 'image' file or an image_path under images/apparel/."}), 400
        abs_path = (SITE_DIR / rel_path).resolve()
        try:
            abs_path.relative_to(APPAREL_DIR.resolve())
        except ValueError:
            return jsonify({"error": "Image not found."}), 404
        if not abs_path.is_file():
            return jsonify({"error": "Image not found."}), 404
        ext = abs_path.suffix.lstrip(".").lower()
        if ext not in ALLOWED_IMAGE_EXTENSIONS:
            return jsonify({"error": "Unsupported image type."}), 400
        data = abs_path.read_bytes()
        if len(data) > MAX_IMAGE_BYTES:
            return jsonify({"error": f"That image is too large ({MAX_IMAGE_BYTES // (1024*1024)}MB limit)."}), 413
        kind = _sniff_image_kind(data[:16])
        if not kind:
            return jsonify({"error": "That file doesn't look like a valid image."}), 400
        media_type = _KIND_TO_MEDIA_TYPE[kind]

    prompt = (
        "This is a product photo or mockup for an apparel listing on Msanii Halisi, a comfort-wear "
        "brand about authenticity, frequency, healing, and ascension — the tone is soft, introspective, "
        "and grounded, never hype-streetwear loud. Based only on what's actually visible in the photo, "
        "suggest a short product name (a few words) and a 1-2 sentence marketing description in that "
        "voice. Respond with ONLY minified JSON in this exact shape, no other text: "
        '{"name": "...", "description": "..."}'
    )
    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        response = client.messages.create(
            model="claude-sonnet-5",
            max_tokens=300,
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": media_type,
                            "data": base64.b64encode(data).decode("ascii"),
                        },
                    },
                    {"type": "text", "text": prompt},
                ],
            }],
        )
        raw_text = "".join(block.text for block in response.content if block.type == "text").strip()
        suggestion = json.loads(raw_text)
        name = str(suggestion.get("name") or "").strip()
        description = str(suggestion.get("description") or "").strip()
        if not name and not description:
            raise ValueError("Empty suggestion")
    except anthropic.AnthropicError as e:
        return jsonify({"configured": True, "error": f"AI request failed: {e}"}), 502
    except (ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError):
        return jsonify({
            "configured": True,
            "error": "The AI response wasn't in the expected format — try again or fill this in manually.",
        }), 502

    return jsonify({"configured": True, "name": name, "description": description})


@app.patch("/api/apparel/<item_id>")
@login_required
def edit_apparel(item_id):
    conn = get_db()
    row = conn.execute("SELECT id FROM apparel WHERE id = ? AND active = 1", (item_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Item not found."}), 404
    data = request.get_json(silent=True) or {}
    fields, values = [], []
    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            conn.close()
            return jsonify({"error": "name cannot be empty."}), 400
        fields.append("name = ?")
        values.append(name)
    if "description" in data:
        fields.append("description = ?")
        values.append((data.get("description") or "").strip())
    if "category" in data:
        category = (data.get("category") or "").strip().lower()
        if category not in ("tshirt", "hoodie", "hat"):
            conn.close()
            return jsonify({"error": "category must be tshirt, hoodie, or hat."}), 400
        fields.append("category = ?")
        values.append(category)
    if not fields:
        conn.close()
        return jsonify({"error": "Nothing to update."}), 400
    values.append(item_id)
    conn.execute(f"UPDATE apparel SET {', '.join(fields)} WHERE id = ?", values)
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.delete("/api/apparel/<item_id>")
@login_required
def delete_apparel(item_id):
    conn = get_db()
    conn.execute("UPDATE apparel SET active = 0 WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.patch("/api/apparel/<item_id>/price")
@login_required
def update_apparel_price(item_id):
    data = request.get_json(silent=True) or {}
    cents = parse_price_to_cents(data.get("price"))
    if cents is None:
        return jsonify({"error": "Enter a valid, non-negative price."}), 400
    conn = get_db()
    row = conn.execute("SELECT id FROM apparel WHERE id = ?", (item_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Item not found."}), 404
    display = f"${cents / 100:,.2f}"
    conn.execute("UPDATE apparel SET price = ?, price_cents = ? WHERE id = ?", (display, cents, item_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "price": display, "price_cents": cents})


#   Albums -- purchasable bundles of 2+ already-uploaded songs (tracks.type
#   == 'audio'). See the albums/album_tracks tables in init_db() above.
# ==================================================================

MIN_ALBUM_TRACKS = 2


def _album_track_rows(album_id):
    """Every track belonging to an album, in the order picked when the album
    was created. Deliberately not filtered on tracks.active -- an album's
    track list is a point-in-time curation decision by the admin, not a live
    view of the storefront catalogue, so delisting a song from the main
    player list later shouldn't silently shrink an album someone already
    bought."""
    conn = get_db()
    rows = conn.execute(
        """SELECT t.* FROM album_tracks at
           JOIN tracks t ON t.id = at.track_id
           WHERE at.album_id = ?
           ORDER BY at.sort_order ASC""",
        (album_id,),
    ).fetchall()
    conn.close()
    return rows


@app.post("/api/albums/cover-upload")
@login_required
def upload_album_cover():
    """Uploads cover art for a new album and returns the relative path to hand
    to POST /api/albums as cover_path. Mirrors /api/apparel/upload-image."""
    file = request.files.get("image")
    data, _media_type, err = _read_and_validate_image(file)
    if err:
        response, status = err
        return response, status

    ext = file.filename.rsplit(".", 1)[-1].lower()
    base_name = secure_filename(file.filename.rsplit(".", 1)[0]) or "album"
    filename = f"{base_name}-{secrets.token_hex(4)}.{ext}"
    dest = ALBUMS_DIR / filename
    try:
        dest.write_bytes(data)
    except OSError:
        dest.unlink(missing_ok=True)
        return jsonify({
            "error": "Upload failed: the server ran out of storage space. "
                     "An admin needs to free up disk space or increase the disk size."
        }), 507

    return jsonify({"ok": True, "cover_path": f"images/albums/{filename}"})


@app.get("/api/albums")
def list_albums():
    conn = get_db()
    rows = conn.execute("SELECT * FROM albums WHERE active = 1 ORDER BY sort_order ASC").fetchall()
    conn.close()
    albums = []
    for row in rows:
        tracks = _album_track_rows(row["id"])
        album = dict(row)
        album["tracks"] = [
            {"id": t["id"], "title": t["title"], "artist": t["artist"], "len": t["len"]}
            for t in tracks
        ]
        album["track_count"] = len(tracks)
        albums.append(album)
    return jsonify(albums)


@app.post("/api/albums")
@login_required
def add_album():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    artist = (data.get("artist") or "").strip()
    cover_path = (data.get("cover_path") or "").strip()
    track_ids = data.get("track_ids") or []
    if not title or not artist or not cover_path:
        return jsonify({"error": "title, artist, and cover_path are required."}), 400
    if not isinstance(track_ids, list) or len(track_ids) < MIN_ALBUM_TRACKS:
        return jsonify({"error": f"Pick at least {MIN_ALBUM_TRACKS} songs for the album."}), 400
    cents = parse_price_to_cents(data.get("price", "0"))
    if cents is None:
        return jsonify({"error": "Enter a valid, non-negative price."}), 400

    conn = get_db()
    placeholders = ",".join("?" for _ in track_ids)
    found = conn.execute(
        f"SELECT id FROM tracks WHERE id IN ({placeholders}) "
        f"AND (src LIKE 'audio/%' OR src LIKE 'videos/%')", track_ids
    ).fetchall()
    found_ids = {r["id"] for r in found}
    missing = [t for t in track_ids if t not in found_ids]
    if missing:
        conn.close()
        return jsonify({
            "error": "One or more selected tracks couldn't be found (albums can only be built from "
                     "already-uploaded local audio/video files, not embedded links): " + ", ".join(missing)
        }), 400

    next_order = conn.execute("SELECT COALESCE(MAX(sort_order),0)+1 FROM albums").fetchone()[0]
    new_id = f"album-{secrets.token_hex(4)}"
    conn.execute(
        "INSERT INTO albums (id, title, artist, price, price_cents, cover_path, sort_order) VALUES (?,?,?,?,?,?,?)",
        (new_id, title, artist, f"${cents / 100:,.2f}", cents, cover_path, next_order),
    )
    for i, track_id in enumerate(track_ids):
        conn.execute(
            "INSERT INTO album_tracks (album_id, track_id, sort_order) VALUES (?,?,?)",
            (new_id, track_id, i),
        )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": new_id})


@app.patch("/api/albums/<album_id>/price")
@login_required
def update_album_price(album_id):
    data = request.get_json(silent=True) or {}
    cents = parse_price_to_cents(data.get("price"))
    if cents is None:
        return jsonify({"error": "Enter a valid, non-negative price."}), 400
    conn = get_db()
    row = conn.execute("SELECT id FROM albums WHERE id = ?", (album_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Album not found."}), 404
    display = f"${cents / 100:,.2f}"
    conn.execute("UPDATE albums SET price = ?, price_cents = ? WHERE id = ?", (display, cents, album_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "price": display, "price_cents": cents})


@app.delete("/api/albums/<album_id>")
@login_required
def delete_album(album_id):
    conn = get_db()
    conn.execute("UPDATE albums SET active = 0 WHERE id = ?", (album_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


def _build_album_zip(album_id):
    """Returns (BytesIO, album_row) with a zip of every track's local media
    file in the album (audio/ or videos/ uploads -- embed-only tracks have no
    downloadable file and are skipped), or (None, album_row/None) if the
    album or none of its files can be found on disk."""
    conn = get_db()
    album = conn.execute("SELECT * FROM albums WHERE id = ?", (album_id,)).fetchone()
    conn.close()
    if not album:
        return None, None
    tracks = _album_track_rows(album_id)

    buf = io.BytesIO()
    included = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, t in enumerate(tracks, start=1):
            src = t["src"] or ""
            if src.startswith("audio/"):
                base_dir = AUDIO_DIR
            elif src.startswith("videos/"):
                base_dir = VIDEOS_DIR
            else:
                continue
            path = base_dir / src.split("/", 1)[-1]
            if not path.is_file():
                continue
            ext = path.suffix
            safe_title = re.sub(r'[\\/:*?"<>|]', "-", t["title"]) or t["id"]
            zf.writestr(f"{i:02d} - {safe_title}{ext}", path.read_bytes())
            included += 1
    if included == 0:
        return None, album
    buf.seek(0)
    return buf, album


@app.get("/api/albums/<album_id>/download")
@login_required
def admin_download_album(album_id):
    """Admin-only: download the zip an album's buyer would receive, for
    previewing/testing the bundle without needing a real Stripe purchase."""
    buf, album = _build_album_zip(album_id)
    if not album:
        return jsonify({"error": "Album not found."}), 404
    if not buf:
        return jsonify({"error": "None of this album's songs have an audio file on disk."}), 404
    safe_title = re.sub(r'[\\/:*?"<>|]', "-", album["title"]) or album_id
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=f"{safe_title}.zip")


@app.get("/api/settings/marquee")
def get_marquee():
    return jsonify({"text": get_setting("marquee_text", DEFAULT_MARQUEE_TEXT)})


@app.patch("/api/settings/marquee")
@login_required
def update_marquee():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "Announcement text cannot be empty."}), 400
    set_setting("marquee_text", text[:500])
    return jsonify({"ok": True, "text": text[:500]})


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@app.post("/api/subscribe")
def subscribe():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not _EMAIL_RE.match(email):
        return jsonify({"error": "Enter a valid email address."}), 400
    conn = get_db()
    try:
        conn.execute("INSERT INTO subscribers (email, source) VALUES (?, ?)", (email, data.get("source", "site")))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()
    return jsonify({"ok": True})


@app.get("/api/subscribers")
@login_required
def list_subscribers():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, email, source, created_at FROM subscribers WHERE active = 1 ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.delete("/api/subscribers/<int:subscriber_id>")
@login_required
def delete_subscriber(subscriber_id):
    conn = get_db()
    conn.execute("UPDATE subscribers SET active = 0 WHERE id = ?", (subscriber_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


def _stripe_configured():
    return bool(STRIPE_SECRET_KEY)


@app.post("/api/checkout")
def create_checkout_session():
    if not _stripe_configured():
        return jsonify({
            "error": "Checkout isn't live yet — Stripe isn't configured. "
                     "Set STRIPE_SECRET_KEY in backend/.env to enable it."
        }), 501

    data = request.get_json(silent=True) or {}
    item_ids = data.get("items") or []
    if not item_ids:
        return jsonify({"error": "No items provided."}), 400

    conn = get_db()
    placeholders = ",".join("?" for _ in item_ids)
    rows = conn.execute(
        f"""
        SELECT id, name, price_cents, is_physical FROM products WHERE id IN ({placeholders}) AND active = 1
        UNION ALL
        SELECT id, name, price_cents, 1 AS is_physical FROM apparel WHERE id IN ({placeholders}) AND active = 1
        UNION ALL
        SELECT id, title AS name, price_cents, 0 AS is_physical FROM albums WHERE id IN ({placeholders}) AND active = 1
        """,
        item_ids + item_ids + item_ids,
    ).fetchall()
    conn.close()

    if not rows:
        return jsonify({"error": "None of those products are available."}), 400

    line_items = [
        {"price_data": {"currency": "usd", "product_data": {"name": row["name"]}, "unit_amount": row["price_cents"]}, "quantity": 1}
        for row in rows
    ]
    needs_shipping = any(row["is_physical"] for row in rows)
    amount_total = sum(row["price_cents"] for row in rows)

    site_url = request.host_url.rstrip("/")
    session_kwargs = dict(
        mode="payment", line_items=line_items,
        # {CHECKOUT_SESSION_ID} is a Stripe-reserved placeholder it substitutes
        # on redirect -- the success page uses it to ask
        # GET /api/orders/by-session/<id> for any digital (album) download
        # links, since purchases are confirmed server-side via webhook, not
        # trusted from the client redirect alone.
        success_url=f"{site_url}/?checkout=success&session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{site_url}/?checkout=cancelled",
    )
    if needs_shipping:
        session_kwargs["shipping_address_collection"] = {"allowed_countries": ["US"]}

    try:
        checkout_session = stripe.checkout.Session.create(**session_kwargs)
    except stripe.error.StripeError as e:
        return jsonify({"error": str(e)}), 502

    conn = get_db()
    conn.execute(
        "INSERT INTO orders (id, stripe_session_id, items, amount_total, status) VALUES (?,?,?,?,?)",
        (f"ord_{secrets.token_hex(8)}", checkout_session.id, json.dumps([row["id"] for row in rows]), amount_total, "pending"),
    )
    conn.commit()
    conn.close()

    return jsonify({"url": checkout_session.url})


@app.post("/api/webhooks/stripe")
def stripe_webhook():
    if not _stripe_configured() or not STRIPE_WEBHOOK_SECRET:
        return jsonify({"error": "Webhook not configured."}), 501
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        return jsonify({"error": "Invalid webhook signature."}), 400

    if event["type"] == "checkout.session.completed":
        obj = event["data"]["object"]
        conn = get_db()
        shipping_details = obj.get("shipping_details") or {}
        # A per-order secret, generated only once a webhook has actually confirmed
        # payment -- this is what lets the success page hand back an album
        # download link that can't be guessed from the order id alone (see
        # /api/orders/by-session/<id> and /api/orders/<id>/download/<album_id>).
        download_token = secrets.token_urlsafe(24)
        conn.execute(
            """UPDATE orders SET status = 'paid', customer_email = ?,
               shipping_name = ?, shipping_address = ?, download_token = ? WHERE stripe_session_id = ?""",
            (obj.get("customer_details", {}).get("email"), shipping_details.get("name"),
             json.dumps(shipping_details.get("address")) if shipping_details.get("address") else None,
             download_token, obj["id"]),
        )
        # Log a 'purchase' analytics event per line item -- this is the strongest
        # per-item performance signal (view -> checkout-start -> purchase), and it's
        # logged here rather than trusting a client-side callback, since a webhook
        # firing is the only proof a purchase actually completed. No visitor_id is
        # attached: Stripe calls this endpoint server-to-server, so there's no
        # mh_visitor cookie on this request to attribute it to.
        order_row = conn.execute(
            "SELECT items FROM orders WHERE stripe_session_id = ?", (obj["id"],)
        ).fetchone()
        if order_row and order_row["items"]:
            try:
                item_ids = json.loads(order_row["items"])
            except (TypeError, ValueError):
                item_ids = []
            for item_id in item_ids:
                label_row = conn.execute(
                    "SELECT name FROM apparel WHERE id = ? UNION ALL SELECT name FROM products WHERE id = ? "
                    "UNION ALL SELECT title AS name FROM albums WHERE id = ?",
                    (item_id, item_id, item_id),
                ).fetchone()
                item_label = label_row["name"] if label_row else item_id
                conn.execute(
                    "INSERT INTO analytics_events (event_type, item_id, item_label, visitor_id) VALUES ('purchase', ?, ?, '')",
                    (item_id, item_label),
                )
        conn.commit()
        conn.close()

    return jsonify({"received": True})


@app.get("/api/orders")
@login_required
def list_orders():
    conn = get_db()
    rows = conn.execute("SELECT * FROM orders ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.get("/api/orders/by-session/<stripe_session_id>")
def order_by_session(stripe_session_id):
    """Public (no login) lookup used by the checkout success page -- Stripe
    redirects the buyer here with their own session id, which is the only
    thing proving they're the one who just paid. Returns any purchased
    albums' download links once the webhook has marked the order 'paid';
    before that (webhook lag, or Stripe not configured) it reports 'pending'
    so the success page can say "hang tight" instead of erroring."""
    conn = get_db()
    order = conn.execute(
        "SELECT * FROM orders WHERE stripe_session_id = ?", (stripe_session_id,)
    ).fetchone()
    if not order:
        conn.close()
        return jsonify({"error": "Order not found."}), 404

    albums = []
    if order["status"] == "paid" and order["download_token"]:
        try:
            item_ids = json.loads(order["items"] or "[]")
        except (TypeError, ValueError):
            item_ids = []
        if item_ids:
            placeholders = ",".join("?" for _ in item_ids)
            album_rows = conn.execute(
                f"SELECT id, title, artist, cover_path FROM albums WHERE id IN ({placeholders})", item_ids
            ).fetchall()
            albums = [
                {
                    "id": a["id"], "title": a["title"], "artist": a["artist"], "cover_path": a["cover_path"],
                    "download_url": f"/api/orders/{order['id']}/download/{a['id']}?token={order['download_token']}",
                }
                for a in album_rows
            ]
    conn.close()
    return jsonify({"status": order["status"], "albums": albums})


@app.get("/api/orders/<order_id>/download/<album_id>")
def order_download_album(order_id, album_id):
    """Token-gated digital delivery: proves the requester actually paid for
    this specific order (the token is only ever generated server-side, by the
    Stripe webhook, once payment is confirmed -- see stripe_webhook()) before
    streaming the album's zip. An already-authenticated admin can also use
    this without a token, for support/testing."""
    conn = get_db()
    order = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    conn.close()
    if not order:
        return jsonify({"error": "Order not found."}), 404

    is_admin = bool(session.get("admin_id"))
    token = request.args.get("token", "")
    if not is_admin:
        if order["status"] != "paid" or not order["download_token"] or not secrets.compare_digest(token, order["download_token"]):
            return jsonify({"error": "Invalid or expired download link."}), 403

    try:
        item_ids = json.loads(order["items"] or "[]")
    except (TypeError, ValueError):
        item_ids = []
    if album_id not in item_ids:
        return jsonify({"error": "That album isn't part of this order."}), 404

    buf, album = _build_album_zip(album_id)
    if not album:
        return jsonify({"error": "Album not found."}), 404
    if not buf:
        return jsonify({"error": "None of this album's songs have an audio file on disk."}), 404
    safe_title = re.sub(r'[\\/:*?"<>|]', "-", album["title"]) or album_id
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=f"{safe_title}.zip")


@app.get("/api/orders/<order_id>/shipping-rates")
@login_required
def order_shipping_rates(order_id):
    conn = get_db()
    order = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    conn.close()
    if not order:
        return jsonify({"error": "Order not found."}), 404
    if not order["shipping_address"]:
        return jsonify({"error": "This order has no shipping address on file."}), 400
    try:
        address = json.loads(order["shipping_address"])
        address_to = {
            "name": order["shipping_name"] or "", "street1": address.get("line1", ""),
            "city": address.get("city", ""), "state": address.get("state", ""),
            "zip": address.get("postal_code", ""), "country": address.get("country", "US"),
        }
        parcel = {"length": "10", "width": "8", "height": "4", "distance_unit": "in", "weight": "1", "mass_unit": "lb"}
        rates = shipping.get_rates(address_to, parcel)
    except shipping.ShippingNotConfigured as e:
        return jsonify({"error": str(e)}), 501
    return jsonify(rates)


@app.post("/api/orders/<order_id>/ship")
@login_required
def order_ship(order_id):
    data = request.get_json(silent=True) or {}
    rate_id = data.get("rate_id")
    if not rate_id:
        return jsonify({"error": "rate_id is required (pick one from /shipping-rates first)."}), 400
    try:
        label = shipping.buy_label(rate_id)
    except shipping.ShippingNotConfigured as e:
        return jsonify({"error": str(e)}), 501
    conn = get_db()
    conn.execute(
        """UPDATE orders SET status = 'shipped', carrier = ?, tracking_number = ?,
           shipping_label_url = ? WHERE id = ?""",
        (label.get("carrier"), label.get("tracking_number"), label.get("label_url"), order_id),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, **label})


# ==================================================================
# Analytics — admin dashboard
# ==================================================================

def _visit_totals(conn, since_expr=None):
    if since_expr is None:
        where, params = "is_bot = 0", ()
    else:
        where, params = "is_bot = 0 AND created_at >= datetime('now', ?)", (since_expr,)
    visits = conn.execute(f"SELECT COUNT(*) FROM page_views WHERE {where}", params).fetchone()[0]
    uniques = conn.execute(
        f"SELECT COUNT(DISTINCT visitor_id) FROM page_views WHERE {where}", params
    ).fetchone()[0]
    return {"visits": visits, "unique_visitors": uniques}


def build_analytics_summary():
    conn = get_db()

    totals = {
        "all_time": _visit_totals(conn),
        "last_7d": _visit_totals(conn, "-7 days"),
        "last_30d": _visit_totals(conn, "-30 days"),
    }

    locations = [
        dict(r) for r in conn.execute(
            """SELECT country, city, COUNT(*) AS visits, COUNT(DISTINCT visitor_id) AS unique_visitors
               FROM page_views WHERE is_bot = 0 GROUP BY country, city ORDER BY visits DESC LIMIT 15"""
        ).fetchall()
    ]

    device_rows = conn.execute(
        "SELECT device_type, COUNT(*) AS c FROM page_views WHERE is_bot = 0 GROUP BY device_type"
    ).fetchall()
    device_total = sum(r["c"] for r in device_rows) or 1
    devices = {
        (r["device_type"] or "unknown"): {"count": r["c"], "pct": round(r["c"] / device_total * 100, 1)}
        for r in device_rows
    }

    browsers = [
        {"browser": r["browser"] or "Unknown", "count": r["c"], "pct": round(r["c"] / device_total * 100, 1)}
        for r in conn.execute(
            "SELECT browser, COUNT(*) AS c FROM page_views WHERE is_bot = 0 GROUP BY browser ORDER BY c DESC LIMIT 10"
        ).fetchall()
    ]

    referrers = [
        dict(r) for r in conn.execute(
            """SELECT COALESCE(NULLIF(TRIM(referrer), ''), 'Direct / None') AS referrer, COUNT(*) AS count
               FROM page_views WHERE is_bot = 0 GROUP BY referrer ORDER BY count DESC LIMIT 10"""
        ).fetchall()
    ]

    # Daily traffic for the last 30 days, zero-filled so the chart has no gaps.
    daily_rows = {
        r["d"]: {"visits": r["visits"], "unique_visitors": r["uniques"]}
        for r in conn.execute(
            """SELECT date(created_at) AS d, COUNT(*) AS visits, COUNT(DISTINCT visitor_id) AS uniques
               FROM page_views WHERE is_bot = 0 AND created_at >= date('now', '-29 days')
               GROUP BY d ORDER BY d ASC"""
        ).fetchall()
    }
    today = datetime.utcnow().date()
    daily_traffic = []
    for i in range(29, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        entry = daily_rows.get(d, {"visits": 0, "unique_visitors": 0})
        daily_traffic.append({"date": d, **entry})

    # Top tracks/videos by play count -- every active track, ranked, including
    # zero-play ones so a brand-new or dud upload is visible too.
    track_rows = conn.execute("SELECT id, title, artist FROM tracks WHERE active = 1").fetchall()
    play_counts = {
        r["item_id"]: r["c"] for r in conn.execute(
            "SELECT item_id, COUNT(*) AS c FROM analytics_events WHERE event_type = 'track_play' GROUP BY item_id"
        ).fetchall()
    }
    top_tracks = sorted(
        [
            {"id": t["id"], "title": t["title"], "artist": t["artist"], "plays": play_counts.get(t["id"], 0)}
            for t in track_rows
        ],
        key=lambda x: -x["plays"],
    )

    # Apparel performance: views (quick-view opens) -> checkout-starts -> purchases,
    # for every currently-active apparel item, with a computed conversion rate.
    # Small per-item queries are fine at boutique catalog sizes (tens of items);
    # if this ever needs to scale to hundreds of SKUs, switch to a single
    # GROUP BY item_id query joined against the apparel table.
    apparel_rows = conn.execute(
        "SELECT id, name, category FROM apparel WHERE active = 1 ORDER BY sort_order ASC"
    ).fetchall()
    apparel_performance = []
    for a in apparel_rows:
        views = conn.execute(
            "SELECT COUNT(*) FROM analytics_events WHERE event_type = 'apparel_quickview' AND item_id = ?", (a["id"],)
        ).fetchone()[0]
        starts = conn.execute(
            "SELECT COUNT(*) FROM analytics_events WHERE event_type = 'checkout_start' AND item_id = ?", (a["id"],)
        ).fetchone()[0]
        purchases = conn.execute(
            "SELECT COUNT(*) FROM analytics_events WHERE event_type = 'purchase' AND item_id = ?", (a["id"],)
        ).fetchone()[0]
        conversion_rate = round(purchases / views * 100, 1) if views else 0.0
        apparel_performance.append({
            "id": a["id"], "name": a["name"], "category": a["category"],
            "views": views, "checkout_starts": starts, "purchases": purchases,
            "conversion_rate": conversion_rate,
        })
    apparel_performance.sort(key=lambda x: (-x["purchases"], -x["conversion_rate"], -x["views"]))

    conn.close()

    return {
        "totals": totals,
        "locations": locations,
        "devices": devices,
        "browsers": browsers,
        "referrers": referrers,
        "daily_traffic": daily_traffic,
        "top_tracks": top_tracks,
        "apparel_performance": apparel_performance,
    }


@app.get("/api/analytics/summary")
@login_required
def analytics_summary():
    return jsonify(build_analytics_summary())


@app.get("/admin/analytics")
@login_required
def admin_analytics():
    return render_template("admin_analytics.html")


# ==================================================================
# Socket.IO — live chat, WebRTC signaling relay, camera-join workflow
#
# This is a pure signaling relay: the server never touches media, it only
# forwards chat text and SDP/ICE JSON between socket ids or to a room.
# ==================================================================

@socketio.on("join_room")
def on_join_room(data):
    room_code = data.get("room")
    role = data.get("role", "viewer")  # 'host' | 'viewer'
    name = data.get("name", "Guest")
    if not room_code:
        return
    join_room(room_code)
    live_session = get_live_session_by_room(room_code)
    if live_session:
        history = [dict(m) for m in list_chat_messages(live_session["id"])]
        emit("chat_history", {"messages": history})
    emit("presence", {"role": role, "name": name, "sid": request.sid}, to=room_code, include_self=False)


@socketio.on("chat_message")
def on_chat_message(data):
    room_code = data.get("room")
    name = data.get("name", "Guest")
    message = (data.get("message") or "").strip()
    if not room_code or not message:
        return
    live_session = get_live_session_by_room(room_code)
    if not live_session:
        return
    add_chat_message(live_session["id"], name, message)
    emit("chat_message", {"name": name, "message": message}, to=room_code)


@socketio.on("host_go_live")
def on_host_go_live(data):
    room_code = data.get("room")
    live_session = get_live_session_by_room(room_code)
    if not live_session:
        return
    set_live_status(live_session["id"], "live")
    emit("live_status", {"status": "live"}, to=room_code)


@socketio.on("host_end_live")
def on_host_end_live(data):
    room_code = data.get("room")
    live_session = get_live_session_by_room(room_code)
    if not live_session:
        return
    set_live_status(live_session["id"], "ended")
    emit("live_status", {"status": "ended"}, to=room_code)


@socketio.on("camera_offer")
def on_camera_offer(data):
    # Viewer sends its WebRTC offer up front (not after approval) so the host
    # can preview their live camera/mic before deciding -- this event carries
    # both the join request and the SDP that used to arrive separately, later,
    # only once approved.
    room_code = data.get("room")
    name = data.get("name", "Guest")
    sdp = data.get("sdp")
    if not sdp:
        return
    live_session = get_live_session_by_room(room_code)
    if not live_session:
        return
    req_id = create_camera_request(live_session["id"], name, request.sid)
    emit(
        "camera_offer",
        {"request_id": req_id, "name": name, "sdp": sdp, "socket_id": request.sid},
        to=room_code,
        include_self=False,
    )


@socketio.on("respond_camera")
def on_respond_camera(data):
    room_code = data.get("room")
    request_id = data.get("request_id")
    approve = bool(data.get("approve"))
    req = get_camera_request(request_id)
    if not req:
        return
    set_camera_request_status(request_id, "approved" if approve else "denied")
    emit(
        "camera_response",
        {"request_id": request_id, "approve": approve, "host_sid": request.sid},
        to=req["socket_id"],
    )
    if approve:
        emit("guest_joining", {"socket_id": req["socket_id"], "name": req["viewer_name"]}, to=room_code)


# ---- WebRTC signaling relay (direct socket-to-socket, not room broadcast) ----

@socketio.on("webrtc_signal")
def on_webrtc_signal(data):
    target_sid = data.get("to")
    if not target_sid:
        return
    payload = dict(data)
    payload["from"] = request.sid
    emit("webrtc_signal", payload, to=target_sid)


init_db()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 8845))
    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
