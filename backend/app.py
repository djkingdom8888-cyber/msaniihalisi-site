from gevent import monkey
monkey.patch_all()

import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import time
import secrets
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import requests
import stripe
from dotenv import load_dotenv
from flask import Flask, g, jsonify, render_template, request, session, send_from_directory
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
        """
    )
    conn.commit()

    # Safe idempotent migration: apparel predates having a description field,
    # so existing databases need it added rather than recreated.
    existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(apparel)").fetchall()}
    if "description" not in existing_cols:
        conn.execute("ALTER TABLE apparel ADD COLUMN description TEXT NOT NULL DEFAULT ''")
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
    device_type, browser = parse_user_agent(request.headers.get("User-Agent", ""))
    referrer = (request.headers.get("Referer", "") or "")[:500]
    conn = get_db()
    conn.execute(
        """INSERT INTO page_views (path, ip_address, country, city, device_type, browser, referrer, visitor_id)
           VALUES (?,?,?,?,?,?,?,?)""",
        (path, ip, country, city, device_type, browser, referrer, g.visitor_id),
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


@app.get("/api/tracks")
def list_tracks():
    conn = get_db()
    rows = conn.execute("SELECT * FROM tracks WHERE active = 1 ORDER BY sort_order ASC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.delete("/api/tracks/<track_id>")
@login_required
def delete_track(track_id):
    conn = get_db()
    row = conn.execute("SELECT src FROM tracks WHERE id = ?", (track_id,)).fetchone()
    conn.execute("UPDATE tracks SET active = 0 WHERE id = ?", (track_id,))
    conn.commit()
    conn.close()
    # Uploaded videos are stored under unique-per-upload filenames, so it's safe to
    # remove the file from disk once its track is delisted — nothing else references it.
    # (Soft-delete only flips `active`; without this the persistent disk fills up with
    # orphaned video files from every replaced/removed upload.)
    if row and row["src"] and row["src"].startswith("videos/"):
        _delete_video_file_if_unreferenced(row["src"])
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
    file = request.files.get("video")
    if not file or not file.filename:
        return jsonify({"error": "No file uploaded."}), 400

    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_VIDEO_EXTENSIONS:
        return jsonify({"error": f"Unsupported file type .{ext}. Allowed: {', '.join(sorted(ALLOWED_VIDEO_EXTENSIONS))}"}), 400

    base_name = secure_filename(file.filename.rsplit(".", 1)[0]) or "video"
    filename = f"{base_name}-{secrets.token_hex(4)}.{ext}"
    dest = VIDEOS_DIR / filename
    try:
        file.save(dest)
    except OSError as e:
        # e.g. errno 28 "No space left on device" if the persistent disk is full.
        dest.unlink(missing_ok=True)
        return jsonify({
            "error": "Upload failed: the server ran out of storage space. "
                     "An admin needs to free up disk space (delete old videos) or increase the disk size."
        }), 507

    seconds = _video_duration_seconds(dest)
    title = (request.form.get("title") or base_name.replace("-", " ").replace("_", " ").title()).strip()
    artist = (request.form.get("artist") or "Msanii Halisi").strip()

    conn = get_db()
    next_order = conn.execute("SELECT COALESCE(MAX(sort_order),0)+1 FROM tracks").fetchone()[0]
    new_id = f"video-{secrets.token_hex(4)}"
    conn.execute(
        "INSERT INTO tracks (id, title, artist, len, seconds, src, type, sort_order) VALUES (?,?,?,?,?,?,?,?)",
        (new_id, title, artist, _format_len(seconds), int(seconds), f"videos/{filename}", "video", next_order),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": new_id, "title": title, "artist": artist})


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


@app.post("/live/<room_code>/upload-recording")
@login_required
def upload_recording(room_code):
    live_session = get_live_session_by_room(room_code)
    if not live_session:
        return jsonify({"error": "Live session not found."}), 404
    file = request.files.get("recording")
    if not file:
        return jsonify({"error": "no file"}), 400
    filename = f"live-{room_code}-{secrets.token_hex(4)}.webm"
    dest = VIDEOS_DIR / filename
    try:
        file.save(dest)
    except OSError:
        dest.unlink(missing_ok=True)
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
        """,
        item_ids + item_ids,
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
        success_url=f"{site_url}/?checkout=success", cancel_url=f"{site_url}/?checkout=cancelled",
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
        conn.execute(
            """UPDATE orders SET status = 'paid', customer_email = ?,
               shipping_name = ?, shipping_address = ? WHERE stripe_session_id = ?""",
            (obj.get("customer_details", {}).get("email"), shipping_details.get("name"),
             json.dumps(shipping_details.get("address")) if shipping_details.get("address") else None, obj["id"]),
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
                    "SELECT name FROM apparel WHERE id = ? UNION ALL SELECT name FROM products WHERE id = ?",
                    (item_id, item_id),
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
        where, params = "1=1", ()
    else:
        where, params = "created_at >= datetime('now', ?)", (since_expr,)
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
               FROM page_views GROUP BY country, city ORDER BY visits DESC LIMIT 15"""
        ).fetchall()
    ]

    device_rows = conn.execute(
        "SELECT device_type, COUNT(*) AS c FROM page_views GROUP BY device_type"
    ).fetchall()
    device_total = sum(r["c"] for r in device_rows) or 1
    devices = {
        (r["device_type"] or "unknown"): {"count": r["c"], "pct": round(r["c"] / device_total * 100, 1)}
        for r in device_rows
    }

    browsers = [
        {"browser": r["browser"] or "Unknown", "count": r["c"], "pct": round(r["c"] / device_total * 100, 1)}
        for r in conn.execute(
            "SELECT browser, COUNT(*) AS c FROM page_views GROUP BY browser ORDER BY c DESC LIMIT 10"
        ).fetchall()
    ]

    referrers = [
        dict(r) for r in conn.execute(
            """SELECT COALESCE(NULLIF(TRIM(referrer), ''), 'Direct / None') AS referrer, COUNT(*) AS count
               FROM page_views GROUP BY referrer ORDER BY count DESC LIMIT 10"""
        ).fetchall()
    ]

    # Daily traffic for the last 30 days, zero-filled so the chart has no gaps.
    daily_rows = {
        r["d"]: {"visits": r["visits"], "unique_visitors": r["uniques"]}
        for r in conn.execute(
            """SELECT date(created_at) AS d, COUNT(*) AS visits, COUNT(DISTINCT visitor_id) AS uniques
               FROM page_views WHERE created_at >= date('now', '-29 days')
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
