import json
import os
import re
import sqlite3
import subprocess
import time
import secrets
from pathlib import Path

import stripe
from dotenv import load_dotenv
from flask import Flask, jsonify, request, session, send_from_directory
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
        """
    )
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
    conn.close()


def login_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)

    return wrapper


@app.route("/")
def index():
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
    conn.execute("UPDATE tracks SET active = 0 WHERE id = ?", (track_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


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
    file.save(dest)

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
    conn = get_db()
    next_order = conn.execute("SELECT COALESCE(MAX(sort_order),0)+1 FROM apparel").fetchone()[0]
    new_id = f"{category}-{secrets.token_hex(4)}"
    conn.execute(
        "INSERT INTO apparel (id, name, category, price, price_cents, image_path, sort_order) VALUES (?,?,?,?,?,?,?)",
        (new_id, name, category, f"${cents / 100:,.2f}", cents, image_path, next_order),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": new_id})


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


init_db()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 8845))
    app.run(host=host, port=port, debug=False)
