#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, json, re, base64, hashlib, traceback, io, smtplib, ssl
from http.server import HTTPServer, SimpleHTTPRequestHandler
from email.parser import BytesParser
from email.policy import default as email_default
from email.mime.text import MIMEText
from urllib.parse import quote, urlparse, parse_qs
from dotenv import load_dotenv

load_dotenv()

# === Konfigurace GCS ===
GCS_BUCKET = os.getenv("GCS_BUCKET", "").strip()
GCS_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()

# Cloud cesta pro anime.json (v bucketu)
ANIME_JSON_CLOUD = os.getenv("ANIME_JSON_CLOUD", "data/anime.json")

# Prefixy pro "soukromá" data
USERS_PREFIX = os.getenv("USERS_PREFIX", "private/users")

# Aplikace – veřejná URL, použije se v odkazech v e-mailu (např. https://animecloud.example.com)
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")

# SMTP (pro ověřovací e-maily)
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or "587")
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "no-reply@localhost").strip()
SMTP_TLS  = os.getenv("SMTP_TLS", "true").lower() not in ("0", "false", "no")

# Ostatní
ROOT = os.getcwd()
FEEDBACK_DIR = os.path.join(ROOT, "feedback")
WIPE_PASSWORD = os.getenv("WIPE_PASSWORD", "789456123Lol")

# ===== Helpers =====
def safe_name(name: str) -> str:
    if isinstance(name, bytes):
        name = name.decode("utf-8", "ignore")
    keep = "._-()[]{}@+&= "
    name = "".join(ch for ch in name if ch.isalnum() or ch in keep)
    name = name.replace("/", "").replace("\\", "")
    return name.strip() or "file"

def json_response(h, status: int, obj):
    h.send_response(status)
    h.send_header("Content-Type", "application/json; charset=utf-8")
    h.end_headers()
    h.wfile.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

def ensure_dirs():
    os.makedirs(FEEDBACK_DIR, exist_ok=True)

# MIME map
EXT_MIME = {
    ".mp4":"video/mp4", ".m4v":"video/x-m4v", ".webm":"video/webm", ".mkv":"video/x-matroska", ".mov":"video/quicktime",
    ".srt":"application/x-subrip", ".vtt":"text/vtt",
    ".jpg":"image/jpeg", ".jpeg":"image/jpeg", ".png":"image/png", ".webp":"image/webp", ".gif":"image/gif",
}
VIDEO_EXTS = {".mp4", ".m4v", ".webm", ".mkv", ".mov"}

def guess_mime(filename: str, sniff: bytes|None=None, default: str="application/octet-stream") -> str:
    fn = (filename or "").lower()
    for ext, mime in EXT_MIME.items():
        if fn.endswith(ext):
            return mime
    if sniff:
        if sniff.startswith(b"\x89PNG"): return "image/png"
        if sniff[:3] == b"\xff\xd8\xff": return "image/jpeg"
        if sniff.startswith(b"RIFF") and b"WEBP" in sniff[:16]: return "image/webp"
        if sniff[:4] == b"\x1a\x45\xdf\xa3": return "video/x-matroska"
        if sniff[:4] == b"ftyp": return "video/mp4"
    return default

# ===== Storage: GCS only =====
_gcs_client = None
def _ensure_gcs():
    global _gcs_client
    if _gcs_client is None:
        if not GCS_BUCKET or not GCS_CREDENTIALS:
            raise RuntimeError("GCS not configured (GCS_BUCKET/GOOGLE_APPLICATION_CREDENTIALS)")
        from google.cloud import storage
        _gcs_client = storage.Client()
    return _gcs_client

def gcs_public_url(path_in_bucket: str) -> str:
    parts = [quote(p) for p in path_in_bucket.split("/")]
    return f"https://storage.googleapis.com/{GCS_BUCKET}/{'/'.join(parts)}"

def upload_to_gcs(path_in_bucket: str, raw: bytes, mime: str, overwrite: bool=True) -> str:
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    blob = bucket.blob(path_in_bucket)
    if not overwrite and blob.exists(client):
        raise RuntimeError("exists")
    # veřejné objekty (covers, videa, subs) můžou být cachované dlouho
    blob.cache_control = "public, max-age=31536000, immutable"
    blob.upload_from_string(raw, content_type=(mime or "application/octet-stream"))
    return gcs_public_url(path_in_bucket)

def upload_private_json(path_in_bucket: str, obj: dict):
    # soukromé JSONy – žádný public URL, necháme default ACL z účtu (přístup jen přes service account)
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    blob = bucket.blob(path_in_bucket)
    raw = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    # krátká cache
    blob.cache_control = "no-store"
    blob.upload_from_string(raw, content_type="application/json; charset=utf-8")

def download_from_gcs(path_in_bucket: str) -> bytes|None:
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    blob = bucket.blob(path_in_bucket)
    if not blob.exists(client):
        return None
    return blob.download_as_bytes()

def download_private_json(path_in_bucket: str) -> dict|None:
    b = download_from_gcs(path_in_bucket)
    if not b:
        return None
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:
        return None

# ===== anime.json: čtení/zápis v cloudu =====
def read_anime_list() -> list:
    try:
        b = download_from_gcs(ANIME_JSON_CLOUD)
        if not b:
            return []
        return json.loads(b.decode("utf-8"))
    except Exception:
        return []

def write_anime_list(items: list) -> str:
    raw = json.dumps(items, ensure_ascii=False, indent=2).encode("utf-8")
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    blob = bucket.blob(ANIME_JSON_CLOUD)
    # pro JSON nedáváme dlouhou cache
    blob.cache_control = "no-cache"
    blob.upload_from_string(raw, content_type="application/json; charset=utf-8")
    return gcs_public_url(ANIME_JSON_CLOUD)

# ===== data URL -> cover upload =====
DATAURL_RE = re.compile(r"^data:(?P<mime>[\w/+.-]+);base64,(?P<b64>.*)$", re.DOTALL)
def save_cover_from_dataurl(data_url: str, slug: str) -> str:
    m = DATAURL_RE.match(data_url.strip())
    if not m:
        raise ValueError("Invalid data URL")
    mime = m.group("mime").lower()
    raw = base64.b64decode(m.group("b64"), validate=True)
    ext = {"image/jpeg":"jpg","image/jpg":"jpg","image/png":"png","image/webp":"webp","image/gif":"gif"}.get(mime,"jpg")
    path_in_bucket = f"covers/{safe_name(slug)}.{ext}"
    return upload_to_gcs(path_in_bucket, raw, mime, overwrite=True)

# ===== multipart parser =====
def parse_multipart_request(handler):
    length = int(handler.headers.get("Content-Length", "0") or "0")
    body = handler.rfile.read(length)
    ctype = handler.headers.get("Content-Type", "")
    headers_bytes = f"Content-Type: {ctype}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
    msg = BytesParser(policy=email_default).parsebytes(headers_bytes + body)
    fields = {}
    if msg.is_multipart():
        for part in msg.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if not name: continue
            filename = part.get_filename()
            payload = part.get_payload(decode=True)
            if filename is None:
                charset = part.get_content_charset() or "utf-8"
                try: value = payload.decode(charset, errors="ignore")
                except Exception: value = payload.decode("utf-8", errors="ignore")
                fields[name] = value
            else:
                fields[name] = payload
    return fields

# ===== Auth helpers (GCS private users) =====
def norm_email(email: str) -> str:
    return (email or "").strip().lower()

def user_blob_key(email: str) -> str:
    e = norm_email(email)
    sha = hashlib.sha256(e.encode("utf-8")).hexdigest()
    return f"{USERS_PREFIX}/{sha}.json"

def hash_password(password: str, salt: bytes|None=None, iters: int=200_000) -> dict:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    return {
        "algo": "pbkdf2_sha256",
        "i": iters,
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(dk).decode("ascii"),
    }

def verify_password(password: str, rec: dict) -> bool:
    try:
        salt = base64.b64decode(rec["salt"])
        iters = int(rec.get("i", 200_000))
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
        return base64.b64encode(dk).decode("ascii") == rec["hash"]
    except Exception:
        return False

def send_email_html(to_addr: str, subject: str, html: str):
    if not SMTP_HOST:
        print("⚠️ SMTP není nakonfigurován – e-mail se neposílá.")
        return
    msg = MIMEText(html, "html", "utf-8")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_addr
    if SMTP_TLS:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls(context=ctx)
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    else:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as s:
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)

# ===== HTTP handler =====
class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200); self.end_headers()

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/stats":
                return self.handle_stats()
            elif parsed.path == "/auth/verify":
                return self.handle_auth_verify(parsed)
            else:
                return super().do_GET()
        except Exception as e:
            traceback.print_exc()
            return json_response(self, 500, {"ok": False, "error": f"Unhandled GET: {e}"})

    def do_DELETE(self):
        try:
            if self.path == "/delete":
                return self.handle_delete()
            else:
                return json_response(self, 404, {"ok": False, "error": "Not found"})
        except Exception as e:
            traceback.print_exc()
            return json_response(self, 500, {"ok": False, "error": f"Unhandled DELETE: {e}"})

    def do_POST(self):
        try:
            match self.path:
                # Uploady & feedback
                case "/upload": self.handle_upload()
                case "/feedback": self.handle_feedback()
                case "/wipe_all": self.handle_wipe_all()
                # Admin obsah
                case "/admin/add_anime": self.handle_add_anime()
                case "/admin/upload_cover": self.handle_upload_cover()
                # Auth (cloud users)
                case "/auth/register": self.handle_auth_register()
                case "/auth/login": self.handle_auth_login()
                case "/auth/update_profile": self.handle_auth_update_profile()
                case _: json_response(self, 404, {"ok": False, "error": "Not found"})
        except Exception as e:
            traceback.print_exc()
            json_response(self, 500, {"ok": False, "error": f"Unhandled error: {e}"})

    # --- Upload video/subs ---
    def handle_upload(self):
        fields = parse_multipart_request(self)
        anime   = fields.get("anime")
        episode = fields.get("episode")
        quality = fields.get("quality")
        video   = fields.get("video")
        vname   = fields.get("videoName")
        subs    = fields.get("subs")
        sname   = fields.get("subsName")

        if not all([anime, episode, quality, video, vname]):
            return json_response(self, 400, {"ok": False, "error": "Missing required fields"})

        ep_folder = f"{int(episode):05d}"
        vname = safe_name(vname)
        sname = safe_name(sname or "subs.srt")

        v_mime = guess_mime(vname, sniff=video[:8] if isinstance(video,(bytes,bytearray)) else None, default="video/mp4")
        s_mime = guess_mime(sname, sniff=subs[:8] if isinstance(subs,(bytes,bytearray)) else None, default="application/x-subrip")

        def avoid_collision(path_in_bucket: str) -> str:
            base, dot, ext = path_in_bucket.partition(".")
            return f"{base}-{hashlib.sha1(os.urandom(8)).hexdigest()[:6]}{('.' + ext) if dot else ''}"

        video_path = f"anime/{anime}/{ep_folder}/{quality}/{vname}"
        subs_path  = f"anime/{anime}/{ep_folder}/{quality}/{sname}"

        try:
            video_url = upload_to_gcs(video_path, video, v_mime, overwrite=True)
        except RuntimeError:
            video_url = upload_to_gcs(avoid_collision(video_path), video, v_mime, overwrite=False)

        subs_url = None
        if subs:
            try:
                subs_url = upload_to_gcs(subs_path, subs, s_mime, overwrite=True)
            except RuntimeError:
                subs_url = upload_to_gcs(avoid_collision(subs_path), subs, s_mime, overwrite=False)

        return json_response(self, 200, {"ok": True, "video": video_url, "subs": subs_url})

    # --- Feedback (lokální dump pro ladění) ---
    def handle_feedback(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        ensure_dirs()
        fid = safe_name(str(data.get("id") or "feedback"))
        with open(os.path.join(FEEDBACK_DIR, f"{fid}.json"), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return json_response(self, 200, {"ok": True})

    # --- Wipe placeholder ---
    def handle_wipe_all(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        if payload.get("password") != WIPE_PASSWORD:
            return json_response(self, 403, {"ok": False, "error": "Forbidden"})
        return json_response(self, 200, {"ok": True, "status": "cloud wipe disabled"})

    # --- Add/Update anime (cloud-only) ---
    def handle_add_anime(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})

        required = ["slug","title","episodes","genres","description","cover","status","year","studio"]
        if not all(k in body for k in required):
            return json_response(self, 400, {"ok": False, "error": "Missing required fields"})

        slug = safe_name(str(body["slug"]).lower())
        cover_in = body.get("cover")

        try:
            if isinstance(cover_in, str) and cover_in.startswith("data:"):
                cover_url = save_cover_from_dataurl(cover_in, slug)
            else:
                cover_url = str(cover_in or "")
        except Exception as e:
            return json_response(self, 400, {"ok": False, "error": f"cover: {e}"})

        try:
            item = {
                "slug": slug,
                "title": str(body["title"]),
                "episodes": int(body["episodes"]),
                "genres": list(body["genres"]),
                "description": str(body["description"]),
                "cover": cover_url,
                "status": str(body["status"]),
                "year": int(body["year"]),
                "studio": str(body["studio"]),
            }
        except Exception as e:
            return json_response(self, 400, {"ok": False, "error": f"fields: {e}"})

        items = read_anime_list()
        items = [a for a in items if a.get("slug") != slug]
        items.append(item)
        url_json = write_anime_list(items)
        return json_response(self, 200, {"ok": True, "saved": item, "anime_json_url": url_json})

    # --- Upload cover (multipart) ---
    def handle_upload_cover(self):
        fields = parse_multipart_request(self)
        slug = fields.get("slug"); cover = fields.get("cover")
        if not slug or not cover:
            return json_response(self, 400, {"ok": False, "error": "Missing slug or cover"})
        sniff = bytes(cover[:12]) if isinstance(cover,(bytes,bytearray)) else None
        mime = guess_mime("cover.bin", sniff=sniff, default="image/jpeg")
        ext = {"image/png":"png","image/webp":"webp","image/gif":"gif","image/jpeg":"jpg"}.get(mime,"jpg")
        url = upload_to_gcs(f"covers/{safe_name(slug)}.{ext}", cover, mime, overwrite=True)
        return json_response(self, 200, {"ok": True, "path": url})

    # --- DELETE video/subs z GCS (pro admin) ---
    def handle_delete(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(body or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        slug = payload.get("anime"); ep = payload.get("episode"); q = payload.get("quality"); name = payload.get("videoName")
        if not all([slug, ep, q, name]):
            return json_response(self, 400, {"ok": False, "error": "Missing fields"})
        ep_folder = f"{int(ep):05d}"
        path = f"anime/{safe_name(slug)}/{ep_folder}/{safe_name(q)}/{safe_name(name)}"
        try:
            client = _ensure_gcs()
            bucket = client.bucket(GCS_BUCKET)
            blob = bucket.blob(path)
            if blob.exists(client):
                blob.delete()
            return json_response(self, 200, {"ok": True})
        except Exception as e:
            traceback.print_exc()
            return json_response(self, 500, {"ok": False, "error": f"delete: {e}"})

    # --- STATS (GCS scan) ---
    def handle_stats(self):
        try:
            client = _ensure_gcs()
            # users
            users_cnt = sum(1 for _ in client.list_blobs(GCS_BUCKET, prefix=f"{USERS_PREFIX}/"))
            # uploads & top anime (unikátní epizody/slug)
            uploads_cnt = 0
            per_slug_ep = {}
            for b in client.list_blobs(GCS_BUCKET, prefix="anime/"):
                name = b.name.lower()
                if any(name.endswith(ext) for ext in VIDEO_EXTS):
                    uploads_cnt += 1
                    parts = b.name.split("/")
                    if len(parts) >= 5:
                        slug, ep = parts[1], parts[2]
                        per_slug_ep.setdefault(slug, set()).add(ep)
            top_slug, top_eps = None, 0
            for slug, eps in per_slug_ep.items():
                if len(eps) > top_eps:
                    top_slug, top_eps = slug, len(eps)
            return json_response(self, 200, {
                "ok": True,
                "users": users_cnt,
                "uploads": uploads_cnt,
                "top_anime": {"slug": top_slug, "episodes": top_eps} if top_slug else None
            })
        except Exception as e:
            traceback.print_exc()
            return json_response(self, 500, {"ok": False, "error": f"stats: {e}"})

    # --- AUTH API ---
    def handle_auth_register(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        email = norm_email(data.get("email") or "")
        password = (data.get("password") or "").strip()
        if not email or not password:
            return json_response(self, 400, {"ok": False, "error": "Missing email/password"})
        key = user_blob_key(email)
        client = _ensure_gcs(); bucket = client.bucket(GCS_BUCKET); blob = bucket.blob(key)
        if blob.exists(client):
            return json_response(self, 409, {"ok": False, "error": "User exists"})
        pw = hash_password(password)
        token = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii").rstrip("=")
        user_obj = {
            "email": email,
            "password": pw,
            "verified": False,
            "verify_token": token,
            "createdAt": int(__import__("time").time()*1000),
            "role": "user",
            "profile": {"nickname": email.split("@")[0], "avatar": None, "secondaryTitle": None}
        }
        upload_private_json(key, user_obj)

        # e-mail s potvrzením
        link = f"{APP_BASE_URL}/auth/verify?email={quote(email)}&token={quote(token)}"
        html = f"""
        <div style="font-family:Segoe UI,Tahoma,sans-serif">
          <h2>Vítej v AnimeCloud</h2>
          <p>Potvrď prosím svůj účet kliknutím na tlačítko:</p>
          <p><a href="{link}" style="display:inline-block;background:#7c5cff;color:#fff;padding:10px 14px;border-radius:8px;text-decoration:none" target="_blank" rel="noreferrer">Aktivovat účet</a></p>
          <p>Nebo otevři odkaz ručně: <br><code>{link}</code></p>
        </div>
        """
        try:
            send_email_html(email, "AnimeCloud – potvrzení registrace", html)
        except Exception as e:
            print("E-mail se nepodařilo odeslat:", e)

        return json_response(self, 200, {"ok": True})

    def handle_auth_verify(self, parsed):
        qs = parse_qs(parsed.query or "")
        email = norm_email((qs.get("email") or [""])[0])
        token = (qs.get("token") or [""])[0]
        if not email or not token:
            # odpověz mini HTML
            html = "<h3>Chybí parametry.</h3>"
            self.send_response(400); self.send_header("Content-Type","text/html; charset=utf-8"); self.end_headers()
            return self.wfile.write(html.encode("utf-8"))
        key = user_blob_key(email)
        user = download_private_json(key)
        if not user or user.get("verify_token") != token:
            html = "<h3>Neplatný odkaz, nebo už byl použit.</h3>"
            self.send_response(400); self.send_header("Content-Type","text/html; charset=utf-8"); self.end_headers()
            return self.wfile.write(html.encode("utf-8"))
        user["verified"] = True
        user["verify_token"] = None
        upload_private_json(key, user)
        html = f"""
        <div style="font-family:Segoe UI,Tahoma,sans-serif">
          <h2>Účet aktivován 🎉</h2>
          <p>Nyní se můžeš přihlásit.</p>
          <p><a href="{APP_BASE_URL}/login.html">Přejít na přihlášení</a></p>
        </div>
        """
        self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.end_headers()
        return self.wfile.write(html.encode("utf-8"))

    def handle_auth_login(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        email = norm_email(data.get("email") or "")
        password = (data.get("password") or "").strip()
        if not email or not password:
            return json_response(self, 400, {"ok": False, "error": "Missing email/password"})
        key = user_blob_key(email)
        user = download_private_json(key)
        if not user or not verify_password(password, user.get("password") or {}):
            return json_response(self, 401, {"ok": False, "error": "Invalid credentials"})
        if not user.get("verified"):
            return json_response(self, 403, {"ok": False, "error": "Account not verified"})
        # jednoduchý "session" token (JWT by šel později)
        sess = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii").rstrip("=")
        user["session"] = {"token": sess, "at": int(__import__("time").time()*1000)}
        upload_private_json(key, user)
        public_profile = {
            "email": user["email"],
            "role": user.get("role","user"),
            "profile": user.get("profile") or {},
        }
        return json_response(self, 200, {"ok": True, "token": sess, "user": public_profile})

    def handle_auth_update_profile(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        email = norm_email(data.get("email") or "")
        token = (data.get("token") or "").strip()
        prof  = data.get("profile") or {}
        if not email or not token:
            return json_response(self, 400, {"ok": False, "error": "Missing email/token"})
        key = user_blob_key(email)
        user = download_private_json(key)
        if not user or (user.get("session") or {}).get("token") != token:
            return json_response(self, 401, {"ok": False, "error": "Unauthorized"})
        user["profile"] = { **(user.get("profile") or {}), **prof }
        upload_private_json(key, user)
        return json_response(self, 200, {"ok": True, "profile": user["profile"]})

def run():
    ensure_dirs()
    port = int(os.getenv("PORT", "8000"))
    httpd = HTTPServer(("0.0.0.0", port), Handler)
    print(f"✅ Server běží na http://0.0.0.0:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
