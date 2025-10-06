#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, io, re, json, base64, hashlib, traceback, smtplib, ssl, time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import default as email_default
from urllib.parse import quote, urlencode, urlparse, parse_qs
from dotenv import load_dotenv

load_dotenv()

# =========================
# Konfigurace z .env
# =========================
# GCS
GCS_BUCKET = os.getenv("GCS_BUCKET", "").strip()
GCS_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()

# Cesty v bucketu
ANIME_JSON_CLOUD = os.getenv("ANIME_JSON_CLOUD", "data/anime.json").strip()

# Users storage: "dir" (výchozí) = jeden JSON na uživatele, "file" = vše v jednom JSON
USERS_STORAGE_MODE = os.getenv("USERS_STORAGE_MODE", "dir").strip().lower()
USERS_JSON_CLOUD   = os.getenv("USERS_JSON_CLOUD", "private/users/users.json").strip()
USERS_DIR_CLOUD    = os.getenv("USERS_DIR_CLOUD", "private/users").strip()

# SMTP (Gmail s App Password)
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or "587")
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "").strip()
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "true").lower() == "true"
SMTP_DEBUG = int(os.getenv("SMTP_DEBUG", "0") or "0")

# DEV usnadnění
DEV_ECHO_VERIFICATION_LINK = os.getenv("DEV_ECHO_VERIFICATION_LINK", "false").lower() == "true"
DEV_SAVE_LAST_EMAIL = os.getenv("DEV_SAVE_LAST_EMAIL", "false").lower() == "true"

# Admin bootstrap (zapnout jen na první start)
ADMIN_BOOT_ENABLE = os.getenv("ADMIN_BOOT_ENABLE", "false").lower() == "true"
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
ADMIN_BOOT_PASSWORD = os.getenv("ADMIN_BOOT_PASSWORD", "").strip()

# Ostatní
ROOT = os.getcwd()
FEEDBACK_DIR = os.path.join(ROOT, "feedback")
OUTBOX_DIR = os.path.join(ROOT, "outbox")
WIPE_PASSWORD = os.getenv("WIPE_PASSWORD", "789456123Lol")

# =========================
# Helpery
# =========================
def ensure_dirs():
    os.makedirs(FEEDBACK_DIR, exist_ok=True)
    os.makedirs(OUTBOX_DIR, exist_ok=True)

def safe_name(name: str) -> str:
    if isinstance(name, bytes):
        name = name.decode("utf-8", "ignore")
    keep = "._-()[]{}@+&= "
    name = "".join(ch for ch in name if ch.isalnum() or ch in keep)
    name = name.replace("/", "").replace("\\", "")
    return name.strip() or "file"

def json_response(h, status: int, obj: dict):
    h.send_response(status)
    h.send_header("Content-Type", "application/json; charset=utf-8")
    h.end_headers()
    h.wfile.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

def html_response(h, status: int, html: str):
    h.send_response(status)
    h.send_header("Content-Type", "text/html; charset=utf-8")
    h.end_headers()
    h.wfile.write(html.encode("utf-8"))

def site_base(h) -> str:
    xf_proto = h.headers.get("X-Forwarded-Proto")
    xf_host  = h.headers.get("X-Forwarded-Host")
    if xf_proto and xf_host:
        return f"{xf_proto}://{xf_host}"
    host = h.headers.get("Host", "localhost")
    scheme = "https" if h.headers.get("X-Forwarded-Proto","").lower()=="https" else "http"
    return f"{scheme}://{host}"

# MIME map
EXT_MIME = {
    ".mp4":"video/mp4", ".m4v":"video/x-m4v", ".webm":"video/webm", ".mkv":"video/x-matroska", ".mov":"video/quicktime",
    ".srt":"application/x-subrip", ".vtt":"text/vtt",
    ".jpg":"image/jpeg", ".jpeg":"image/jpeg", ".png":"image/png", ".webp":"image/webp", ".gif":"image/gif",
}
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

# multipart parser
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

# =========================
# GCS klient & operace (ONLY GCS)
# =========================
_gcs_client = None

def _ensure_gcs():
    global _gcs_client
    if _gcs_client is None:
        if not GCS_BUCKET:
            raise RuntimeError("GCS_BUCKET není nastaven.")
        from google.cloud import storage
        _gcs_client = storage.Client()
    return _gcs_client

def gcs_public_url(path_in_bucket: str) -> str:
    parts = [quote(p) for p in path_in_bucket.split("/")]
    return f"https://storage.googleapis.com/{GCS_BUCKET}/{'/'.join(parts)}"

def upload_bytes(path_in_bucket: str, raw: bytes, mime: str, overwrite: bool=True, immutable: bool=True) -> str:
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    blob = bucket.blob(path_in_bucket)
    if not overwrite and blob.exists(client):
        raise RuntimeError("exists")
    if immutable:
        blob.cache_control = "public, max-age=31536000, immutable"
    blob.upload_from_string(raw, content_type=(mime or "application/octet-stream"))
    return gcs_public_url(path_in_bucket)

def download_bytes(path_in_bucket: str) -> bytes|None:
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    blob = bucket.blob(path_in_bucket)
    if not blob.exists(client):
        return None
    return blob.download_as_bytes()

# =========================
# anime.json (cloud)
# =========================
def read_anime_list() -> list:
    try:
        b = download_bytes(ANIME_JSON_CLOUD)
        if not b: return []
        return json.loads(b.decode("utf-8"))
    except Exception:
        return []

def write_anime_list(items: list) -> str:
    raw = json.dumps(items, ensure_ascii=False, indent=2).encode("utf-8")
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    blob = bucket.blob(ANIME_JSON_CLOUD)
    blob.upload_from_string(raw, content_type="application/json; charset=utf-8")
    return gcs_public_url(ANIME_JSON_CLOUD)

# =========================
# Users (GCS): "dir" (výchozí) nebo "file"
# =========================
def _users_mode(): return "dir" if USERS_STORAGE_MODE == "dir" else "file"
def _users_file(): return USERS_JSON_CLOUD
def _users_dir():  return USERS_DIR_CLOUD.strip("/")

def _user_obj_key(email: str) -> str:
    return f"{_users_dir()}/{safe_name((email or '').lower())}.json"

def read_users_map() -> dict:
    if _users_mode() == "file":
        b = download_bytes(_users_file())
        if not b: return {}
        try: return json.loads(b.decode("utf-8"))
        except: return {}
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    out = {}
    for blob in client.list_blobs(bucket, prefix=_users_dir()+"/"):
        if not blob.name.lower().endswith(".json"): continue
        try:
            data = json.loads(blob.download_as_bytes().decode("utf-8"))
            email = (data.get("email") or "").lower()
            if email: out[email] = data
        except Exception:
            continue
    return out

def write_users_map(obj: dict) -> None:
    if _users_mode() != "file":
        raise RuntimeError("write_users_map is file-only")
    raw = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    bucket.blob(_users_file()).upload_from_string(raw, content_type="application/json; charset=utf-8")

def read_user(email: str) -> dict|None:
    email = (email or "").strip().lower()
    if not email: return None
    if _users_mode() == "file":
        return read_users_map().get(email)
    b = download_bytes(_user_obj_key(email))
    if not b: return None
    try: return json.loads(b.decode("utf-8"))
    except: return None

def write_user(u: dict) -> None:
    email = (u.get("email") or "").strip().lower()
    if not email: raise ValueError("user.email is required")
    if _users_mode() == "file":
        users = read_users_map()
        users[email] = u
        write_users_map(users); return
    raw = json.dumps(u, ensure_ascii=False, indent=2).encode("utf-8")
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    bucket.blob(_user_obj_key(email)).upload_from_string(raw, content_type="application/json; charset=utf-8")

def delete_user(email: str) -> bool:
    email = (email or "").strip().lower()
    if not email: return False
    if _users_mode() == "file":
        users = read_users_map()
        if email in users:
            del users[email]; write_users_map(users); return True
        return False
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    blob = bucket.blob(_user_obj_key(email))
    if blob.exists(client): blob.delete(); return True
    return False

def users_count() -> int:
    if _users_mode() == "file":
        return len(read_users_map())
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    return sum(1 for b in client.list_blobs(bucket, prefix=_users_dir()+"/") if b.name.lower().endswith(".json"))

# =========================
# Cover z data:URL
# =========================
DATAURL_RE = re.compile(r"^data:(?P<mime>[\w/+.-]+);base64,(?P<b64>.*)$", re.DOTALL)
def save_cover_from_dataurl(data_url: str, slug: str) -> str:
    m = DATAURL_RE.match(data_url.strip())
    if not m:
        raise ValueError("Invalid data URL")
    mime = m.group("mime").lower()
    raw = base64.b64decode(m.group("b64"), validate=True)
    ext = {"image/jpeg":"jpg","image/jpg":"jpg","image/png":"png","image/webp":"webp","image/gif":"gif"}.get(mime,"jpg")
    path_in_bucket = f"covers/{safe_name(slug)}.{ext}"
    return upload_bytes(path_in_bucket, raw, mime, overwrite=True, immutable=True)

# =========================
# SMTP odesílání
# =========================
def send_email(to_addr: str, subject: str, html: str, text: str|None=None):
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and SMTP_FROM):
        return False, "SMTP not configured"
    try:
        msg = EmailMessage()
        msg["From"] = SMTP_FROM
        msg["To"] = to_addr
        msg["Subject"] = subject
        if text:
            msg.set_content(text)
            msg.add_alternative(html, subtype="html")
        else:
            msg.set_content("HTML email")
            msg.add_alternative(html, subtype="html")

        if DEV_SAVE_LAST_EMAIL:
            with open(os.path.join(OUTBOX_DIR, "last_email.eml"), "wb") as f:
                f.write(bytes(msg))

        if SMTP_STARTTLS:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
            if SMTP_DEBUG: server.set_debuglevel(1)
            server.ehlo(); server.starttls(context=ssl.create_default_context())
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg); server.quit()
        else:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30)
            if SMTP_DEBUG: server.set_debuglevel(1)
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg); server.quit()
        return True, None
    except Exception as e:
        return False, str(e)

# =========================
# Auth utility
# =========================
def scrypt_hash(password: str, salt: bytes|None=None):
    if salt is None: import os as _os; salt = _os.urandom(16)
    h = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
    return base64.b64encode(h).decode("ascii"), base64.b64encode(salt).decode("ascii")

def check_password(password: str, enc_hash: str, enc_salt: str) -> bool:
    try:
        want = base64.b64decode(enc_hash)
        salt = base64.b64decode(enc_salt)
        got = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
        return got == want
    except Exception:
        return False

# =========================
# HTTP handler
# =========================
class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200); self.end_headers()

    # ---------- GET ----------
    def do_GET(self):
        try:
            if self.path.startswith("/auth/verify"):
                return self.handle_auth_verify_get()
            return super().do_GET()
        except Exception as e:
            traceback.print_exc()
            html_response(self, 500, f"<h1>500</h1><pre>{e}</pre>")

    # ---------- POST ----------
    def do_POST(self):
        try:
            match self.path:
                # Upload & admin
                case "/upload": self.handle_upload()
                case "/feedback": self.handle_feedback()
                case "/wipe_all": self.handle_wipe_all()
                case "/admin/add_anime": self.handle_add_anime()
                case "/admin/upload_cover": self.handle_upload_cover()
                # Auth
                case "/auth/register": self.handle_auth_register()
                case "/auth/login": self.handle_auth_login()
                case "/auth/verify": self.handle_auth_verify_post()
                # Default
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
            video_url = upload_bytes(video_path, video, v_mime, overwrite=True, immutable=True)
        except RuntimeError:
            video_url = upload_bytes(avoid_collision(video_path), video, v_mime, overwrite=False, immutable=True)

        subs_url = None
        if subs:
            try:
                subs_url = upload_bytes(subs_path, subs, s_mime, overwrite=True, immutable=True)
            except RuntimeError:
                subs_url = upload_bytes(avoid_collision(subs_path), subs, s_mime, overwrite=False, immutable=True)

        return json_response(self, 200, {"ok": True, "video": video_url, "subs": subs_url})

    # --- Feedback ---
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

    # --- Wipe (placeholder) ---
    def handle_wipe_all(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        if payload.get("password") != WIPE_PASSWORD:
            return json_response(self, 403, {"ok": False, "error": "Forbidden"})
        return json_response(self, 200, {"ok": True, "status": "cloud wipe disabled"})

    # --- Add/Update anime (zapíše do GCS data/anime.json) ---
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
        url = upload_bytes(f"covers/{safe_name(slug)}.{ext}", cover, mime, overwrite=True, immutable=True)
        return json_response(self, 200, {"ok": True, "path": url})

    # =========================
    # Auth endpoints
    # =========================
    def handle_auth_register(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})

        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        if not email or not password:
            return json_response(self, 400, {"ok": False, "error": "Missing email/password"})
        if read_user(email):
            return json_response(self, 409, {"ok": False, "error": "exists"})

        h, salt = scrypt_hash(password)
        import secrets
        token = secrets.token_urlsafe(32)

        user_obj = {
            "email": email,
            "role": "user",
            "createdAt": int(time.time()*1000),
            "verified": False,
            "verify_token": token,
            "pwd": h,
            "salt": salt,
            "profile": {"nickname": email.split("@")[0], "avatar": None, "secondaryTitle": None}
        }
        write_user(user_obj)

        vurl = f"{site_base(self)}/auth/verify?{urlencode({'email': email, 'token': token})}"
        html = f"""
        <div style="font-family:sans-serif;line-height:1.5">
          <h2>Vítej v AnimeCloud 👋</h2>
          <p>Potvrď prosím svůj e-mail kliknutím na tlačítko:</p>
          <p><a href="{vurl}" style="background:#7c5cff;color:#fff;padding:10px 14px;border-radius:8px;text-decoration:none">Ověřit účet</a></p>
          <p>Pokud tlačítko nefunguje, použij tento odkaz: <a href="{vurl}">{vurl}</a></p>
        </div>
        """
        ok, err = send_email(email, "Ověření účtu — AnimeCloud", html, text=f"Ověř svůj účet: {vurl}")
        resp = {"ok": True}
        if DEV_ECHO_VERIFICATION_LINK:
            resp["verification_url"] = vurl
        if not ok:
            resp["warning"] = f"Email neodeslán: {err}"
        return json_response(self, 200, resp)

    def handle_auth_verify_post(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        email = (data.get("email") or "").strip().lower()
        token = data.get("token") or ""
        return self._verify_core(email, token, as_html=False)

    def handle_auth_verify_get(self):
        q = parse_qs(urlparse(self.path).query)
        email = (q.get("email", [""])[0] or "").strip().lower()
        token = q.get("token", [""])[0] or ""
        # HTML režim: _verify_core samo pošle odpověď
        self._verify_core(email, token, as_html=True)

    def _verify_core(self, email: str, token: str, as_html: bool):
        u = read_user(email)
        if not u or not token or token != u.get("verify_token"):
            if as_html:
                return html_response(
                    self, 400,
                    "<!doctype html><meta charset='utf-8'>"
                    "<h1>Ověření selhalo</h1><p>Neplatný odkaz nebo e-mail.</p>"
                )
            return json_response(self, 400, {"ok": False, "error": "invalid"})

        u["verified"] = True
        u.pop("verify_token", None)
        write_user(u)

        if as_html:
            login_url = f"{site_base(self)}/login.html"
            html = f"""<!doctype html>
<html lang="cs">
<meta charset="utf-8">
<title>Účet ověřen</title>
<meta http-equiv="refresh" content="1;url={login_url}">
<style>
  body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:24px}}
  .ok{{display:inline-block;background:#e9f7ef;color:#1e7e34;border:1px solid #c3e6cb;
       border-radius:8px;padding:10px 12px;margin-bottom:12px}}
  a.button{{display:inline-block;background:#7c5cff;color:#fff;text-decoration:none;
       padding:8px 12px;border-radius:8px}}
</style>
<h1>Účet ověřen <span class="ok">✅</span></h1>
<p>Nyní se můžete přihlásit.</p>
<p><a class="button" href="{login_url}">Pokračovat na přihlášení</a></p>
<script>setTimeout(function(){{ location.href = "{login_url}"; }}, 1000);</script>
</html>"""
            return html_response(self, 200, html)

        return json_response(self, 200, {"ok": True})

    def handle_auth_login(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})

        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        u = read_user(email)
        if not u:
            return json_response(self, 401, {"ok": False, "error": "Invalid credentials"})
        if not u.get("verified"):
            return json_response(self, 403, {"ok": False, "error": "Account not verified"})
        if not check_password(password, u.get("pwd",""), u.get("salt","")):
            return json_response(self, 401, {"ok": False, "error": "Invalid credentials"})
        import secrets
        token = secrets.token_urlsafe(24)
        return json_response(self, 200, {
            "ok": True,
            "token": token,
            "user": {"email": email, "role": u.get("role","user"), "profile": u.get("profile",{})}
        })

# =========================
# Bootstrap admin
# =========================
def ensure_bootstrap_admin():
    if not ADMIN_BOOT_ENABLE or not ADMIN_EMAIL or not ADMIN_BOOT_PASSWORD:
        return
    if read_user(ADMIN_EMAIL):
        print("ℹ️  Bootstrap admin: už existuje, nic nedělám.")
        return
    h, salt = scrypt_hash(ADMIN_BOOT_PASSWORD)
    u = {
        "email": ADMIN_EMAIL,
        "role": "admin",
        "createdAt": int(time.time()*1000),
        "verified": True,
        "pwd": h,
        "salt": salt,
        "profile": {"nickname": "Admin", "avatar": None, "secondaryTitle": None}
    }
    write_user(u)
    print(f"✅ Bootstrap admin vytvořen: {ADMIN_EMAIL}. Po přihlášení přepni ADMIN_BOOT_ENABLE=false.")

def _mask(s: str, keep=2):
    if not s: return "<empty>"
    return (s[:keep] + "…" + s[-keep:]) if len(s) > keep*2 else "***"

def print_config_summary():
    print("— Config —")
    print("PORT:", os.getenv("PORT","8000"))
    print("GCS_BUCKET:", GCS_BUCKET or "<empty>")
    print("ANIME_JSON_CLOUD:", ANIME_JSON_CLOUD)
    print("USERS_STORAGE_MODE:", USERS_STORAGE_MODE, "USERS_DIR_CLOUD:", USERS_DIR_CLOUD, "USERS_JSON_CLOUD:", USERS_JSON_CLOUD)
    print("SMTP_HOST:", SMTP_HOST or "<empty>", "PORT:", SMTP_PORT, "STARTTLS:", SMTP_STARTTLS)
    print("SMTP_USER:", _mask(SMTP_USER))
    print(".env present:", os.path.exists(os.path.join(ROOT, ".env")))

# =========================
# Run
# =========================
def run():
    ensure_dirs()
    print_config_summary()
    ensure_bootstrap_admin()
    port = int(os.getenv("PORT", "8000"))
    httpd = HTTPServer(("0.0.0.0", port), Handler)
    print(f"✅ Server běží na http://0.0.0.0:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
