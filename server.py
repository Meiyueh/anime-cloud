#!/usr/bin/env python3
import os, json, re, base64, requests, hashlib, hmac, time, traceback, io, secrets
from http.server import HTTPServer, SimpleHTTPRequestHandler
from email.parser import BytesParser
from email.policy import default as email_default
from urllib.parse import quote, urlparse, parse_qs
from dotenv import load_dotenv

load_dotenv()

# === Konfigurace úložiště GCS (povinné) ===
GCS_BUCKET = os.getenv("GCS_BUCKET", "").strip()
GCS_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()

# Cesty v bucketu
ANIME_JSON_CLOUD = os.getenv("ANIME_JSON_CLOUD", "data/anime.json")   # veřejné čtení pro web
USERS_PREFIX     = os.getenv("USERS_PREFIX", "private/users")         # neveřejné
TOKENS_PREFIX    = os.getenv("TOKENS_PREFIX", "private/tokens")       # neveřejné

# Ostatní
ROOT = os.getcwd()
FEEDBACK_DIR = os.path.join(ROOT, "feedback")
WIPE_PASSWORD = os.getenv("WIPE_PASSWORD", "789456123Lol")
AUTH_SECRET   = os.getenv("AUTH_SECRET", "dev-secret-change-me").encode("utf-8")  # podepisování tokenů

# ===== Helpers =====
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

def ensure_dirs():
    os.makedirs(FEEDBACK_DIR, exist_ok=True)

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

# ===== GCS klient =====
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

def _gcs_blob(path_in_bucket: str):
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    return bucket.blob(path_in_bucket)

def upload_public_bytes(path_in_bucket: str, raw: bytes, mime: str, overwrite: bool=True) -> str:
    blob = _gcs_blob(path_in_bucket)
    if not overwrite and blob.exists():
        raise RuntimeError("exists")
    # veřejné soubory (obálky, videa) — cache dlouhá
    blob.cache_control = "public, max-age=31536000, immutable"
    blob.upload_from_string(raw, content_type=(mime or "application/octet-stream"))
    return gcs_public_url(path_in_bucket)

def upload_private_bytes(path_in_bucket: str, raw: bytes, mime: str):
    blob = _gcs_blob(path_in_bucket)
    # žádné public ACL — implicitně soukromé, přístup jen přes server s credentials
    blob.upload_from_string(raw, content_type=(mime or "application/octet-stream"))
    return path_in_bucket  # nevracíme veřejnou URL

def download_bytes(path_in_bucket: str) -> bytes|None:
    blob = _gcs_blob(path_in_bucket)
    if not blob.exists():
        return None
    return blob.download_as_bytes()

def delete_blob(path_in_bucket: str) -> bool:
    blob = _gcs_blob(path_in_bucket)
    if not blob.exists(): return False
    blob.delete(); return True

# ===== anime.json: čtení/zápis (veřejně čitelné) =====
def read_anime_list() -> list:
    try:
        b = download_bytes(ANIME_JSON_CLOUD)
        if not b: return []
        return json.loads(b.decode("utf-8"))
    except Exception:
        return []

def write_anime_list(items: list) -> str:
    raw = json.dumps(items, ensure_ascii=False, indent=2).encode("utf-8")
    # JSON nechceme dlouhý immutable cache — použijeme bez explicitního cache_control
    blob = _gcs_blob(ANIME_JSON_CLOUD)
    blob.upload_from_string(raw, content_type="application/json; charset=utf-8")
    return gcs_public_url(ANIME_JSON_CLOUD)

# ===== data URL -> cover upload =====
DATAURL_RE = re.compile(r"^data:(?P<mime>[\w/+.-]+);base64,(?P<b64>.*)$", re.DOTALL)
def save_cover_from_dataurl(data_url: str, slug: str) -> str:
    m = DATAURL_RE.match(data_url.strip())
    if not m: raise ValueError("Invalid data URL")
    mime = m.group("mime").lower()
    raw = base64.b64decode(m.group("b64"), validate=True)
    ext = {"image/jpeg":"jpg","image/jpg":"jpg","image/png":"png","image/webp":"webp","image/gif":"gif"}.get(mime,"jpg")
    path_in_bucket = f"covers/{safe_name(slug)}.{ext}"
    return upload_public_bytes(path_in_bucket, raw, mime, overwrite=True)

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

# ===== Jednoduché JWT (HMAC-SHA256) =====
def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("utf-8")
def b64u_dec(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def make_token(email: str, role: str, days=30) -> str:
    header = b64u(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    now = int(time.time())
    payload_obj = {"sub":email, "role":role, "iat":now, "exp": now + days*86400}
    payload = b64u(json.dumps(payload_obj).encode())
    sig = hmac.new(AUTH_SECRET, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{b64u(sig)}"

# ===== "DB" uživatelů v GCS (privátní) =====
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def email_key(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()

def user_path(email: str) -> str:
    return f"{USERS_PREFIX}/{email_key(email)}.json"

def read_user(email: str) -> dict|None:
    b = download_bytes(user_path(email))
    if not b: return None
    try: return json.loads(b.decode("utf-8"))
    except: return None

def write_user(email: str, rec: dict):
    raw = json.dumps(rec, ensure_ascii=False, indent=2).encode("utf-8")
    upload_private_bytes(user_path(email), raw, "application/json; charset=utf-8")

def new_password_hash(password: str) -> dict:
    salt = secrets.token_bytes(16)
    iters = 200_000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    return {
        "algo": "pbkdf2_sha256",
        "iter": iters,
        "salt": b64u(salt),
        "hash": b64u(dk),
    }

def verify_password(pwd_hash: dict, password: str) -> bool:
    if not pwd_hash: return False
    try:
        iters = int(pwd_hash.get("iter", 200_000))
        salt = b64u_dec(pwd_hash["salt"])
        expect = b64u_dec(pwd_hash["hash"])
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
        return hmac.compare_digest(dk, expect)
    except Exception:
        return False

def create_verify_token(email: str) -> str:
    token = b64u(secrets.token_bytes(24))
    upload_private_bytes(f"{TOKENS_PREFIX}/{token}.txt", email.encode("utf-8"), "text/plain")
    return token

def consume_verify_token(token: str) -> str|None:
    path = f"{TOKENS_PREFIX}/{token}.txt"
    b = download_bytes(path)
    if not b: return None
    email = b.decode("utf-8", "ignore").strip()
    try: delete_blob(path)
    except: pass
    return email

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
            if parsed.path == "/auth/verify":
                qs = parse_qs(parsed.query or "")
                token = (qs.get("token") or [""])[0]
                if not token:
                    return html_response(self, 400, "<h1>Chybí token</h1>")
                email = consume_verify_token(token)
                if not email:
                    return html_response(self, 400, "<h1>Neplatný nebo použitý token</h1>")
                user = read_user(email)
                if not user:
                    return html_response(self, 404, "<h1>Uživatel nenalezen</h1>")
                user["verified"] = True
                write_user(email, user)
                return html_response(self, 200, "<h1>Účet ověřen ✅</h1><p>Můžete se přihlásit.</p>")
            else:
                # statické soubory
                return super().do_GET()
        except Exception as e:
            traceback.print_exc()
            return html_response(self, 500, f"<h1>Chyba</h1><pre>{e}</pre>")

    def do_POST(self):
        try:
            match self.path:
                # Upload + admin
                case "/upload": self.handle_upload()
                case "/feedback": self.handle_feedback()
                case "/wipe_all": self.handle_wipe_all()
                case "/admin/add_anime": self.handle_add_anime()
                case "/admin/upload_cover": self.handle_upload_cover()
                # Auth
                case "/auth/register": self.handle_register()
                case "/auth/login": self.handle_login()
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
            video_url = upload_public_bytes(video_path, video, v_mime, overwrite=True)
        except RuntimeError:
            video_url = upload_public_bytes(avoid_collision(video_path), video, v_mime, overwrite=False)

        subs_url = None
        if subs:
            try:
                subs_url = upload_public_bytes(subs_path, subs, s_mime, overwrite=True)
            except RuntimeError:
                subs_url = upload_public_bytes(avoid_collision(subs_path), subs, s_mime, overwrite=False)

        return json_response(self, 200, {"ok": True, "video": video_url, "subs": subs_url})

    # --- Feedback (lokálně do /feedback, opt. mirror do cloudu by šel doplnit) ---
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
        url = upload_public_bytes(f"covers/{safe_name(slug)}.{ext}", cover, mime, overwrite=True)
        return json_response(self, 200, {"ok": True, "path": url})

    # --- Auth: /auth/register ---
    def handle_register(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})

        email = (body.get("email") or "").strip().lower()
        password1 = body.get("password1") or ""
        password2 = body.get("password2") or ""
        nickname  = (body.get("nickname") or "").strip() or email.split("@")[0]

        if not EMAIL_RE.match(email):
            return json_response(self, 400, {"ok": False, "error": "Neplatný e-mail"})
        if not password1 or len(password1) < 8:
            return json_response(self, 400, {"ok": False, "error": "Heslo musí mít alespoň 8 znaků"})
        if password1 != password2:
            return json_response(self, 400, {"ok": False, "error": "Hesla se neshodují"})
        if read_user(email):
            return json_response(self, 409, {"ok": False, "error": "Uživatel už existuje"})

        rec = {
            "email": email,
            "role": "user",
            "createdAt": int(time.time()*1000),
            "verified": False,
            "profile": { "nickname": nickname, "avatar": None, "primaryTitle": "USER", "secondaryTitle": None, "frame": None },
            "password": new_password_hash(password1),
        }
        write_user(email, rec)

        token = create_verify_token(email)
        verify_url = f"{self._origin()}/auth/verify?token={token}"

        # Tady by se posílal e-mail (SMTP / služba). Pro vývoj vracíme verify_url.
        return json_response(self, 200, {"ok": True, "verify_url": verify_url})

    # --- Auth: /auth/login ---
    def handle_login(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})

        email = (body.get("email") or "").strip().lower()
        password = body.get("password") or ""
        user = read_user(email)
        if not user or not verify_password(user.get("password"), password):
            return json_response(self, 401, {"ok": False, "error": "Špatný e-mail nebo heslo"})
        if not user.get("verified"):
            return json_response(self, 403, {"ok": False, "error": "Účet není ověřen. Zkontroluj e-mail."})
        token = make_token(email, user.get("role","user"))
        return json_response(self, 200, {
            "ok": True,
            "token": token,
            "user": { "email": email, "role": user.get("role","user"), "profile": user.get("profile") }
        })

    # pomocný origin
    def _origin(self) -> str:
        host = self.headers.get("Host") or "localhost:8000"
        proto = "https" if host.endswith(":443") else "http"
        return f"{proto}://{host}"

def run():
    ensure_dirs()
    port = int(os.getenv("PORT", "8000"))
    httpd = HTTPServer(("0.0.0.0", port), Handler)
    print(f"✅ Server běží na http://0.0.0.0:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
