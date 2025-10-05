#!/usr/bin/env python3
import os, json, re, base64, requests, hashlib, traceback, io, time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from email.parser import BytesParser
from email.policy import default as email_default
from urllib.parse import quote
from dotenv import load_dotenv

load_dotenv()

# === Konfigurace úložišť ===
GCS_BUCKET = os.getenv("GCS_BUCKET", "").strip()
GCS_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE", "")
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "anime-cloud")

# Cloud cesta pro anime.json (sjednoceno s FE na /data/)
ANIME_JSON_CLOUD = os.getenv("ANIME_JSON_CLOUD", "data/anime.json")

# Default admin (pro první spuštění; lze přepsat env proměnnými)
DEFAULT_ADMIN_EMAIL = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@localanim")
DEFAULT_ADMIN_PASS  = os.getenv("DEFAULT_ADMIN_PASS",  "12345")

# Ostatní
ROOT = os.getcwd()
FEEDBACK_DIR = os.path.join(ROOT, "feedback")
WIPE_PASSWORD = "789456123Lol"

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

def ensure_dirs():
    os.makedirs(FEEDBACK_DIR, exist_ok=True)

# MIME map
EXT_MIME = {
    ".mp4":"video/mp4", ".m4v":"video/x-m4v", ".webm":"video/webm", ".mkv":"video/x-matroska", ".mov":"video/quicktime",
    ".srt":"application/x-subrip", ".vtt":"text/vtt",
    ".jpg":"image/jpeg", ".jpeg":"image/jpeg", ".png":"image/png", ".webp":"image/webp", ".gif":"image/gif",
}
VIDEO_EXT = {".mp4",".m4v",".webm",".mkv",".mov"}
SUBS_EXT  = {".srt",".vtt"}

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

# ===== Storage: GCS / Supabase =====
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
    blob.cache_control = "public, max-age=31536000, immutable"
    blob.upload_from_string(raw, content_type=(mime or "application/octet-stream"))
    return gcs_public_url(path_in_bucket)

def download_from_gcs(path_in_bucket: str) -> bytes|None:
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    blob = bucket.blob(path_in_bucket)
    if not blob.exists(client):
        return None
    return blob.download_as_bytes()

def delete_from_gcs(path_in_bucket: str) -> None:
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    blob = bucket.blob(path_in_bucket)
    if blob.exists(client):
        blob.delete()

def list_from_gcs(prefix: str) -> list[str]:
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    return [b.name for b in client.list_blobs(bucket, prefix=prefix)]

def supabase_public_url(path_in_bucket: str) -> str:
    parts = [quote(p) for p in path_in_bucket.split("/")]
    return f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/{'/'.join(parts)}"

def upload_to_supabase(path_in_bucket: str, raw: bytes, mime: str, overwrite: bool=True) -> str:
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError("Supabase not configured.")
    url = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_BUCKET}/{path_in_bucket}"
    headers = {
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": mime or "application/octet-stream",
        "x-upsert": "true" if overwrite else "false",
        "cache-control": "public, max-age=31536000, immutable",
    }
    r = requests.post(url, headers=headers, data=raw, timeout=60)
    if not r.ok and r.status_code != 409:
        raise RuntimeError(f"Upload failed {r.status_code}: {r.text}")
    return supabase_public_url(path_in_bucket)

def download_from_supabase_public(path_in_bucket: str) -> bytes|None:
    if not SUPABASE_URL:
        return None
    url = supabase_public_url(path_in_bucket)
    r = requests.get(url, timeout=30)
    if r.status_code == 200:
        return r.content
    return None

def delete_from_supabase(path_in_bucket: str) -> None:
    if not SUPABASE_URL or not SUPABASE_KEY: return
    url = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_BUCKET}/{path_in_bucket}"
    headers = {"Authorization": f"Bearer {SUPABASE_KEY}"}
    requests.delete(url, headers=headers, timeout=30)

def list_from_supabase(prefix: str) -> list[str]:
    """Jednoduché (nerekurzivní) listování – pro strom používáme GCS. Pokud je aktivní jen Supabase, vrátíme prázdné pole."""
    # Supabase list vyžaduje rekurzi přes folders; pro zjednodušení strom nepodporujeme, pokud neběží GCS.
    return []

def upload_bytes(path_in_bucket: str, raw: bytes, mime: str, overwrite: bool=True) -> str:
    if GCS_BUCKET:
        return upload_to_gcs(path_in_bucket, raw, mime, overwrite)
    return upload_to_supabase(path_in_bucket, raw, mime, overwrite)

def download_bytes(path_in_bucket: str) -> bytes|None:
    if GCS_BUCKET:
        return download_from_gcs(path_in_bucket)
    return download_from_supabase_public(path_in_bucket)

def delete_bytes(path_in_bucket: str) -> None:
    if GCS_BUCKET:
        delete_from_gcs(path_in_bucket)
    else:
        delete_from_supabase(path_in_bucket)

def list_objects(prefix: str) -> list[str]:
    if GCS_BUCKET:
        return list_from_gcs(prefix)
    return list_from_supabase(prefix)

# ===== anime.json: čtení/zápis přímo v cloudu =====
def read_anime_list() -> list:
    try:
        b = download_bytes(ANIME_JSON_CLOUD)
        if not b:
            return []
        return json.loads(b.decode("utf-8"))
    except Exception:
        return []

def write_anime_list(items: list) -> str:
    raw = json.dumps(items, ensure_ascii=False, indent=2).encode("utf-8")
    if GCS_BUCKET:
        client = _ensure_gcs()
        bucket = client.bucket(GCS_BUCKET)
        blob = bucket.blob(ANIME_JSON_CLOUD)
        # záměrně bez dlouhé cache
        blob.upload_from_string(raw, content_type="application/json; charset=utf-8")
        return gcs_public_url(ANIME_JSON_CLOUD)
    else:
        return upload_to_supabase(ANIME_JSON_CLOUD, raw, "application/json; charset=utf-8", overwrite=True)

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
    return upload_bytes(path_in_bucket, raw, mime, overwrite=True)

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

# ===== Users (cloud) =====
def _pw_hash(passwd: str) -> str:
    salt = os.urandom(16)
    iters = 200_000
    dk = hashlib.pbkdf2_hmac("sha256", passwd.encode("utf-8"), salt, iters, dklen=32)
    return "pbkdf2$%d$%s$%s" % (iters, salt.hex(), dk.hex())

def _pw_check(passwd: str, stored: str) -> bool:
    try:
        scheme, s_iters, s_salt, s_hash = stored.split("$")
        iters = int(s_iters); salt = bytes.fromhex(s_salt); hh = bytes.fromhex(s_hash)
        dk = hashlib.pbkdf2_hmac("sha256", passwd.encode("utf-8"), salt, iters, dklen=len(hh))
        return dk == hh
    except Exception:
        return False

def _user_path(email: str) -> str:
    return f"users/{safe_name(email)}.json"

def _read_user(email: str) -> dict|None:
    b = download_bytes(_user_path(email))
    if not b: return None
    try: return json.loads(b.decode("utf-8"))
    except Exception: return None

def _write_user(u: dict) -> str:
    raw = json.dumps(u, ensure_ascii=False, indent=2).encode("utf-8")
    return upload_bytes(_user_path(u["email"]), raw, "application/json; charset=utf-8", overwrite=True)

def ensure_default_admin():
    u = _read_user(DEFAULT_ADMIN_EMAIL)
    if u: return
    now = int(time.time()*1000)
    admin = {
        "email": DEFAULT_ADMIN_EMAIL,
        "role": "admin",
        "createdAt": now,
        "profile": { "nickname": "Admin", "avatar": None, "primaryTitle": "ADMIN", "secondaryTitle": None, "frame": None },
        "pass": _pw_hash(DEFAULT_ADMIN_PASS)
    }
    _write_user(admin)

# ===== HTTP handler =====
class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200); self.end_headers()

    def do_POST(self):
        try:
            match self.path:
                case "/upload": self.handle_upload()
                case "/feedback": self.handle_feedback()
                case "/wipe_all": self.handle_wipe_all()
                case "/admin/add_anime": self.handle_add_anime()
                case "/admin/upload_cover": self.handle_upload_cover()
                # users
                case "/users/register": self.handle_user_register()
                case "/users/login": self.handle_user_login()
                case "/users/profile/get": self.handle_user_get()
                case "/users/profile/update": self.handle_user_update()
                case "/users/avatar": self.handle_user_avatar()
                case _: json_response(self, 404, {"ok": False, "error": "Not found"})
        except Exception as e:
            traceback.print_exc()
            json_response(self, 500, {"ok": False, "error": f"Unhandled error: {e}"})

    def do_GET(self):
        try:
            if self.path == "/admin/tree":
                self.handle_admin_tree()
                return
            return super().do_GET()
        except Exception as e:
            traceback.print_exc()
            json_response(self, 500, {"ok": False, "error": f"Unhandled error: {e}"})

    def do_DELETE(self):
        try:
            if self.path == "/delete":
                self.handle_delete_object()
            else:
                json_response(self, 404, {"ok": False, "error": "Not found"})
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
            video_url = upload_bytes(video_path, video, v_mime, overwrite=True)
        except RuntimeError:
            video_url = upload_bytes(avoid_collision(video_path), video, v_mime, overwrite=False)

        subs_url = None
        if subs:
            try:
                subs_url = upload_bytes(subs_path, subs, s_mime, overwrite=True)
            except RuntimeError:
                subs_url = upload_bytes(avoid_collision(subs_path), subs, s_mime, overwrite=False)

        return json_response(self, 200, {"ok": True, "video": video_url, "subs": subs_url})

    # --- Feedback -> cloud + lokální fallback ---
    def handle_feedback(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        fid = safe_name(str(data.get("id") or f"feedback_{int(time.time()*1000)}"))
        raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        # zkus cloud
        try:
            upload_bytes(f"feedback/{fid}.json", raw, "application/json; charset=utf-8", overwrite=True)
            cloud = True
        except Exception:
            cloud = False
        # lokální záloha
        try:
            ensure_dirs()
            with open(os.path.join(FEEDBACK_DIR, f"{fid}.json"), "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
        return json_response(self, 200, {"ok": True, "stored_cloud": cloud})

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
        url = upload_bytes(f"covers/{safe_name(slug)}.{ext}", cover, mime, overwrite=True)
        return json_response(self, 200, {"ok": True, "path": url})

    # --- Users API ---
    def handle_user_register(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        email = (body.get("email") or "").strip().lower()
        password = body.get("password") or ""
        if not email or not password:
            return json_response(self, 400, {"ok": False, "error": "Missing email/password"})
        if _read_user(email):
            return json_response(self, 409, {"ok": False, "error": "User exists"})
        now = int(time.time()*1000)
        u = {
            "email": email,
            "role": "user",
            "createdAt": now,
            "profile": { "nickname": email.split("@")[0], "avatar": None, "primaryTitle": "USER", "secondaryTitle": None, "frame": None },
            "pass": _pw_hash(password)
        }
        _write_user(u)
        return json_response(self, 200, {"ok": True})

    def handle_user_login(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        email = (body.get("email") or "").strip().lower()
        password = body.get("password") or ""
        u = _read_user(email)
        if not u or not _pw_check(password, u.get("pass","")):
            return json_response(self, 401, {"ok": False, "error": "Bad credentials"})
        # sanitize
        out = {k:v for k,v in u.items() if k != "pass"}
        return json_response(self, 200, {"ok": True, "user": out})

    def handle_user_get(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        email = (body.get("email") or "").strip().lower()
        u = _read_user(email)
        if not u: return json_response(self, 404, {"ok": False, "error": "Not found"})
        return json_response(self, 200, {"ok": True, "user": {k:v for k,v in u.items() if k!="pass"}})

    def handle_user_update(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        email = (body.get("email") or "").strip().lower()
        patch = body.get("profilePatch") or {}
        u = _read_user(email)
        if not u: return json_response(self, 404, {"ok": False, "error": "Not found"})
        u.setdefault("profile", {})
        if "nickname" in patch: u["profile"]["nickname"] = patch["nickname"] or u["profile"].get("nickname")
        if "secondaryTitle" in patch: u["profile"]["secondaryTitle"] = patch["secondaryTitle"]
        _write_user(u)
        return json_response(self, 200, {"ok": True, "user": {k:v for k,v in u.items() if k!="pass"}})

    def handle_user_avatar(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        email = (body.get("email") or "").strip().lower()
        data_url = body.get("dataUrl") or ""
        u = _read_user(email)
        if not u: return json_response(self, 404, {"ok": False, "error": "Not found"})
        m = DATAURL_RE.match(data_url.strip())
        if not m: return json_response(self, 400, {"ok": False, "error": "Invalid image data"})
        mime = m.group("mime").lower()
        raw = base64.b64decode(m.group("b64"), validate=True)
        ext = {"image/jpeg":"jpg","image/jpg":"jpg","image/png":"png","image/webp":"webp"}.get(mime,"jpg")
        path = f"users/avatars/{safe_name(email)}.{ext}"
        url = upload_bytes(path, raw, mime, overwrite=True)
        u.setdefault("profile", {})["avatar"] = url
        _write_user(u)
        return json_response(self, 200, {"ok": True, "avatar": url})

    # --- Admin tree (cloud listing) ---
    def handle_admin_tree(self):
        # pouze GCS strom (Supabase list je zjednodušeně nepodporován)
        objs = list_objects("anime/")
        if not objs and not GCS_BUCKET:
            return json_response(self, 400, {"ok": False, "error": "Listing not supported without GCS"})
        # slug -> title map z anime.json
        name_map = {a.get("slug"): a.get("title") for a in read_anime_list()}
        # poskládej records
        records = []
        # pomocný lookup pro titulky
        subs_lookup = set([p for p in objs if any(p.lower().endswith(ext) for ext in SUBS_EXT)])
        for p in objs:
            low = p.lower()
            if not any(low.endswith(ext) for ext in VIDEO_EXT):
                continue
            try:
                _, slug, epfolder, quality, fname = p.split("/", 4)
            except ValueError:
                continue
            ep = int(epfolder)
            base_no_ext = fname.rsplit(".",1)[0]
            # hledej matching .srt/.vtt ve stejné složce
            subs_name = None
            for ext in (".srt",".vtt"):
                cand = f"anime/{slug}/{epfolder}/{quality}/{base_no_ext}{ext}"
                if cand in subs_lookup:
                    subs_name = base_no_ext+ext
                    break
            records.append({
                "slug": slug,
                "title": name_map.get(slug, slug),
                "episode": ep,
                "epFolder": epfolder,
                "quality": quality,
                "videoName": fname,
                "subsName": subs_name,
                "path": p,
                "subsPath": f"anime/{slug}/{epfolder}/{quality}/{subs_name}" if subs_name else None
            })
        return json_response(self, 200, {"ok": True, "records": records})

    # --- Delete (single object) ---
    def handle_delete_object(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        path = body.get("path")
        if not path and all(k in body for k in ("anime","episode","quality","videoName")):
            epf = f"{int(body['episode']):05d}"
            path = f"anime/{body['anime']}/{epf}/{body['quality']}/{body['videoName']}"
        if not path:
            return json_response(self, 400, {"ok": False, "error": "Missing path"})
        delete_bytes(path)
        # volitelně smaž i subsPath
        subs = body.get("subsPath")
        if subs: 
            try: delete_bytes(subs)
            except Exception: pass
        return json_response(self, 200, {"ok": True, "deleted": path})

def run():
    ensure_dirs()
    try:
        ensure_default_admin()
    except Exception:
        pass
    port = int(os.getenv("PORT", "8000"))
    httpd = HTTPServer(("0.0.0.0", port), Handler)
    print(f"✅ Server běží na http://0.0.0.0:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
