#!/usr/bin/env python3
import os, json, re, base64, requests, hashlib, traceback, io, time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from email.parser import BytesParser
from email.policy import default as email_default
from urllib.parse import quote, urlparse, parse_qs
from dotenv import load_dotenv

load_dotenv()

# === Konfigurace úložišť ===
GCS_BUCKET = os.getenv("GCS_BUCKET", "").strip()
GCS_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE", "")
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "anime-cloud")

# Cesty v cloudu
ANIME_JSON_CLOUD = os.getenv("ANIME_JSON_CLOUD", "data/anime.json")  # sjednoceno na /data
USERS_PREFIX     = os.getenv("USERS_PREFIX", "users")
FEEDBACK_PREFIX  = os.getenv("FEEDBACK_PREFIX", "feedback")

# Ostatní
ROOT = os.getcwd()
FEEDBACK_DIR = os.path.join(ROOT, "feedback")  # lokální fallback
WIPE_PASSWORD = os.getenv("WIPE_PASSWORD", "789456123Lol")

# ===== Helpers =====
def now_ms() -> int: return int(time.time() * 1000)

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
    # dlouhá cache pouze pro statické soubory, JSONy řešíme zvlášť
    if not path_in_bucket.endswith(".json"):
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

def delete_from_gcs(path_in_bucket: str) -> bool:
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    blob = bucket.blob(path_in_bucket)
    if not blob.exists(client):
        return False
    blob.delete()
    return True

def list_gcs(prefix: str) -> list[str]:
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    blobs = client.list_blobs(bucket, prefix=prefix)
    return [b.name for b in blobs if not b.name.endswith("/")]  # bez "adresářů"

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
    if path_in_bucket.endswith(".json"):
        headers["cache-control"] = "no-cache"
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

def delete_from_supabase(path_in_bucket: str) -> bool:
    if not SUPABASE_URL or not SUPABASE_KEY:
        return False
    url = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_BUCKET}/{path_in_bucket}"
    headers = {"Authorization": f"Bearer {SUPABASE_KEY}"}
    r = requests.delete(url, headers=headers, timeout=30)
    return r.status_code in (200, 204)

def list_supabase(prefix: str) -> list[str]:
    if not SUPABASE_URL or not SUPABASE_KEY:
        return []
    url = f"{SUPABASE_URL}/storage/v1/object/list/{SUPABASE_BUCKET}"
    headers = {"Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type":"application/json"}
    payload = {"prefix": prefix, "limit": 10000}
    out = []
    r = requests.post(url, headers=headers, json=payload, timeout=60)
    if not r.ok:
        return out
    for itm in r.json() or []:
        name = itm.get("name") or ""
        # response je relativní k prefixu, takže slož prefix + name
        out.append(f"{prefix.rstrip('/')}/{name}")
    return out

def upload_bytes(path_in_bucket: str, raw: bytes, mime: str, overwrite: bool=True) -> str:
    if GCS_BUCKET:
        return upload_to_gcs(path_in_bucket, raw, mime, overwrite)
    return upload_to_supabase(path_in_bucket, raw, mime, overwrite)

def download_bytes(path_in_bucket: str) -> bytes|None:
    if GCS_BUCKET:
        return download_from_gcs(path_in_bucket)
    return download_from_supabase_public(path_in_bucket)

def delete_bytes(path_in_bucket: str) -> bool:
    if GCS_BUCKET:
        return delete_from_gcs(path_in_bucket)
    return delete_from_supabase(path_in_bucket)

def list_objects(prefix: str) -> list[str]:
    if GCS_BUCKET:
        return list_gcs(prefix)
    return list_supabase(prefix)

def public_url(path_in_bucket: str) -> str:
    if GCS_BUCKET:
        return gcs_public_url(path_in_bucket)
    return supabase_public_url(path_in_bucket)

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
    # JSON bez dlouhé cache
    if GCS_BUCKET:
        client = _ensure_gcs()
        bucket = client.bucket(GCS_BUCKET)
        blob = bucket.blob(ANIME_JSON_CLOUD)
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
def email_key(email: str) -> str:
    e = (email or "").strip().lower()
    return hashlib.sha256(e.encode("utf-8")).hexdigest()

def user_path(email: str) -> str:
    return f"{USERS_PREFIX}/{email_key(email)}.json"

def load_user(email: str) -> dict|None:
    b = download_bytes(user_path(email))
    if not b: return None
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:
        return None

def save_user(user_obj: dict):
    raw = json.dumps(user_obj, ensure_ascii=False, indent=2).encode("utf-8")
    upload_bytes(user_path(user_obj["email"]), raw, "application/json; charset=utf-8", overwrite=True)

def hash_pwd(salt: str, pwd: str) -> str:
    return hashlib.sha256((salt + ":" + pwd).encode("utf-8")).hexdigest()

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
            if self.path.startswith("/users/profile"):
                return self.handle_users_profile()
            elif self.path.startswith("/admin/list_tree"):
                return self.handle_admin_list_tree()
            elif self.path.startswith("/feedback/list"):
                return self.handle_feedback_list()
            else:
                return super().do_GET()
        except Exception as e:
            traceback.print_exc()
            json_response(self, 500, {"ok": False, "error": f"Unhandled error: {e}"})

    def do_DELETE(self):
        try:
            match self.path:
                case "/delete": self.handle_delete_object()
                case _: json_response(self, 404, {"ok": False, "error": "Not found"})
        except Exception as e:
            traceback.print_exc()
            json_response(self, 500, {"ok": False, "error": f"Unhandled error: {e}"})

    def do_POST(self):
        try:
            match self.path:
                case "/upload": self.handle_upload()
                case "/feedback": self.handle_feedback()
                case "/wipe_all": self.handle_wipe_all()
                case "/admin/add_anime": self.handle_add_anime()
                case "/admin/upload_cover": self.handle_upload_cover()
                # users
                case "/users/register": self.handle_users_register()
                case "/users/login": self.handle_users_login()
                case "/users/update_profile": self.handle_users_update_profile()
                case "/users/change_password": self.handle_users_change_password()
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

    # --- Feedback: uložit i do cloudu ---
    def handle_feedback(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})

        # lokální fallback (neztrácej)
        ensure_dirs()
        fid = safe_name(str(data.get("id") or f"feedback_{now_ms()}"))
        with open(os.path.join(FEEDBACK_DIR, f"{fid}.json"), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        # cloud
        try:
            raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
            upload_bytes(f"{FEEDBACK_PREFIX}/{fid}.json", raw, "application/json; charset=utf-8", overwrite=True)
        except Exception as e:
            # nevadí, jen zaloguj
            print("Feedback cloud save failed:", e)

        return json_response(self, 200, {"ok": True})

    def handle_feedback_list(self):
        # přečti všechny soubory z feedback/
        try:
            files = list_objects(f"{FEEDBACK_PREFIX}/")
            out = []
            for p in files:
                b = download_bytes(p)
                if not b: continue
                try:
                    out.append(json.loads(b.decode("utf-8")))
                except: pass
            # seřadit novější první
            out.sort(key=lambda x: x.get("ts", 0), reverse=True)
            return json_response(self, 200, {"ok": True, "items": out})
        except Exception as e:
            return json_response(self, 500, {"ok": False, "error": f"list_error: {e}"})

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
        url = upload_bytes(f"covers/{safe_name(slug)}.{ext}", cover, mime, overwrite=True)
        return json_response(self, 200, {"ok": True, "path": url})

    # --- Admin: list cloud tree anime/... ---
    def handle_admin_list_tree(self):
        try:
            entries = list_objects("anime/")
            # entries: "anime/slug/00001/720p/720p_1.mp4" apod.
            # Seskupíme podle (slug, episode, quality, base)
            tree_map = {}  # (slug, ep, q, base) -> {videoName, subsName, urlVideo, urlSubs, updated?}
            for p in entries:
                parts = p.split("/")
                if len(parts) < 6:  # anime/slug/00001/720p/file
                    continue
                _, slug, ep_folder, q, name = parts[0], parts[1], parts[2], parts[3], parts[4]
                ep = int(ep_folder)
                base, dot, ext = name.rpartition(".")
                key = (slug, ep, q, base)
                rec = tree_map.get(key) or {"slug":slug, "episode":ep, "quality":q, "videoName":None, "subsName":None, "videoUrl":None, "subsUrl":None}
                if ext.lower() == "srt":
                    rec["subsName"] = name
                    rec["subsUrl"]  = public_url(p)
                else:
                    rec["videoName"] = name
                    rec["videoUrl"]  = public_url(p)
                tree_map[key] = rec

            flat = list(tree_map.values())

            # doplníme tituly z anime.json
            titles = {a.get("slug"): a.get("title") for a in read_anime_list()}
            for r in flat:
                r["title"] = titles.get(r["slug"], r["slug"])
            return json_response(self, 200, {"ok": True, "items": flat})
        except Exception as e:
            return json_response(self, 500, {"ok": False, "error": f"list_tree_error: {e}"})

    # --- Delete video (+párové srt) ---
    def handle_delete_object(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})

        slug = body.get("anime"); ep = int(body.get("episode")); q = body.get("quality"); name = body.get("videoName")
        if not (slug and ep and q and name):
            return json_response(self, 400, {"ok": False, "error": "Missing fields"})

        ep_folder = f"{int(ep):05d}"
        video_path = f"anime/{slug}/{ep_folder}/{q}/{safe_name(name)}"
        base, dot, ext = name.rpartition(".")
        subs_path  = f"anime/{slug}/{ep_folder}/{q}/{base}.srt"
        ok_v = delete_bytes(video_path)
        ok_s = delete_bytes(subs_path)  # nevadí, když neexistuje
        return json_response(self, 200, {"ok": True, "deleted_video": ok_v, "deleted_subs": ok_s})

    # ===== Users endpoints =====
    def handle_users_register(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        email = (body.get("email") or "").strip().lower()
        password = body.get("password") or ""
        if not email or not password:
            return json_response(self, 400, {"ok": False, "error": "Missing email/password"})
        if load_user(email):
            return json_response(self, 409, {"ok": False, "error": "User exists"})
        salt = hashlib.sha1(os.urandom(16)).hexdigest()
        user = {
            "email": email,
            "salt": salt,
            "pwd_hash": hash_pwd(salt, password),
            "role": "user",
            "createdAt": now_ms(),
            "profile": {
                "nickname": email.split("@")[0],
                "avatar": None,
                "primaryTitle": "USER",
                "secondaryTitle": None,
                "frame": None
            }
        }
        save_user(user)
        return json_response(self, 200, {"ok": True})

    def handle_users_login(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        email = (body.get("email") or "").strip().lower()
        password = body.get("password") or ""
        u = load_user(email)
        if not u:
            return json_response(self, 401, {"ok": False, "error": "No such user"})
        if hash_pwd(u.get("salt",""), password) != u.get("pwd_hash"):
            return json_response(self, 401, {"ok": False, "error": "Bad credentials"})
        # odpověď bez citlivých polí
        out = {
            "email": u["email"],
            "role": u.get("role","user"),
            "createdAt": u.get("createdAt"),
            "profile": u.get("profile") or {}
        }
        return json_response(self, 200, {"ok": True, "user": out})

    def handle_users_profile(self):
        q = parse_qs(urlparse(self.path).query or "")
        email = (q.get("email",[None])[0] or "").strip().lower()
        if not email:
            return json_response(self, 400, {"ok": False, "error": "Missing email"})
        u = load_user(email)
        if not u:
            return json_response(self, 404, {"ok": False, "error": "Not found"})
        out = {
            "email": u["email"],
            "role": u.get("role","user"),
            "createdAt": u.get("createdAt"),
            "profile": u.get("profile") or {}
        }
        return json_response(self, 200, {"ok": True, "user": out})

    def handle_users_update_profile(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        email = (body.get("email") or "").strip().lower()
        patch = body.get("patch") or {}
        u = load_user(email)
        if not u:
            return json_response(self, 404, {"ok": False, "error": "Not found"})
        prof = u.get("profile") or {}
        for k in ("nickname","avatar","secondaryTitle","frame"):
            if k in patch:
                prof[k] = patch[k]
        # primární titul odvozujeme z role
        prof["primaryTitle"] = "ADMIN" if u.get("role")=="admin" else ("UPLOADER" if u.get("role")=="uploader" else "USER")
        u["profile"] = prof
        save_user(u)
        return json_response(self, 200, {"ok": True})

    def handle_users_change_password(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        email = (body.get("email") or "").strip().lower()
        old = body.get("oldPassword") or ""
        new = body.get("newPassword") or ""
        if len(new) < 8:
            return json_response(self, 400, {"ok": False, "error": "Password too short"})
        u = load_user(email)
        if not u:
            return json_response(self, 404, {"ok": False, "error": "Not found"})
        if hash_pwd(u.get("salt",""), old) != u.get("pwd_hash"):
            return json_response(self, 401, {"ok": False, "error": "Bad credentials"})
        salt = hashlib.sha1(os.urandom(16)).hexdigest()
        u["salt"] = salt
        u["pwd_hash"] = hash_pwd(salt, new)
        save_user(u)
        return json_response(self, 200, {"ok": True})

def run():
    ensure_dirs()
    port = int(os.getenv("PORT", "8000"))
    httpd = HTTPServer(("0.0.0.0", port), Handler)
    print(f"✅ Server běží na http://0.0.0.0:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
