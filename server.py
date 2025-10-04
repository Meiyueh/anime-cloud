#!/usr/bin/env python3
import os, json, re, base64, requests, hashlib
from http.server import HTTPServer, SimpleHTTPRequestHandler
from email.parser import BytesParser
from email.policy import default as email_default
from urllib.parse import quote
from dotenv import load_dotenv

# ========== ENV ==========
load_dotenv()

# --- GCS config (použije se, pokud je nastaven GCS_BUCKET) ---
GCS_BUCKET = os.getenv("GCS_BUCKET", "").strip()
GCS_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()

# --- Supabase config (fallback, když není GCS_BUCKET) ---
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE", "")
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "anime-cloud")

ROOT = os.getcwd()
DATA_DIR = os.path.join(ROOT, "data")
ANIME_JSON = os.path.join(DATA_DIR, "anime.json")
FEEDBACK_DIR = os.path.join(ROOT, "feedback")
WIPE_PASSWORD = "789456123Lol"

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

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(FEEDBACK_DIR, exist_ok=True)

EXT_MIME = {
    ".mp4":"video/mp4", ".m4v":"video/x-m4v", ".webm":"video/webm", ".mkv":"video/x-matroska", ".mov":"video/quicktime",
    ".srt":"application/x-subrip", ".vtt":"text/vtt",
    ".jpg":"image/jpeg", ".jpeg":"image/jpeg", ".png":"image/png", ".webp":"image/webp", ".gif":"image/gif",
}
def guess_mime(filename: str, sniff: bytes | None = None, default: str = "application/octet-stream") -> str:
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

# ========== STORAGE LAYER ==========
# --- GCS (preferovaný) ---
_gcs_client = None
def _ensure_gcs():
    global _gcs_client
    if _gcs_client is None:
        from google.cloud import storage
        if not GCS_BUCKET or not GCS_CREDENTIALS:
            raise RuntimeError("GCS not configured (GCS_BUCKET/GOOGLE_APPLICATION_CREDENTIALS).")
        _gcs_client = storage.Client()
    return _gcs_client

def gcs_public_url(path_in_bucket: str) -> str:
    parts = [quote(p) for p in path_in_bucket.split("/")]
    return f"https://storage.googleapis.com/{GCS_BUCKET}/{'/'.join(parts)}"

def upload_to_gcs(path_in_bucket: str, raw: bytes, mime: str, overwrite: bool = True) -> str:
    client = _ensure_gcs()
    bucket = client.bucket(GCS_BUCKET)
    blob = bucket.blob(path_in_bucket)
    if not overwrite and blob.exists(client):
        raise RuntimeError("exists")
    blob.cache_control = "public, max-age=31536000, immutable"
    blob.upload_from_string(raw, content_type=(mime or "application/octet-stream"))
    # public read bucket -> URL funguje bez signování
    return gcs_public_url(path_in_bucket)

# --- Supabase (fallback) ---
def supabase_public_url(path_in_bucket: str) -> str:
    parts = [quote(p) for p in path_in_bucket.split("/")]
    return f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/{'/'.join(parts)}"

def upload_to_supabase(path_in_bucket: str, raw: bytes, mime: str, overwrite: bool = True) -> str:
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

# --- unified API ---
def upload_bytes(path_in_bucket: str, raw: bytes, mime: str, overwrite: bool = True) -> str:
    if GCS_BUCKET:
        return upload_to_gcs(path_in_bucket, raw, mime, overwrite)
    return upload_to_supabase(path_in_bucket, raw, mime, overwrite)

# ========== DATA URL COVER ==========
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

# ========== MULTIPART ==========
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

# ========== HTTP HANDLER ==========
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
                case _: json_response(self, 404, {"ok": False, "error": "Not found"})
        except Exception as e:
            json_response(self, 500, {"ok": False, "error": f"Unhandled error: {e}"})

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

    def handle_feedback(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        ensure_dirs()
        fid = safe_name(str(data.get("id") or "feedback"))
        with open(os.path.join(FEEDBACK_DIR, f"{fid}.json"), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return json_response(self, 200, {"ok": True})

    def handle_wipe_all(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})
        if payload.get("password") != WIPE_PASSWORD:
            return json_response(self, 403, {"ok": False, "error": "Forbidden"})
        return json_response(self, 200, {"ok": True, "status": "cloud wipe disabled"})

    def handle_add_anime(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
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

        items = load_json(ANIME_JSON, [])
        items = [a for a in items if a.get("slug") != slug]
        items.append(item)
        save_json(ANIME_JSON, items)
        return json_response(self, 200, {"ok": True, "saved": item})

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

def run():
    ensure_dirs()
    port = int(os.getenv("PORT", "8000"))
    httpd = HTTPServer(("0.0.0.0", port), Handler)
    print(f"✅ Server běží na http://0.0.0.0:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
