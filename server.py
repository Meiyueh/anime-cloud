#!/usr/bin/env python3
import os, json, re, base64, shutil, requests
from http.server import HTTPServer, SimpleHTTPRequestHandler
from email.parser import BytesParser
from email.policy import default as email_default

# === SUPABASE CONFIG ===
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE", "")
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "anime-cloud")

# === PATHS ===
ROOT = os.getcwd()
DATA_DIR = os.path.join(ROOT, "data")
ANIME_JSON = os.path.join(DATA_DIR, "anime.json")
WIPE_PASSWORD = "789456123Lol"

# === HELPERS ===
def safe_name(name: str) -> str:
    if isinstance(name, bytes):
        name = name.decode("utf-8", "ignore")
    keep = "._-()[]{}@+&= "
    name = "".join(ch for ch in name if ch.isalnum() or ch in keep)
    name = name.replace("/", "").replace("\\", "")
    return name.strip() or "file"

def json_response(handler, status, obj):
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.end_headers()
    handler.wfile.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

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

# === SUPABASE UPLOAD ===
def upload_to_supabase(path_in_bucket: str, raw: bytes, mime: str) -> str:
    """Nahraje bytes do Supabase Storage a vrátí veřejnou URL."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError("Supabase credentials missing")
    url = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_BUCKET}/{path_in_bucket}"
    r = requests.post(
        url,
        headers={"Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type": mime},
        data=raw,
    )
    if not r.ok and r.status_code != 409:  # 409 = soubor už existuje (ignore)
        raise RuntimeError(f"Upload failed {r.status_code}: {r.text}")
    return f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/{path_in_bucket}"

# === DATA URL COVER ===
DATAURL_RE = re.compile(r"^data:(?P<mime>[\w/+.-]+);base64,(?P<b64>.*)$", re.DOTALL)
def save_cover_from_dataurl(data_url: str, slug: str) -> str:
    m = DATAURL_RE.match(data_url.strip())
    if not m:
        raise ValueError("Invalid data URL")
    mime = m.group("mime").lower()
    raw = base64.b64decode(m.group("b64"), validate=True)
    ext = {
        "image/jpeg": "jpg",
        "image/jpg": "jpg",
        "image/png": "png",
        "image/webp": "webp",
        "image/gif": "gif",
    }.get(mime, "jpg")
    path_in_bucket = f"covers/{safe_name(slug)}.{ext}"
    return upload_to_supabase(path_in_bucket, raw, mime)

# === MULTIPART PARSER ===
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
            if not name:
                continue
            filename = part.get_filename()
            payload = part.get_payload(decode=True)
            if filename is None:
                charset = part.get_content_charset() or "utf-8"
                try:
                    value = payload.decode(charset, errors="ignore")
                except Exception:
                    value = payload.decode("utf-8", errors="ignore")
                fields[name] = value
            else:
                fields[name] = payload
    return fields

# === HANDLER ===
class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        match self.path:
            case "/upload": self.handle_upload()
            case "/feedback": self.handle_feedback()
            case "/wipe_all": self.handle_wipe_all()
            case "/admin/add_anime": self.handle_add_anime()
            case "/admin/upload_cover": self.handle_upload_cover()
            case _: self.send_error(404, "Not found")

    # --- Upload video/subs ---
    def handle_upload(self):
        fields = parse_multipart_request(self)
        anime = fields.get("anime")
        episode = fields.get("episode")
        quality = fields.get("quality")
        video = fields.get("video")
        videoName = fields.get("videoName")
        subs = fields.get("subs")
        subsName = fields.get("subsName")

        if not all([anime, episode, quality, video, videoName]):
            return self.send_error(400, "Missing required fields")

        ep_folder = f"{int(episode):05d}"
        videoName = safe_name(videoName)
        video_path = f"anime/{anime}/{ep_folder}/{quality}/{videoName}"
        subs_path = f"anime/{anime}/{ep_folder}/{quality}/{safe_name(subsName or 'subs.srt')}"

        try:
            video_url = upload_to_supabase(video_path, video, "video/mp4")
            subs_url = None
            if subs:
                subs_url = upload_to_supabase(subs_path, subs, "application/x-subrip")
            json_response(self, 200, {"status": "ok", "video": video_url, "subs": subs_url})
        except Exception as e:
            json_response(self, 500, {"status": "error", "message": str(e)})

    # --- Feedback ---
    def handle_feedback(self):
        length = int(self.headers.get("Content-Length", "0"))
        data = json.loads(self.rfile.read(length))
        os.makedirs("feedback", exist_ok=True)
        with open(f"feedback/{data.get('id','feedback')}.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        self.send_response(200); self.end_headers()

    # --- Wipe ---
    def handle_wipe_all(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        if payload.get("password") != WIPE_PASSWORD:
            self.send_error(403, "Forbidden"); return
        json_response(self, 200, {"status": "cloud wipe disabled (Supabase)"})

    # --- Add anime ---
    def handle_add_anime(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        slug = safe_name(body["slug"].lower())
        cover_in = body.get("cover")
        try:
            if isinstance(cover_in, str) and cover_in.startswith("data:"):
                cover_url = save_cover_from_dataurl(cover_in, slug)
            else:
                cover_url = str(cover_in)
        except Exception as e:
            return json_response(self, 400, {"ok": False, "error": str(e)})

        item = {
            "slug": slug,
            "title": body["title"],
            "episodes": int(body["episodes"]),
            "genres": body["genres"],
            "description": body["description"],
            "cover": cover_url,
            "status": body["status"],
            "year": int(body["year"]),
            "studio": body["studio"],
        }

        items = load_json(ANIME_JSON, [])
        items = [a for a in items if a.get("slug") != slug]
        items.append(item)
        save_json(ANIME_JSON, items)
        json_response(self, 200, {"ok": True, "saved": item})

    # --- Upload cover ---
    def handle_upload_cover(self):
        fields = parse_multipart_request(self)
        slug = fields.get("slug")
        cover = fields.get("cover")
        if not slug or not cover:
            return json_response(self, 400, {"ok": False, "error": "Missing slug or cover"})
        try:
            url = upload_to_supabase(f"covers/{safe_name(slug)}.jpg", cover, "image/jpeg")
            json_response(self, 200, {"ok": True, "path": url})
        except Exception as e:
            json_response(self, 500, {"ok": False, "error": str(e)})

# === START SERVER ===
def run():
    port = int(os.getenv("PORT", "8000"))
    httpd = HTTPServer(("0.0.0.0", port), Handler)
    print(f"✅ Server běží na http://0.0.0.0:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
