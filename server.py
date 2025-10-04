#!/usr/bin/env python3
import os, json, shutil, re, base64
from http.server import HTTPServer, SimpleHTTPRequestHandler
from email.parser import BytesParser
from email.policy import default as email_default

ROOT = os.getcwd()
UPLOAD_ROOT   = os.path.join(ROOT, 'uploads')
FEEDBACK_DIR  = os.path.join(ROOT, 'feedback')
DATA_DIR      = os.path.join(ROOT, 'data')
ANIME_JSON    = os.path.join(DATA_DIR, 'anime.json')
COVERS_DIR    = os.path.join(ROOT, 'assets', 'covers')
WIPE_PASSWORD = "789456123Lol"

def safe_name(name: str) -> str:
    if isinstance(name, bytes):
        name = name.decode('utf-8', 'ignore')
    keep = "._-()[]{}@+&= "
    name = "".join(ch for ch in name if ch.isalnum() or ch in keep)
    name = name.replace('/', '').replace('\\', '')
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
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def ensure_dirs():
    os.makedirs(UPLOAD_ROOT, exist_ok=True)
    os.makedirs(FEEDBACK_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(COVERS_DIR, exist_ok=True)

DATAURL_RE = re.compile(r"^data:(?P<mime>[\w/+.-]+);base64,(?P<b64>.*)$", re.DOTALL)

def save_cover_from_dataurl(data_url: str, slug: str) -> str:
    """
    Uloží cover z data URL do assets/covers/<slug>.<ext> a vrátí relativní cestu (covers/xxx.ext).
    """
    m = DATAURL_RE.match(data_url.strip())
    if not m:
        raise ValueError("Invalid data URL")
    mime = m.group("mime").lower()
    b64 = m.group("b64")
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:
        raise ValueError("Invalid base64 in data URL")

    ext = {
        'image/jpeg': 'jpg', 'image/jpg': 'jpg',
        'image/png': 'png',  'image/webp': 'webp', 'image/gif': 'gif'
    }.get(mime, 'bin')

    fname = f"{safe_name(slug)}.{ext}"
    fpath = os.path.join(COVERS_DIR, fname)
    with open(fpath, "wb") as f:
        f.write(raw)
    rel = os.path.join("covers", fname).replace("\\", "/")
    return rel

# ---------- Pomocný multipart parser (bez modulu cgi; funguje v Py 3.13) ----------
def parse_multipart_request(handler):
    """
    Vrátí dict { name: value } kde value je:
      - str pro textová pole (dekódovaná podle charsetu, default utf-8)
      - bytes pro binární pole (soubory)
    Pozn.: názvy souborů posíláš zvlášť jako videoName/subsName, takže filename nepotřebujeme.
    """
    length = int(handler.headers.get("Content-Length", "0") or "0")
    body = handler.rfile.read(length) if length > 0 else b""

    ctype = handler.headers.get("Content-Type", "")
    # vytvoříme pseudo hlavičky pro email parser
    headers_bytes = f"Content-Type: {ctype}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
    msg = BytesParser(policy=email_default).parsebytes(headers_bytes + body)

    fields = {}
    if msg.is_multipart():
        for part in msg.iter_parts():
            # jméno pole z Content-Disposition
            name = part.get_param('name', header='content-disposition')
            if not name:
                continue
            filename = part.get_filename()
            payload = part.get_payload(decode=True)  # bytes

            if filename is None:
                # textové pole: zkusíme dekódovat
                charset = part.get_content_charset() or 'utf-8'
                try:
                    value = payload.decode(charset, errors='ignore')
                except Exception:
                    value = payload.decode('utf-8', errors='ignore')
                fields[name] = value
            else:
                # binární pole (soubor)
                fields[name] = payload
    else:
        # fallback: není multipart
        pass

    return fields

class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200); self.end_headers()

    def do_POST(self):
        if self.path == "/upload":
            return self.handle_upload()
        elif self.path == "/feedback":
            return self.handle_feedback()
        elif self.path == "/wipe_all":
            return self.handle_wipe_all()
        elif self.path == "/admin/add_anime":
            return self.handle_add_anime()
        elif self.path == "/admin/upload_cover":
            return self.handle_upload_cover()
        else:
            self.send_error(404, "Not found")

    def do_DELETE(self):
        if self.path == "/delete":
            return self.handle_delete()
        else:
            self.send_error(404, "Not found")

    # ---------- Upload videí a titulků ----------
    def handle_upload(self):
        if not (self.headers.get("Content-Type","").startswith("multipart/form-data")):
            self.send_error(400, "Content-Type must be multipart/form-data"); return

        fields = parse_multipart_request(self)

        anime     = fields.get("anime")
        episode   = fields.get("episode")
        quality   = fields.get("quality")
        video     = fields.get("video")        # bytes
        videoName = fields.get("videoName")
        subs      = fields.get("subs")         # bytes (optional)
        subsName  = fields.get("subsName")

        if isinstance(anime, bytes): anime = anime.decode('utf-8','ignore')
        if isinstance(episode, bytes): episode = episode.decode('utf-8','ignore')
        if isinstance(quality, bytes): quality = quality.decode('utf-8','ignore')
        if isinstance(videoName, bytes): videoName = videoName.decode('utf-8','ignore')
        if isinstance(subsName, bytes): subsName = subsName.decode('utf-8','ignore')

        if not (anime and episode and quality and isinstance(video, (bytes, bytearray)) and videoName):
            self.send_error(400, "Missing required fields"); return

        videoName = safe_name(videoName)
        if subsName: subsName = safe_name(subsName)

        ep_folder = f"{int(episode):05d}"
        target_dir = os.path.join(UPLOAD_ROOT, anime, ep_folder, quality)
        os.makedirs(target_dir, exist_ok=True)

        video_path = os.path.join(target_dir, videoName)
        if os.path.exists(video_path):
            self.send_error(409, "File already exists"); return
        with open(video_path, "wb") as f:
            f.write(video)

        if subs and subsName:
            subs_path = os.path.join(target_dir, subsName)
            with open(subs_path, "wb") as f:
                f.write(subs)

        json_response(self, 200, {"status": "ok"})

    # ---------- Mazání nahrávky ----------
    def handle_delete(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
            anime = data["anime"]
            ep    = f"{int(data['episode']):05d}"
            q     = data["quality"]
            vname = data["videoName"]
        except Exception:
            self.send_error(400, "Invalid JSON or missing fields"); return

        folder = os.path.join(UPLOAD_ROOT, anime, ep, q)
        video_path = os.path.join(folder, vname)
        base, _ = os.path.splitext(vname)
        subs_path = os.path.join(folder, base + ".srt")

        ok = False
        if os.path.exists(video_path):
            os.remove(video_path); ok = True
        if os.path.exists(subs_path):
            os.remove(subs_path); ok = True

        json_response(self, 200 if ok else 404, {"status": "ok" if ok else "not_found"})

    # ---------- Feedback ----------
    def handle_feedback(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except Exception:
            self.send_error(400, "Invalid JSON"); return

        os.makedirs(FEEDBACK_DIR, exist_ok=True)
        ts = int(data.get("ts") or 0) or 0
        fid = data.get("id") or f"{ts}"
        fname = os.path.join(FEEDBACK_DIR, f"{fid}.json")
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        self.send_response(200); self.end_headers()

    # ---------- Wipe uploads ----------
    def handle_wipe_all(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
            pwd = payload.get("password","")
        except Exception:
            self.send_error(400, "Invalid JSON"); return

        if pwd != WIPE_PASSWORD:
            self.send_error(403, "Forbidden"); return

        if os.path.isdir(UPLOAD_ROOT):
            shutil.rmtree(UPLOAD_ROOT, ignore_errors=True)
        os.makedirs(UPLOAD_ROOT, exist_ok=True)

        json_response(self, 200, {"status":"wiped"})

    # ---------- Admin: přidání/aktualizace anime ----------
    def handle_add_anime(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "Invalid JSON"})

        required = ["slug","title","episodes","genres","description","cover","status","year","studio"]
        if not all(k in body for k in required):
            return json_response(self, 400, {"ok": False, "error": "Missing required fields"})

        slug  = safe_name(str(body["slug"]).strip().lower())
        title = str(body["title"]).strip()
        try:
            episodes = int(body["episodes"])
            year     = int(body["year"])
        except Exception:
            return json_response(self, 400, {"ok": False, "error": "episodes/year must be numbers"})

        genres = body["genres"]
        if not isinstance(genres, list) or not all(isinstance(x, str) and x.strip() for x in genres):
            return json_response(self, 400, {"ok": False, "error": "genres must be non-empty list of strings"})

        description = str(body["description"]).strip()
        status      = str(body["status"]).strip()
        studio      = str(body["studio"]).strip()
        cover_in    = body["cover"]

        # cover: data-url → lokální soubor; jinak bereme jako cestu/URL
        try:
            if isinstance(cover_in, str) and cover_in.startswith("data:"):
                cover_path = save_cover_from_dataurl(cover_in, slug)
            else:
                cover_path = str(cover_in)
        except Exception as e:
            return json_response(self, 400, {"ok": False, "error": f"cover invalid: {e}"})

        item = {
            "slug": slug,
            "title": title,
            "episodes": episodes,
            "genres": genres,
            "description": description,
            "cover": cover_path[7:] if cover_path.startswith("assets/") else cover_path,
            "status": status,
            "year": year,
            "studio": studio
        }

        items = load_json(ANIME_JSON, [])
        items = [a for a in items if a.get("slug") != slug]
        items.append(item)
        save_json(ANIME_JSON, items)

        return json_response(self, 200, {"ok": True, "saved": item})

    # ---------- Admin: upload coveru (multipart) ----------
    def handle_upload_cover(self):
        if not (self.headers.get("Content-Type","").startswith("multipart/form-data")):
            return json_response(self, 400, {"ok": False, "error": "Content-Type must be multipart/form-data"})

        fields = parse_multipart_request(self)

        slug  = fields.get("slug")
        cover = fields.get("cover")  # bytes
        if isinstance(slug, bytes):
            slug = slug.decode("utf-8", "ignore")
        if not slug or not isinstance(cover, (bytes, bytearray)):
            return json_response(self, 400, {"ok": False, "error": "Missing slug or cover"})

        # pokus odhadnout příponu
        ext = "jpg"
        sniff = bytes(cover[:10])
        if sniff.startswith(b"\x89PNG"):
            ext = "png"
        elif sniff[:3] == b"\xff\xd8\xff":
            ext = "jpg"
        elif sniff[:4] == b"RIFF":
            ext = "webp"

        fname = f"{safe_name(slug)}.{ext}"
        os.makedirs(COVERS_DIR, exist_ok=True)
        fpath = os.path.join(COVERS_DIR, fname)
        with open(fpath, "wb") as f:
            f.write(cover)
        rel = os.path.join("covers", fname).replace("\\", "/")
        return json_response(self, 200, {"ok": True, "path": rel})

def run():
    ensure_dirs()
    port = int(os.getenv("PORT", "8000"))  # Render dodá PORT
    httpd = HTTPServer(("0.0.0.0", port), Handler)
    print(f"✅ Server běží na http://0.0.0.0:{port}")
    print(f"📂 Uploads: {UPLOAD_ROOT}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
