#!/usr/bin/env python3
import os, re, io, json, base64, hashlib, hmac, time, datetime
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, quote
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import BytesParser
from email.policy import default as email_default
import smtplib

# ===== mini .env loader (bez externích balíků) =====
def load_env_dotfile(path=".env"):
    if not os.path.exists(path): return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("#"): continue
            if "=" not in line: continue
            k,v = line.split("=",1)
            k=k.strip(); v=v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_env_dotfile(os.path.join(BASE_DIR, ".env"))

# ====== config ======
PORT = int(os.getenv("PORT", "8080"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

# --- GCS ---
GCS_BUCKET = os.getenv("GCS_BUCKET")  # required
# toleruj překlepy v .env
ANIME_JSON_CLOUD = os.getenv("ANIME_JSON_CLOUD") or os.getenv("ANIME_JSONCLOUD") or "data/anime.json"
USERS_STORAGE_MODE = (os.getenv("USERS_STORAGE_MODE") or os.getenv("USER_STORAGE_MODE") or "dir").lower()
USERS_JSON_CLOUD = os.getenv("USERS_JSON_CLOUD") or os.getenv("USERS_DIR_CLOUD") or "private/users"
FEEDBACK_DIR_CLOUD = os.getenv("FEEDBACK_DIR_CLOUD") or "private/feedback"

# --- Admin bootstrap ---
ADMIN_BOOT_ENABLE   = os.getenv("ADMIN_BOOT_ENABLE", "false").lower() == "true"
ADMIN_EMAIL         = (os.getenv("ADMIN_EMAIL", "")).strip().lower()
ADMIN_BOOT_PASSWORD = os.getenv("ADMIN_BOOT_PASSWORD", "")

# --- SMTP ---
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER")
SMTP_PASS     = os.getenv("SMTP_PASS")
SMTP_FROM     = os.getenv("SMTP_FROM", SMTP_USER or "")
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "true").lower() == "true"
SMTP_DEBUG    = os.getenv("SMTP_DEBUG", "0") in ("1","true","True")
DEV_ECHO_VERIFICATION_LINK = os.getenv("DEV_ECHO_VERIFICATION_LINK","false").lower() == "true"
DEV_SAVE_LAST_EMAIL        = os.getenv("DEV_ECHO_LAST_EMAIL","false").lower() == "true" or os.getenv("DEV_SAVE_LAST_EMAIL","false").lower()=="true"

DEBUG_AUTH = os.getenv("DEBUG_AUTH","false").lower() == "true"

# ====== GCS client ======
GCS = None
Bucket = None
def init_gcs():
    global GCS, Bucket
    from google.cloud import storage  # needs google-cloud-storage
    GCS = storage.Client()
    Bucket = GCS.bucket(GCS_BUCKET)

def gcs_public_url(path_in_bucket: str) -> str:
    parts = [quote(p) for p in path_in_bucket.split("/")]
    return f"https://storage.googleapis.com/{GCS_BUCKET}/{'/'.join(parts)}"

def gcs_read_bytes(path:str) -> bytes|None:
    blob = Bucket.blob(path)
    if not blob.exists(): return None
    return blob.download_as_bytes()

def gcs_read_json(path:str, default=None):
    b = gcs_read_bytes(path)
    if not b: return default
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:
        return default

def gcs_write_json(path:str, obj):
    blob = Bucket.blob(path)
    payload = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    blob.upload_from_string(payload, content_type="application/json; charset=utf-8")

def gcs_write_bytes(path:str, raw:bytes, content_type:str|None=None, cache_control:str|None=None):
    blob = Bucket.blob(path)
    if cache_control:
        blob.cache_control = cache_control
    blob.upload_from_string(raw, content_type=content_type or "application/octet-stream")
    return gcs_public_url(path)

def gcs_list(prefix:str):
    return list(GCS.list_blobs(GCS_BUCKET, prefix=prefix))

# ====== users storage helpers ======
def user_path(email:str)->str:
    base = USERS_JSON_CLOUD.rstrip("/")
    return f"{base}/{email.lower()}.json"

def load_user(email:str):
    return gcs_read_json(user_path(email), default=None)

def save_user(u:dict):
    gcs_write_json(user_path(u["email"]), u)

def count_users():
    names = [b for b in gcs_list(USERS_JSON_CLOUD.rstrip("/") + "/") if b.name.endswith(".json")]
    total = len(names)
    verified = 0
    for b in names:
        data = gcs_read_json(b.name, {})
        if data.get("verified"): verified += 1
    return total, verified

# ====== uploads stats (anime/) ======
VIDEO_EXT = {".mp4",".m4v",".webm",".mkv",".mov"}
def is_video_name(name:str)->bool:
    n = name.lower()
    return any(n.endswith(ext) for ext in VIDEO_EXT)

def collect_uploads_tree():
    """
    Projde 'anime/' a vrátí:
    {
      slug: {
        "episodes": { "00001": { "480p":[...], "720p":[...], ... } },
        "counts": { "total":N, "by_quality":{"480p":n,...} }
      }, ...
    }
    Každý soubor: {"name": "...", "path": "...", "size": int, "updated": "..."}
    """
    tree = {}
    for blob in gcs_list("anime/"):
        parts = blob.name.split("/")
        # očekáváme anime/<slug>/<00001>/<quality>/<filename>
        if len(parts) < 5: 
            continue
        _, slug, ep, qual = parts[:4]
        filename = parts[-1]
        if not is_video_name(filename) and not filename.lower().endswith(".srt"):
            # bereme i .srt, ať je vidět v listu
            pass
        # create structure
        tree.setdefault(slug, {"episodes":{}, "counts":{"total":0,"by_quality":{}}})
        eps = tree[slug]["episodes"].setdefault(ep,{})
        arr = eps.setdefault(qual,[])
        arr.append({
            "name": filename,
            "path": blob.name,
            "size": blob.size,
            "updated": blob.updated.isoformat() if getattr(blob, "updated", None) else None,
            "url": gcs_public_url(blob.name)
        })
        # počítat jen video do totals
        if is_video_name(filename):
            tree[slug]["counts"]["total"] += 1
            tree[slug]["counts"]["by_quality"][qual] = tree[slug]["counts"]["by_quality"].get(qual,0)+1
    return tree

def uploads_stats():
    tree = collect_uploads_tree()
    uploads_total = sum(v["counts"]["total"] for v in tree.values())
    # nejaktivnější anime podle počtu unikátních epizod (podle složky ep)
    def uniq_eps(slug_data):
        return len(slug_data["episodes"])
    top_slug = None
    top_eps = 0
    for slug, data in tree.items():
        ue = uniq_eps(data)
        if ue > top_eps:
            top_eps = ue; top_slug = slug
    return uploads_total, {"slug": top_slug, "episodes": top_eps}

# ====== password hashing ======
def hash_password(password:str, salt:bytes=None, iterations:int=200_000)->str:
    if salt is None: salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2-sha256:{iterations}:{base64.urlsafe_b64encode(salt).decode()}:{dk.hex()}"

def verify_password(password:str, stored:str)->bool:
    try:
        algo, iters, salt_b64, hexhash = stored.split(":",3)
        if algo != "pbkdf2-sha256": return False
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        iters = int(iters)
        calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters).hex()
        return hmac.compare_digest(calc, hexhash)
    except Exception:
        return False

# ====== tokeny & time ======
def gen_token(nbytes=24)->str:
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("=")

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

# ====== mail ======
def send_verification_email(to_email:str, verify_url:str):
    if DEV_ECHO_VERIFICATION_LINK:
        print("[DEV] Verification link:", verify_url)

    msg = MIMEMultipart("alternative")
    msg["From"] = SMTP_FROM or SMTP_USER or "no-reply@example.com"
    msg["To"] = to_email
    msg["Subject"] = "Ověření účtu • AnimeCloud"

    text = f"Ověř svůj účet: {verify_url}\n"
    html = f"""
        <div style="font-family:sans-serif;line-height:1.5">
          <h2>Vítej v AnimeCloud 👋</h2>
          <p>Potvrď prosím svůj e-mail kliknutím na tlačítko:</p>
          <p><a href="{verify_url}" style="background:#7c5cff;color:#fff;padding:10px 14px;border-radius:8px;text-decoration:none">Ověřit účet</a></p>
          <p>Pokud tlačítko nefunguje, použij tento odkaz: <a href="{verify_url}">{verify_url}</a></p>
        </div>
    """
    msg.attach(MIMEText(text, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    if DEV_SAVE_LAST_EMAIL:
        with open(os.path.join(BASE_DIR, "last_email.eml"), "wb") as f:
            f.write(msg.as_bytes())

    if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
        print("[WARN] SMTP není kompletně nastaven – e-mail se neodeslal.")
        return

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
        if SMTP_DEBUG: s.set_debuglevel(1)
        if SMTP_STARTTLS:
            s.starttls()
        s.ehlo()
        s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(msg["From"], [to_email], msg.as_string())

# ====== multipart parsování (bez cgi) ======
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

# ====== mime helpers ======
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

def safe_name(name: str) -> str:
    if isinstance(name, bytes):
        name = name.decode("utf-8", "ignore")
    keep = "._-()[]{}@+&= "
    name = "".join(ch for ch in name if ch.isalnum() or ch in keep)
    name = name.replace("/", "").replace("\\", "")
    return name.strip() or "file"

# ====== HTTP handler ======
class Handler(SimpleHTTPRequestHandler):
    def _set_cors(self):
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGINS)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def end_headers(self):
        self._set_cors()
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    # --- helpers ---
    def _read_body(self):
        ctype = self.headers.get('Content-Type','')
        raw = self.rfile.read(int(self.headers.get('Content-Length','0') or 0))
        if 'application/json' in ctype:
            try: return json.loads(raw.decode('utf-8'))
            except Exception: return {}
        if 'application/x-www-form-urlencoded' in ctype:
            qs = parse_qs(raw.decode('utf-8'), keep_blank_values=True)
            return {k:(v[0] if isinstance(v,list) else v) for k,v in qs.items()}
        return {}

    def _json(self, code:int, obj:dict):
        payload = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _html(self, code:int, html:str):
        data = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # --- routing ---
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/auth/verify":
            return self.handle_verify(parsed)
        if parsed.path == "/stats":
            total, verified = count_users()
            up_total, top = uploads_stats()
            return self._json(200, {
                "users_total": total, 
                "users_verified": verified,
                "uploads_total": up_total,
                "top_anime": top
            })
        if parsed.path == "/feedback/list":
            return self.handle_feedback_list()
        if parsed.path == "/admin/uploads/tree":
            return self.handle_admin_uploads_tree()
        # default: statika
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/auth/register":
            return self.handle_register()
        if parsed.path == "/auth/login":
            return self.handle_login()
        if parsed.path == "/auth/resend":
            return self.handle_resend()
        if parsed.path == "/upload":
            return self.handle_upload()
        if parsed.path == "/feedback":
            return self.handle_feedback_save()
        if parsed.path == "/admin/add_anime":
            return self.handle_add_anime()
        if parsed.path == "/admin/upload_cover":
            return self.handle_upload_cover()
        self.send_error(404, "Not found")

    # --- AUTH ---
    def handle_register(self):
        data = self._read_body()
        email = (data.get("email") or "").strip().lower()
        p1 = (data.get("password") or data.get("pass") or "").strip()
        p2 = (data.get("password2") or data.get("confirm") or data.get("pass2") or "").strip()
        # name je nepovinné – pokud není, vezmeme část před @
        name = (data.get("name") or "").strip()
        if not name and email:
            name = email.split("@")[0]

        if not email or not p1 or not p2:
            return self._json(400, {"error":"missing_fields"})
        if p1 != p2:
            if DEBUG_AUTH: print(f"[DEBUG] password mismatch for {email}")
            return self._json(400, {"error":"password_mismatch"})
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return self._json(400, {"error":"invalid_email"})
        if load_user(email):
            return self._json(409, {"error":"email_exists"})

        u = {
            "email": email,
            "name": name,
            "password_hash": hash_password(p1),
            "verified": False,
            "role": "user",
            "created_at": now_iso(),
            "verify_token": gen_token(),
            "verify_expires": int(time.time()) + 60*60*48
        }
        save_user(u)

        host = self.headers.get("Host") or f"127.0.0.1:{PORT}"
        verify_url = f"http://{host}/auth/verify?email={email}&token={u['verify_token']}"
        try:
            send_verification_email(email, verify_url)
        except Exception as e:
            print("[MAIL] send error:", e)

        return self._json(200, {"ok":True})

    def handle_resend(self):
        data = self._read_body()
        email = (data.get("email") or "").strip().lower()
        u = load_user(email)
        if not u:
            return self._json(404, {"error":"not_found"})
        if u.get("verified"):
            return self._json(400, {"error":"already_verified"})
        u["verify_token"] = gen_token()
        u["verify_expires"] = int(time.time()) + 60*60*48
        save_user(u)
        host = self.headers.get("Host") or f"127.0.0.1:{PORT}"
        verify_url = f"http://{host}/auth/verify?email={email}&token={u['verify_token']}"
        try:
            send_verification_email(email, verify_url)
        except Exception as e:
            print("[MAIL] send error:", e)
        return self._json(200, {"ok":True})

    def handle_verify(self, parsed):
        qs = parse_qs(parsed.query)
        email = (qs.get("email",[""])[0]).strip().lower()
        token = (qs.get("token",[""])[0]).strip()

        u = load_user(email)
        if not u or not token or token != u.get("verify_token"):
            return self._html(400, self.render_verify_page(ok=False, msg="Ověření selhalo<br/>Neplatný odkaz nebo e-mail."))

        exp = int(u.get("verify_expires", 0))
        if exp and time.time() > exp:
            return self._html(400, self.render_verify_page(ok=False, msg="Odkaz vypršel. Požádej o nový v aplikaci."))

        u["verified"] = True
        u["verify_token"] = None
        u["verify_expires"] = None
        save_user(u)

        return self._html(200, self.render_verify_page(ok=True, msg="Účet ověřen ✅<br/>Nyní se můžeš přihlásit.", redirect="/login.html", delay_ms=1500))

    def render_verify_page(self, ok:bool, msg:str, redirect:str=None, delay_ms:int=0)->str:
        meta = f'<meta http-equiv="refresh" content="{delay_ms/1000};url={redirect}">' if redirect else ""
        js = f'<script>setTimeout(function(){{location.href="{redirect}";}}, {delay_ms});</script>' if redirect else ""
        color = "#9ef39b" if ok else "#ffb3b3"
        return f"""<!doctype html><html lang="cs"><head>
<meta charset="utf-8"><title>Ověření účtu</title>{meta}
<style>body{{background:#0e0e12;color:#fff;font-family:system-ui;}}
.card{{max-width:720px;margin:60px auto;background:#181820;border:1px solid #2a2a36;border-radius:14px;padding:24px}}
h1{{margin:0 0 10px}} .msg{{color:{color};line-height:1.6}}
small{{opacity:.8}} a{{color:#7c5cff}}</style></head>
<body><div class="card">
<h1>Ověření účtu</h1>
<p class="msg">{msg}</p>
{"<small>Za chvíli budeš přesměrován na přihlášení…</small>" if redirect else ""}
</div>{js}</body></html>"""

    def handle_login(self):
        data = self._read_body()
        email = (data.get("email") or "").strip().lower()
        password = (data.get("password") or "").strip()
        if not email or not password:
            return self._json(400, {"error":"missing_fields"})

        u = load_user(email)
        if not u or not verify_password(password, u.get("password_hash","")):
            return self._json(403, {"error":"invalid_credentials"})
        if not u.get("verified"):
            return self._json(403, {"error":"not_verified"})

        return self._json(200, {"ok":True, "user":{"email":u["email"], "name":u.get("name"), "role":u.get("role","user"), "profile":u.get("profile")}})

    # --- UPLOAD multipart ---
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
            return self._json(400, {"ok": False, "error": "missing_fields"})

        ep_folder = f"{int(episode):05d}"
        vname = safe_name(vname)
        sname = safe_name(sname or "subs.srt")

        v_mime = guess_mime(vname, sniff=video[:8] if isinstance(video,(bytes,bytearray)) else None, default="video/mp4")
        s_mime = guess_mime(sname, sniff=subs[:8] if isinstance(subs,(bytes,bytearray)) else None, default="application/x-subrip")

        video_path = f"anime/{anime}/{ep_folder}/{quality}/{vname}"
        subs_path  = f"anime/{anime}/{ep_folder}/{quality}/{sname}"

        video_url = gcs_write_bytes(video_path, video, content_type=v_mime, cache_control="public, max-age=31536000, immutable")
        subs_url = None
        if subs:
            subs_url = gcs_write_bytes(subs_path, subs, content_type=s_mime, cache_control="public, max-age=31536000, immutable")

        return self._json(200, {"ok": True, "video": video_url, "subs": subs_url})

    # --- FEEDBACK ---
    def handle_feedback_save(self):
        data = self._read_body()
        if not data or not data.get("id"):
            return self._json(400, {"ok":False, "error":"invalid"})
        path = f"{FEEDBACK_DIR_CLOUD.rstrip('/')}/{safe_name(data['id'])}.json"
        gcs_write_json(path, data)
        return self._json(200, {"ok":True})

    def handle_feedback_list(self):
        items = []
        prefix = FEEDBACK_DIR_CLOUD.rstrip("/") + "/"
        for b in gcs_list(prefix):
            if not b.name.endswith(".json"): continue
            try:
                obj = gcs_read_json(b.name, None)
                if obj: items.append(obj)
            except Exception:
                pass
        # seřaď podle ts desc (pokud je)
        items.sort(key=lambda x: x.get("ts",0), reverse=True)
        return self._json(200, {"ok":True, "items": items})

    # --- ADMIN: add anime + cover ---
    def handle_add_anime(self):
        data = self._read_body()
        required = ["slug","title","episodes","genres","description","cover","status","year","studio"]
        if not all(k in data for k in required):
            return self._json(400, {"ok":False, "error":"missing_fields"})

        slug = safe_name(str(data["slug"]).lower())
        cover_in = data.get("cover")

        # cover může být data URL
        try:
            cover_url = None
            if isinstance(cover_in, str) and cover_in.startswith("data:"):
                # data URL
                m = re.match(r"^data:(?P<mime>[\w/+.-]+);base64,(?P<b64>.*)$", cover_in, re.DOTALL)
                if not m: raise ValueError("invalid data URL")
                mime = m.group("mime").lower()
                raw = base64.b64decode(m.group("b64"), validate=True)
                ext = {"image/jpeg":"jpg","image/jpg":"jpg","image/png":"png","image/webp":"webp","image/gif":"gif"}.get(mime,"jpg")
                cover_path = f"covers/{slug}.{ext}"
                cover_url = gcs_write_bytes(cover_path, raw, content_type=mime, cache_control="public, max-age=31536000, immutable")
            elif isinstance(cover_in, str):
                cover_url = cover_in
        except Exception as e:
            return self._json(400, {"ok":False, "error": f"cover: {e}"})

        try:
            item = {
                "slug": slug,
                "title": str(data["title"]),
                "episodes": int(data["episodes"]),
                "genres": list(data["genres"]),
                "description": str(data["description"]),
                "cover": cover_url or str(cover_in or ""),
                "status": str(data["status"]),
                "year": int(data["year"]),
                "studio": str(data["studio"]),
            }
        except Exception as e:
            return self._json(400, {"ok":False, "error": f"fields: {e}"})

        # 1) načti stávající list
        items = gcs_read_json(ANIME_JSON_CLOUD, []) or []
        # 2) přepiš podle slug
        items = [a for a in items if a.get("slug") != slug]
        items.append(item)
        # 3) zapiš
        gcs_write_json(ANIME_JSON_CLOUD, items)

        return self._json(200, {"ok": True, "saved": item, "anime_json_url": gcs_public_url(ANIME_JSON_CLOUD)})

    def handle_upload_cover(self):
        fields = parse_multipart_request(self)
        slug = fields.get("slug"); cover = fields.get("cover")
        if not slug or not cover:
            return self._json(400, {"ok": False, "error": "Missing slug or cover"})
        sniff = bytes(cover[:12]) if isinstance(cover,(bytes,bytearray)) else None
        mime = guess_mime("cover.bin", sniff=sniff, default="image/jpeg")
        ext = {"image/png":"png","image/webp":"webp","image/gif":"gif","image/jpeg":"jpg"}.get(mime,"jpg")
        url = gcs_write_bytes(f"covers/{safe_name(slug)}.{ext}", cover, content_type=mime, cache_control="public, max-age=31536000, immutable")
        return self._json(200, {"ok": True, "path": url})

    # --- ADMIN: uploads tree ---
    def handle_admin_uploads_tree(self):
        tree = collect_uploads_tree()
        return self._json(200, {"ok":True, "tree": tree})

# ===== bootstrap admin user (jednorázově) =====
def bootstrap_admin_if_needed():
    if not ADMIN_BOOT_ENABLE or not ADMIN_EMAIL or not ADMIN_BOOT_PASSWORD:
        return
    u = load_user(ADMIN_EMAIL)
    if u:
        print("[BOOT] Admin už existuje – nic nedělám.")
        return
    u = {
        "email": ADMIN_EMAIL,
        "name": "Administrator",
        "password_hash": hash_password(ADMIN_BOOT_PASSWORD),
        "verified": True,
        "role": "admin",
        "created_at": now_iso(),
        "verify_token": None,
        "verify_expires": None
    }
    save_user(u)
    print(f"[BOOT] Vytvořen admin účet: {ADMIN_EMAIL}. Nezapomeň ADMIN_BOOT_ENABLE=false v .env.")

def main():
    if not GCS_BUCKET:
        raise RuntimeError("Chybí GCS_BUCKET v .env")

    init_gcs()
    if ADMIN_BOOT_ENABLE:
        bootstrap_admin_if_needed()

    os.chdir(BASE_DIR)  # servíruj statické soubory
    httpd = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"✅ AnimeCloud server běží na http://0.0.0.0:{PORT}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()
