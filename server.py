#!/usr/bin/env python3
import os, re, io, json, base64, hashlib, hmac, time, datetime, mimetypes
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, quote
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import BytesParser
from email.policy import default as email_default
import smtplib

# ========= .env loader =========
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

# ========= config =========
PORT = int(os.getenv("PORT", "8080"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

# GCS (čti i staré/špatně nazvané proměnné kvůli kompatibilitě)
GCS_BUCKET = os.getenv("GCS_BUCKET")
ANIME_JSON_CLOUD = os.getenv("ANIME_JSON_CLOUD") or os.getenv("ANIME_JSONCLOUD") or "data/anime.json"
USERS_STORAGE_MODE = os.getenv("USERS_STORAGE_MODE") or os.getenv("USER_STORAGE_MODE") or "dir"
USERS_JSON_CLOUD = os.getenv("USERS_JSON_CLOUD") or os.getenv("USERS_DIR_CLOUD") or "private/users"

# Admin bootstrap
ADMIN_BOOT_ENABLE   = os.getenv("ADMIN_BOOT_ENABLE", "false").lower() == "true"
ADMIN_EMAIL         = (os.getenv("ADMIN_EMAIL", "")).strip().lower()
ADMIN_BOOT_PASSWORD = os.getenv("ADMIN_BOOT_PASSWORD", "")

# SMTP
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER")
SMTP_PASS     = os.getenv("SMTP_PASS")
SMTP_FROM     = os.getenv("SMTP_FROM", SMTP_USER or "")
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "true").lower() == "true"
SMTP_DEBUG    = os.getenv("SMTP_DEBUG", "0") in ("1","true","True")
DEV_ECHO_VERIFICATION_LINK = os.getenv("DEV_ECHO_VERIFICATION_LINK","false").lower() == "true"
DEV_SAVE_LAST_EMAIL        = os.getenv("DEV_SAVE_LAST_EMAIL","false").lower() == "true" or os.getenv("DEV_ECHO_LAST_EMAIL","false").lower()=="true"

DEBUG_AUTH = os.getenv("DEBUG_AUTH","false").lower() == "true"

# ========= GCS client =========
GCS = None
Bucket = None

def init_gcs():
    global GCS, Bucket
    from google.cloud import storage
    GCS = storage.Client()
    Bucket = GCS.bucket(GCS_BUCKET)

def gcs_public_url(path_in_bucket: str) -> str:
    parts = [quote(p) for p in path_in_bucket.split("/")]
    return f"https://storage.googleapis.com/{GCS_BUCKET}/{'/'.join(parts)}"

def gcs_read_json(path:str, default=None):
    blob = Bucket.blob(path)
    if not blob.exists(): return default
    data = blob.download_as_bytes()
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return default

def gcs_write_json(path:str, obj):
    blob = Bucket.blob(path)
    payload = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    # JSON – necháme krátký cache-control (default)
    blob.upload_from_string(payload, content_type="application/json; charset=utf-8")

def gcs_upload_bytes(path:str, raw:bytes, content_type:str=None, cache_immutable:bool=True) -> str:
    blob = Bucket.blob(path)
    if cache_immutable:
        blob.cache_control = "public, max-age=31536000, immutable"
    blob.upload_from_string(raw, content_type=content_type or "application/octet-stream")
    return gcs_public_url(path)

def gcs_download_bytes(path:str) -> bytes|None:
    blob = Bucket.blob(path)
    if not blob.exists():
        return None
    return blob.download_as_bytes()

def gcs_list(prefix:str):
    return [b.name for b in GCS.list_blobs(GCS_BUCKET, prefix=prefix)]

# ========= users storage =========
def user_path(email:str)->str:
    base = USERS_JSON_CLOUD.rstrip("/")
    return f"{base}/{email.lower()}.json"

def load_user(email:str):
    return gcs_read_json(user_path(email), default=None)

def save_user(u:dict):
    gcs_write_json(user_path(u["email"]), u)

def count_users():
    names = [n for n in gcs_list(USERS_JSON_CLOUD.rstrip("/") + "/") if n.endswith(".json")]
    total = len(names)
    verified = 0
    for n in names:
        data = gcs_read_json(n, {})
        if data.get("verified"): verified += 1
    return total, verified

# ========= password hashing =========
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

# ========= tokens & time =========
def gen_token(nbytes=24)->str:
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("=")

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

# ========= mail =========
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

# ========= multipart parser =========
def parse_multipart(handler):
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length)
    ctype = handler.headers.get("Content-Type", "")
    headers_bytes = f"Content-Type: {ctype}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
    msg = BytesParser(policy=email_default).parsebytes(headers_bytes + raw)
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
                fields[name + "Name"] = filename
    return fields

# ========= mime helpers =========
VIDEO_EXTS = {".mp4",".m4v",".webm",".mkv",".mov"}
SUB_EXTS   = {".srt",".vtt"}
IMG_MAGIC  = (b"\x89PNG", b"\xff\xd8\xff", b"RIFF")

def guess_mime(filename:str, sniff:bytes|None=None, default="application/octet-stream"):
    fn = (filename or "").lower()
    mt = mimetypes.guess_type(fn)[0]
    if mt: return mt
    if sniff:
        if sniff.startswith(b"\x89PNG"): return "image/png"
        if sniff[:3] == b"\xff\xd8\xff": return "image/jpeg"
        if sniff.startswith(b"RIFF") and b"WEBP" in sniff[:16]: return "image/webp"
        if sniff[:4] == b"\x1a\x45\xdf\xa3": return "video/x-matroska"
        if sniff[:4] == b"ftyp": return "video/mp4"
    return default

# ========= uploads scan =========
RE_UPLOAD_PATH = re.compile(r"^anime/([^/]+)/(\d{5})/([^/]+)/([^/]+)$", re.I)

def list_video_files_under_anime():
    names = gcs_list("anime/")
    # filtruj jen soubory s „video“ příponou
    out = []
    for n in names:
        if RE_UPLOAD_PATH.match(n):
            fn = n.rsplit("/",1)[-1].lower()
            ext = "."+fn.split(".")[-1] if "." in fn else ""
            if ext in VIDEO_EXTS:
                out.append(n)
    return out

def build_episodes_map():
    """Vrátí { slug: počet_unikátních_epizod } z GCS stromu anime/slug/00001/quality/filename"""
    names = list_video_files_under_anime()
    seen = {}
    for n in names:
        m = RE_UPLOAD_PATH.match(n)
        if not m: continue
        slug, ep5 = m.group(1), m.group(2)
        key = (slug, ep5)
        seen[key] = 1
    per_slug = {}
    for (slug, _ep) in seen.keys():
        per_slug[slug] = per_slug.get(slug, 0) + 1
    return per_slug, len(names)

# ========= HTTP handler =========
class Handler(SimpleHTTPRequestHandler):
    def _set_cors(self):
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGINS)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def end_headers(self):
        self._set_cors()
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204); self.end_headers()

    # helpers
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

    # routes
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/auth/verify":      return self.handle_verify(parsed)
        if parsed.path == "/stats":            return self.handle_stats()
        if parsed.path == "/uploads/episodes_map": return self.handle_episodes_map()
        if parsed.path == "/feedback/all":     return self.handle_feedback_list_all()
        if parsed.path == "/feedback/user":    return self.handle_feedback_list_user(parsed)
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/auth/register": return self.handle_register()
        if parsed.path == "/auth/login":    return self.handle_login()
        if parsed.path == "/auth/resend":   return self.handle_resend()
        if parsed.path == "/upload":        return self.handle_upload()
        if parsed.path == "/feedback":      return self.handle_feedback_save()
        if parsed.path == "/feedback/reply":return self.handle_feedback_reply()
        if parsed.path == "/admin/add_anime": return self.handle_add_anime()
        self.send_error(404, "Not found")

    # ===== AUTH =====
    def handle_register(self):
        data = self._read_body()
        email = (data.get("email") or "").strip().lower()
        name  = (data.get("name")  or email.split("@")[0]).strip()
        p1 = (data.get("password") or data.get("pass") or "").strip()
        p2 = (data.get("password2") or data.get("password_confirm") or data.get("confirm") or data.get("pass2") or "").strip()

        if not email or not p1 or not p2:
            return self._json(400, {"ok":False,"error":"missing_fields"})
        if p1 != p2:
            if DEBUG_AUTH: print(f"[DEBUG] password mismatch for {email}")
            return self._json(400, {"ok":False,"error":"password_mismatch"})
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return self._json(400, {"ok":False,"error":"invalid_email"})
        if load_user(email):
            return self._json(409, {"ok":False,"error":"email_exists"})

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
            return self._json(404, {"ok":False,"error":"not_found"})
        if u.get("verified"):
            return self._json(400, {"ok":False,"error":"already_verified"})
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
        exp = int(u.get("verify_expires", 0) or 0)
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
            return self._json(400, {"ok": False, "error": "missing_fields"})

        u = load_user(email)
        if not u or not verify_password(password, u.get("password_hash","")):
            return self._json(403, {"ok": False, "error": "invalid_credentials"})
        if not u.get("verified"):
            return self._json(403, {"ok": False, "error": "not_verified"})

        token = gen_token()
        user_payload = {
            "email": u["email"],
            "name": u.get("name"),
            "role": u.get("role", "user"),
            "profile": u.get("profile", {})
        }
        if DEBUG_AUTH:
            print("[AUTH] login ok →", user_payload)
        return self._json(200, {"ok": True, "user": user_payload, "token": token})

    # ===== UPLOAD =====
    def handle_upload(self):
        if not GCS_BUCKET:
            return self._json(500, {"ok":False,"error":"GCS not configured"})
        fields = parse_multipart(self)
        slug    = (fields.get("anime") or "").strip().lower()
        episode = (fields.get("episode") or "").strip()
        quality = (fields.get("quality") or "").strip()
        video   = fields.get("video")
        vname   = fields.get("videoName") or "video.mp4"
        subs    = fields.get("subs")
        sname   = fields.get("subsName") or "subs.srt"

        if not slug or not episode or not quality or not video:
            return self._json(400, {"ok":False, "error":"Missing required fields"})

        try:
            ep_folder = f"{int(episode):05d}"
        except Exception:
            return self._json(400, {"ok":False, "error":"Bad episode number"})

        # video
        v_mime = guess_mime(vname, sniff=video[:12] if isinstance(video,(bytes,bytearray)) else None, default="video/mp4")
        v_path = f"anime/{slug}/{ep_folder}/{quality}/{vname}"
        v_url  = gcs_upload_bytes(v_path, video, content_type=v_mime, cache_immutable=True)

        # titulky (nepovinné)
        s_url = None
        if subs:
            s_mime = guess_mime(sname, sniff=subs[:12] if isinstance(subs,(bytes,bytearray)) else None, default="application/x-subrip")
            s_path = f"anime/{slug}/{ep_folder}/{quality}/{sname}"
            s_url  = gcs_upload_bytes(s_path, subs, content_type=s_mime, cache_immutable=True)

        return self._json(200, {"ok":True, "video": v_url, "subs": s_url})

    # ===== FEEDBACK (GCS: feedback/{ID}.json) =====
    def handle_feedback_save(self):
        data = self._read_body()
        # očekáváme { id, user|name, category, priority, message, status?, ts? }
        if not data.get("id") or not data.get("message"):
            return self._json(400, {"ok":False, "error":"missing_fields"})
        tid = str(data["id"])
        now_ts = int(time.time()*1000)
        ticket = {
            "id": tid,
            "user": (data.get("user") or None),
            "name": (data.get("name") or None),
            "category": data.get("category") or "other",
            "priority": data.get("priority") or "normal",
            "status": data.get("status") or "open",
            "ts": int(data.get("ts") or now_ts),
            "messages": [
                {
                    "id": f"{tid}_0",
                    "role": "user",
                    "author": data.get("user") or data.get("name") or "anonym",
                    "text": data.get("message") or "",
                    "ts": int(data.get("ts") or now_ts)
                }
            ]
        }
        gcs_write_json(f"feedback/{tid}.json", ticket)
        return self._json(200, {"ok":True})

    def handle_feedback_list_all(self):
        names = [n for n in gcs_list("feedback/") if n.endswith(".json")]
        items = []
        for n in names:
            t = gcs_read_json(n, None)
            if t: items.append(t)
        items.sort(key=lambda x: x.get("ts",0), reverse=True)
        return self._json(200, {"ok":True, "items": items})

    def handle_feedback_list_user(self, parsed):
        qs = parse_qs(parsed.query)
        email = (qs.get("email",[""])[0]).strip().lower()
        names = [n for n in gcs_list("feedback/") if n.endswith(".json")]
        items = []
        for n in names:
            t = gcs_read_json(n, None)
            if t and (t.get("user","") or "").lower() == email:
                items.append(t)
        items.sort(key=lambda x: x.get("ts",0), reverse=True)
        return self._json(200, {"ok":True, "items": items})

    def handle_feedback_reply(self):
        data = self._read_body()
        tid = (data.get("id") or "").strip()
        if not tid: return self._json(400, {"ok":False,"error":"missing_id"})
        t = gcs_read_json(f"feedback/{tid}.json", None)
        if not t: return self._json(404, {"ok":False,"error":"not_found"})
        # nepřidávej zprávy do uzavřených
        if t.get("status") in ("resolved","approved","rejected"):
            return self._json(400, {"ok":False,"error":"closed"})
        msg = (data.get("message") or "").strip()
        role = (data.get("role") or "admin")
        author = (data.get("author") or "admin")
        if msg:
            t.setdefault("messages", [])
            t["messages"].append({
                "id": f"{tid}_{len(t['messages'])+1}",
                "role": role,
                "author": author,
                "text": msg,
                "ts": int(time.time()*1000)
            })
        new_status = data.get("status")
        if new_status:
            t["status"] = new_status
        gcs_write_json(f"feedback/{tid}.json", t)
        return self._json(200, {"ok":True})

    # ===== Admin: add/update anime.json =====
    def handle_add_anime(self):
        data = self._read_body()
        required = ["slug","title","episodes","genres","description","cover","status","year","studio"]
        if not all(k in data for k in required):
            return self._json(400, {"ok":False,"error":"Missing required fields"})
        item = {
            "slug": str(data["slug"]).lower(),
            "title": str(data["title"]),
            "episodes": int(data["episodes"]),
            "genres": list(data["genres"]),
            "description": str(data["description"]),
            "cover": str(data["cover"]),
            "status": str(data["status"]),
            "year": int(data["year"]),
            "studio": str(data["studio"]),
        }
        # read current, replace by slug, write back
        cur = gcs_read_json(ANIME_JSON_CLOUD, []) or []
        cur = [a for a in cur if (a.get("slug") or "").lower() != item["slug"]]
        cur.append(item)
        gcs_write_json(ANIME_JSON_CLOUD, cur)
        return self._json(200, {"ok":True, "saved": item, "anime_json": gcs_public_url(ANIME_JSON_CLOUD)})

    # ===== Stats & episodes map =====
    def handle_episodes_map(self):
        per_slug, _total_files = build_episodes_map()
        return self._json(200, {"ok":True, "per_slug": per_slug})

    def handle_stats(self):
        users_total, users_verified = count_users()
        per_slug, total_video_files = build_episodes_map()
        # top anime podle počtu unikátních epizod
        top_slug = None; top_count = 0
        for s,c in per_slug.items():
            if c > top_count:
                top_count = c; top_slug = s
        return self._json(200, {
            "ok": True,
            "users_total": users_total,
            "users_verified": users_verified,
            "uploads_total_files": total_video_files,
            "top_anime_slug": top_slug,
            "top_anime_unique_eps": top_count
        })

# ===== bootstrap admin user =====
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
    os.chdir(BASE_DIR)
    httpd = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"AnimeCloud server běží na portu {PORT}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()
