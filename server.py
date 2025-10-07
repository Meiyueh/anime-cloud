#!/usr/bin/env python3
import os, re, io, json, base64, hashlib, hmac, time, datetime, smtplib, traceback, cgi
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, quote
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ===== mini .env loader =====
def load_env_dotfile(path=".env"):
    if not os.path.exists(path): return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k, v = line.split("=", 1)
            k = k.strip(); v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_env_dotfile(os.path.join(BASE_DIR, ".env"))

# ===== Config =====
PORT = int(os.getenv("PORT", "8080"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

GCS_BUCKET = os.getenv("GCS_BUCKET", "").strip()
if not GCS_BUCKET:
    raise RuntimeError("Chybí GCS_BUCKET v .env")

# Cesty v bucketu
ANIME_JSON_CLOUD = (
    os.getenv("ANIME_JSON_CLOUD")
    or os.getenv("ANIME_JSONCLOUD")
    or "data/anime.json"
)
USERS_STORAGE_MODE = (os.getenv("USERS_STORAGE_MODE") or os.getenv("USER_STORAGE_MODE") or "dir").lower()
USERS_JSON_CLOUD = os.getenv("USERS_JSON_CLOUD") or os.getenv("USERS_DIR_CLOUD") or "private/users"
FEEDBACK_PREFIX = "feedback"  # složka pro tikety: feedback/{ID}.json

# Admin bootstrap (volitelně)
ADMIN_BOOT_ENABLE   = os.getenv("ADMIN_BOOT_ENABLE", "false").lower() == "true"
ADMIN_EMAIL         = (os.getenv("ADMIN_EMAIL", "")).strip().lower()
ADMIN_BOOT_PASSWORD = os.getenv("ADMIN_BOOT_PASSWORD", "")

# SMTP (pro ověření účtu)
SMTP_HOST     = os.getenv("SMTP_HOST", "")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASS     = os.getenv("SMTP_PASS", "")
SMTP_FROM     = os.getenv("SMTP_FROM", SMTP_USER)
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "true").lower() == "true"
SMTP_DEBUG    = os.getenv("SMTP_DEBUG", "0") in ("1","true","True")
DEV_ECHO_VERIFICATION_LINK = os.getenv("DEV_ECHO_VERIFICATION_LINK","false").lower() == "true"
DEV_SAVE_LAST_EMAIL        = os.getenv("DEV_SAVE_LAST_EMAIL","false").lower() == "true"

DEBUG_AUTH = os.getenv("DEBUG_AUTH","false").lower() == "true"

# ===== GCS =====
from google.cloud import storage
GCS = storage.Client()
Bucket = GCS.bucket(GCS_BUCKET)

def gcs_public_url(path_in_bucket: str) -> str:
    parts = [quote(p) for p in path_in_bucket.split("/")]
    return f"https://storage.googleapis.com/{GCS_BUCKET}/{'/'.join(parts)}"

def gcs_read_json(path: str, default=None):
    blob = Bucket.blob(path)
    if not blob.exists(): return default
    data = blob.download_as_bytes()
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return default

def gcs_write_json(path: str, obj):
    blob = Bucket.blob(path)
    raw = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    blob.upload_from_string(raw, content_type="application/json; charset=utf-8")

def gcs_upload_bytes(path: str, raw: bytes, mime: str, cache_immutable: bool=False):
    blob = Bucket.blob(path)
    if cache_immutable:
        blob.cache_control = "public, max-age=31536000, immutable"
    blob.upload_from_string(raw, content_type=mime or "application/octet-stream")
    return gcs_public_url(path)

def gcs_delete(path: str) -> bool:
    blob = Bucket.blob(path)
    if not blob.exists(): return False
    blob.delete()
    return True

def gcs_list(prefix: str):
    return list(GCS.list_blobs(GCS_BUCKET, prefix=prefix))

# ===== Helpers =====
def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

def gen_token(nbytes=24)->str:
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("=")

def safe_name(name: str) -> str:
    if isinstance(name, bytes): name = name.decode("utf-8", "ignore")
    keep = "._-()[]{}@+&= "
    name = "".join(ch for ch in name if ch.isalnum() or ch in keep)
    return name.replace("/", "").replace("\\", "").strip() or "file"

VIDEO_EXTS = (".mp4",".m4v",".webm",".mkv",".mov")
SUBS_EXTS  = (".srt",".vtt")

EXT_MIME = {
    ".mp4":"video/mp4",".m4v":"video/x-m4v",".webm":"video/webm",".mkv":"video/x-matroska",".mov":"video/quicktime",
    ".srt":"application/x-subrip",".vtt":"text/vtt",
    ".jpg":"image/jpeg",".jpeg":"image/jpeg",".png":"image/png",".webp":"image/webp",".gif":"image/gif",
}
def guess_mime(filename: str, sniff: bytes|None=None, default: str="application/octet-stream")->str:
    fn = (filename or "").lower()
    for ext, mime in EXT_MIME.items():
        if fn.endswith(ext): return mime
    if sniff:
        if sniff.startswith(b"\x89PNG"): return "image/png"
        if sniff[:3] == b"\xff\xd8\xff": return "image/jpeg"
        if sniff.startswith(b"RIFF") and b"WEBP" in sniff[:16]: return "image/webp"
        if sniff[:4] == b"\x1a\x45\xdf\xa3": return "video/x-matroska"
        if sniff[:4] == b"ftyp": return "video/mp4"
    return default

# password hashing
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

# users I/O
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
        try:
            data = json.loads(b.download_as_bytes().decode("utf-8"))
            if data.get("verified"): verified += 1
        except Exception:
            pass
    return total, verified

# ===== Streaming multipart (pro velké soubory) =====
def parse_multipart_stream(handler):
    env = {
        'REQUEST_METHOD': 'POST',
        'CONTENT_TYPE': handler.headers.get('Content-Type', ''),
        'CONTENT_LENGTH': handler.headers.get('Content-Length', '0'),
    }
    fs = cgi.FieldStorage(
        fp=handler.rfile,
        headers=handler.headers,
        environ=env,
        keep_blank_values=True
    )
    out = {}
    if fs and fs.list:
        for item in fs.list:
            key = item.name
            if not key: continue
            if item.filename:
                out[key] = {"filename": item.filename, "file": item.file}
            else:
                out[key] = item.value
    return out

# mail
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

    if not (SMTP_HOST and SMTP_USER and SMTP_PASS):
        print("[WARN] SMTP není kompletně nastaven – e-mail se neodeslal.")
        return

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
        if SMTP_DEBUG: s.set_debuglevel(1)
        if SMTP_STARTTLS: s.starttls()
        s.ehlo()
        s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(msg["From"], [to_email], msg.as_string())

# ===== HTTP handler =====
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

    # -- helpers
    def _read_body(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length","0") or 0))
        ctype = self.headers.get("Content-Type","")
        if "application/json" in ctype:
            try: return json.loads(raw.decode("utf-8"))
            except Exception: return {}
        if "application/x-www-form-urlencoded" in ctype:
            qs = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
            return {k:(v[0] if isinstance(v,list) else v) for k,v in qs.items()}
        return {}

    def _json(self, code:int, obj:dict):
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
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

    # -- routing
    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/auth/verify":    return self.handle_verify(parsed)
            if parsed.path == "/stats":          return self.handle_stats()
            if parsed.path == "/uploads/counts": return self.handle_upload_counts()
            if parsed.path == "/feedback/list":  return self.handle_feedback_list()
            return super().do_GET()
        except Exception as e:
            traceback.print_exc()
            return self._json(500, {"ok":False,"error":str(e)})

    def do_POST(self):
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/auth/register":      return self.handle_register()
            if parsed.path == "/auth/login":         return self.handle_login()
            if parsed.path == "/auth/resend":        return self.handle_resend()
            if parsed.path == "/auth/update_profile":return self.handle_update_profile()
            if parsed.path == "/upload":             return self.handle_upload()
            if parsed.path == "/feedback":           return self.handle_feedback_save()
            if parsed.path == "/feedback/update":    return self.handle_feedback_update()
            if parsed.path == "/admin/add_anime":    return self.handle_add_anime()
            if parsed.path == "/admin/upload_cover": return self.handle_upload_cover()
            if parsed.path == "/delete":             return self.handle_delete_file()
            if parsed.path == "/wipe_all":           return self.handle_wipe_all()
            return self._json(404, {"ok":False,"error":"Not found"})
        except Exception as e:
            traceback.print_exc()
            return self._json(500, {"ok":False,"error":str(e)})

    # ===== Auth =====
    def handle_register(self):
        d = self._read_body()
        email = (d.get("email") or "").strip().lower()
        name  = (d.get("name") or email.split("@")[0]).strip()
        p1 = (d.get("password") or d.get("pass") or "").strip()
        p2 = (d.get("password2") or d.get("password_confirm") or d.get("confirm") or d.get("pass2") or p1).strip()

        if not email or not p1 or not p2:
            return self._json(400, {"ok":False,"error":"missing_fields"})
        if p1 != p2:
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
        try: send_verification_email(email, verify_url)
        except Exception as e: print("[MAIL] send error:", e)

        return self._json(200, {"ok":True})

    def handle_resend(self):
        d = self._read_body()
        email = (d.get("email") or "").strip().lower()
        u = load_user(email)
        if not u: return self._json(404, {"ok":False,"error":"not_found"})
        if u.get("verified"): return self._json(400, {"ok":False,"error":"already_verified"})
        u["verify_token"] = gen_token()
        u["verify_expires"] = int(time.time()) + 60*60*48
        save_user(u)
        host = self.headers.get("Host") or f"127.0.0.1:{PORT}"
        verify_url = f"http://{host}/auth/verify?email={email}&token={u['verify_token']}"
        try: send_verification_email(email, verify_url)
        except Exception as e: print("[MAIL] send error:", e)
        return self._json(200, {"ok":True})

    def handle_verify(self, parsed):
        qs = parse_qs(parsed.query)
        email = (qs.get("email",[""])[0]).strip().lower()
        token = (qs.get("token",[""])[0]).strip()
        u = load_user(email)
        if not u or not token or token != u.get("verify_token"):
            return self._html(400, self._verify_page(False,"Ověření selhalo<br/>Neplatný odkaz nebo e-mail."))
        exp = int(u.get("verify_expires", 0))
        if exp and time.time() > exp:
            return self._html(400, self._verify_page(False,"Odkaz vypršel. Požádej o nový v aplikaci."))
        u["verified"] = True
        u["verify_token"] = None
        u["verify_expires"] = None
        save_user(u)
        return self._html(200, self._verify_page(True,"Účet ověřen ✅<br/>Nyní se můžeš přihlásit.", redirect="/login.html", delay_ms=1200))

    def _verify_page(self, ok:bool, msg:str, redirect:str=None, delay_ms:int=0)->str:
        meta = f'<meta http-equiv="refresh" content="{delay_ms/1000};url={redirect}">' if redirect else ""
        js = f'<script>setTimeout(function(){{location.href="{redirect}";}}, {delay_ms});</script>' if redirect else ""
        color = "#9ef39b" if ok else "#ffb3b3"
        return f"""<!doctype html><html lang="cs"><head><meta charset="utf-8">{meta}
<title>Ověření účtu</title>
<style>body{{background:#0e0e12;color:#fff;font-family:system-ui;}}
.card{{max-width:720px;margin:60px auto;background:#181820;border:1px solid #2a2a36;border-radius:14px;padding:24px}}
h1{{margin:0 0 10px}} .msg{{color:{color};line-height:1.6}} a{{color:#7c5cff}}</style></head>
<body><div class="card"><h1>Ověření účtu</h1><p class="msg">{msg}</p></div>{js}</body></html>"""

    def handle_login(self):
        d = self._read_body()
        email = (d.get("email") or "").strip().lower()
        password = (d.get("password") or "").strip()
        if not email or not password:
            return self._json(400, {"ok":False,"error":"missing_fields"})
        u = load_user(email)
        if not u or not verify_password(password, u.get("password_hash","")):
            return self._json(403, {"ok":False,"error":"invalid_credentials"})
        if not u.get("verified"):
            return self._json(403, {"ok":False,"error":"not_verified"})
        token = gen_token()
        payload = {"email":u["email"],"name":u.get("name"),"role":u.get("role","user"),"profile":u.get("profile",{})}
        if DEBUG_AUTH: print("[AUTH] login ok", payload)
        return self._json(200, {"ok":True, "user":payload, "token":token})

    def handle_update_profile(self):
        d = self._read_body()
        email = (d.get("email") or "").strip().lower()
        patch = d.get("profile") or d.get("profilePatch") or {}
        if not email or not isinstance(patch, dict):
            return self._json(400, {"ok":False, "error":"bad_request"})
        u = load_user(email)
        if not u:
            return self._json(404, {"ok":False, "error":"not_found"})
        allowed = {"nickname","secondaryTitle","avatar"}
        clean = {k:v for k,v in patch.items() if k in allowed}
        prof = u.get("profile") or {}
        prof.update(clean)
        u["profile"] = prof
        save_user(u)
        return self._json(200, {"ok":True, "profile": prof})

    # ===== Uploads =====
    def handle_upload(self):
        fields = parse_multipart_stream(self)

        anime   = (fields.get("anime") or "").strip().lower()
        episode = int(str(fields.get("episode") or "0").strip() or "0")
        quality = (fields.get("quality") or "").strip()

        v_field = fields.get("video")
        vname_client = (fields.get("videoName") or "")
        s_field = fields.get("subs")
        sname_client = (fields.get("subsName") or "")

        if not anime or not episode or not quality or not v_field:
            return self._json(400, {"ok":False,"error":"Missing fields"})

        ep_folder = f"{int(episode):05d}"

        if isinstance(v_field, dict):
            vname = safe_name(vname_client or v_field.get("filename") or "video.mp4")
            v_mime = guess_mime(vname)
        else:
            return self._json(400, {"ok":False,"error":"Bad video field"})

        if isinstance(s_field, dict):
            sname = safe_name(sname_client or s_field.get("filename") or "subs.srt")
            s_mime = guess_mime(sname)
        else:
            s_field = None
            sname = None
            s_mime = None

        video_path = f"anime/{anime}/{ep_folder}/{quality}/{vname}"
        subs_path  = f"anime/{anime}/{ep_folder}/{quality}/{sname}" if s_field else None

        # STREAM do GCS
        v_blob = Bucket.blob(video_path)
        v_blob.cache_control = "public, max-age=31536000, immutable"
        v_file = v_field["file"]; v_file.seek(0)
        v_blob.upload_from_file(v_file, content_type=v_mime)

        s_url = None
        if s_field:
            s_blob = Bucket.blob(subs_path)
            s_blob.cache_control = "public, max-age=31536000, immutable"
            s_file = s_field["file"]; s_file.seek(0)
            s_blob.upload_from_file(s_file, content_type=s_mime)
            s_url = gcs_public_url(subs_path)

        v_url = gcs_public_url(video_path)
        return self._json(200, {"ok":True, "video":v_url, "subs":s_url})

    def handle_delete_file(self):
        d = self._read_body()
        anime = (d.get("anime") or "").strip().lower()
        episode = int(d.get("episode") or 0)
        quality = (d.get("quality") or "").strip()
        name = safe_name(d.get("videoName") or "")
        if not anime or not episode or not quality or not name:
            return self._json(400, {"ok":False,"error":"Missing"})
        ep_folder = f"{int(episode):05d}"
        path = f"anime/{anime}/{ep_folder}/{quality}/{name}"
        ok = gcs_delete(path)
        return self._json(200 if ok else 404, {"ok":ok})

    # ===== Feedback =====
    def _normalize_ticket(self, rec: dict) -> dict:
        """Ujisti se, že ticket má messages[]. Pokud přišel jen 'message', převést na 1. položku vláka."""
        if not isinstance(rec, dict): return {}
        rec.setdefault("id", f"tkt_{int(time.time()*1000)}")
        rec.setdefault("status", "open")
        rec.setdefault("ts", int(time.time()*1000))
        # uživatelská první zpráva
        if "messages" not in rec or not isinstance(rec["messages"], list) or not rec["messages"]:
            init_text = (rec.get("message") or "").strip()
            author = rec.get("user") or rec.get("name") or "anonym"
            if init_text:
                rec["messages"] = [{
                    "id": rec["id"]+"_0",
                    "role": "user",
                    "author": author,
                    "text": init_text,
                    "ts": rec["ts"]
                }]
            else:
                rec["messages"] = []
        # nepotřebné pole už neschovávejme
        if "message" in rec: del rec["message"]
        return rec

    def handle_feedback_save(self):
        d = self._read_body()
        d = self._normalize_ticket(d or {})
        fid = safe_name(d.get("id") or f"tkt_{int(time.time()*1000)}")
        path = f"{FEEDBACK_PREFIX}/{fid}.json"
        gcs_write_json(path, d)
        return self._json(200, {"ok":True})

    def handle_feedback_update(self):
        d = self._read_body()
        fid = safe_name(d.get("id") or "")
        if not fid: return self._json(400, {"ok":False,"error":"missing_id"})
        path = f"{FEEDBACK_PREFIX}/{fid}.json"
        cur = gcs_read_json(path, {})
        if not cur: return self._json(404, {"ok":False,"error":"not_found"})
        cur = self._normalize_ticket(cur)

        # append message (optional)
        msg = (d.get("message") or "").strip()
        if msg:
            cur.setdefault("messages", [])
            cur["messages"].append({
                "id": f"{fid}_{len(cur['messages'])+1}",
                "role": d.get("role") or "admin",
                "author": d.get("author") or "admin",
                "text": msg,
                "ts": int(time.time()*1000)
            })
        # update status (optional)
        if d.get("status"):
            cur["status"] = d["status"]

        gcs_write_json(path, cur)
        return self._json(200, {"ok":True, "saved":cur})

    def handle_feedback_list(self):
        blobs = gcs_list(FEEDBACK_PREFIX + "/")
        out = []
        for b in blobs:
            if not b.name.endswith(".json"): continue
            try:
                data = json.loads(b.download_as_bytes().decode("utf-8"))
                out.append(self._normalize_ticket(data))
            except Exception:
                pass
        out.sort(key=lambda x: x.get("ts", 0), reverse=True)
        return self._json(200, {"ok":True, "items": out})

    # ===== Anime katalog (cloud) =====
    def handle_add_anime(self):
        d = self._read_body()
        req = ["slug","title","episodes","genres","description","cover","status","year","studio"]
        if not all(k in d for k in req):
            return self._json(400, {"ok":False,"error":"missing_fields"})
        slug = safe_name(str(d["slug"]).lower())
        cover_in = d.get("cover")

        # cover: data URL → upload do covers/{slug}.ext
        if isinstance(cover_in, str) and cover_in.startswith("data:"):
            m = re.match(r"^data:(?P<mime>[\w/+.-]+);base64,(?P<b64>.*)$", cover_in, re.DOTALL)
            if not m: return self._json(400, {"ok":False,"error":"invalid_cover"})
            mime = m.group("mime").lower()
            raw = base64.b64decode(m.group("b64"), validate=True)
            ext = {"image/jpeg":"jpg","image/jpg":"jpg","image/png":"png","image/webp":"webp","image/gif":"gif"}.get(mime,"jpg")
            cover_path = f"covers/{slug}.{ext}"
            cover_url = gcs_upload_bytes(cover_path, raw, mime, cache_immutable=True)
        else:
            cover_url = str(cover_in or "")

        try:
            item = {
                "slug": slug,
                "title": str(d["title"]),
                "episodes": int(d["episodes"]),
                "genres": list(d["genres"]),
                "description": str(d["description"]),
                "cover": cover_url if cover_url.startswith("http") else cover_path if cover_url else "",
                "status": str(d["status"]),
                "year": int(d["year"]),
                "studio": str(d["studio"]),
            }
        except Exception as e:
            return self._json(400, {"ok":False, "error":f"fields:{e}"})

        items = gcs_read_json(ANIME_JSON_CLOUD, []) or []
        items = [a for a in items if a.get("slug") != slug]
        items.append(item)
        gcs_write_json(ANIME_JSON_CLOUD, items)
        return self._json(200, {"ok":True, "saved": item, "anime_json_url": gcs_public_url(ANIME_JSON_CLOUD)})

    def handle_upload_cover(self):
        fields = parse_multipart_stream(self)
        slug = (fields.get("slug") or "").strip().lower()
        c_field = fields.get("cover")
        if not slug or not isinstance(c_field, dict):
            return self._json(400, {"ok":False,"error":"Missing"})
        mime = guess_mime(c_field.get("filename") or "cover.jpg", default="image/jpeg")
        ext = {"image/png":"png","image/webp":"webp","image/gif":"gif","image/jpeg":"jpg"}.get(mime,"jpg")
        path = f"covers/{slug}.{ext}"
        blob = Bucket.blob(path); blob.cache_control = "public, max-age=31536000, immutable"
        f = c_field["file"]; f.seek(0)
        blob.upload_from_file(f, content_type=mime)
        return self._json(200, {"ok":True, "path": gcs_public_url(path)})

    # ===== Stats =====
    def handle_stats(self):
        users_total, users_verified = count_users()

        blobs = gcs_list("anime/")
        uploads_total = 0
        ep_by_anime = {}  # klíč (slug, ep_folder) → unikátní epizoda

        for b in blobs:
            name_raw = b.name
            name = name_raw.lower()
            if not any(name.endswith(ext) for ext in VIDEO_EXTS):
                continue
            parts = name_raw.split("/")
            if len(parts) < 5:  # anime/slug/00001/quality/file
                continue
            slug = parts[1]
            ep_folder = parts[2]
            uploads_total += 1
            ep_by_anime[(slug, ep_folder)] = 1

        # top anime podle unikátních epizod
        counts = {}
        for (slug, _ep) in ep_by_anime.keys():
            counts[slug] = counts.get(slug, 0) + 1

        top_anime = None
        if counts:
            slug_top, n = max(counts.items(), key=lambda kv: kv[1])
            top_anime = {"slug": slug_top, "episodes_uploaded": n}

        return self._json(200, {
            "ok": True,
            "users_total": users_total,
            "users_verified": users_verified,
            "uploads_total": uploads_total,
            "top_anime": top_anime
        })

    def handle_upload_counts(self):
        blobs = gcs_list("anime/")
        ep_by_anime = {}
        for b in blobs:
            name = b.name  # anime/{slug}/{00001}/{quality}/file
            if not name.startswith("anime/"): continue
            if not any(name.lower().endswith(ext) for ext in VIDEO_EXTS): continue
            parts = name.split("/")
            if len(parts) < 5: continue
            slug = parts[1]; ep_folder = parts[2]
            ep_by_anime.setdefault(slug, set()).add(ep_folder)
        by_anime = {slug: len(s) for slug, s in ep_by_anime.items()}
        return self._json(200, {"ok":True, "by_anime": by_anime})

    # ===== Wipe (placeholder) =====
    def handle_wipe_all(self):
        d = self._read_body()
        pwd = d.get("password")
        if not pwd:
            return self._json(400, {"ok":False,"error":"no_password"})
        return self._json(200, {"ok":True,"status":"cloud wipe disabled"})

# ===== Bootstrap admin =====
def bootstrap_admin_if_needed():
    if not ADMIN_BOOT_ENABLE or not ADMIN_EMAIL or not ADMIN_BOOT_PASSWORD:
        return
    if load_user(ADMIN_EMAIL):
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
    if ADMIN_BOOT_ENABLE: bootstrap_admin_if_needed()
    os.chdir(BASE_DIR)
    httpd = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"AnimeCloud server běží na http://0.0.0.0:{PORT}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()
