#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, io, json, base64, hashlib, hmac, time, datetime, smtplib, traceback
from http.server import SimpleHTTPRequestHandler, HTTPServer
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlparse, parse_qs, urlencode, quote
from email.parser import BytesParser
from email.policy import default as email_default

# ===== mini .env loader =====
def load_env_dotfile(path=".env"):
    if not os.path.exists(path): return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k,v = line.split("=",1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_env_dotfile(os.path.join(BASE_DIR, ".env"))

# ===== Config =====
PORT = int(os.getenv("PORT", "8080"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

GCS_BUCKET = os.getenv("GCS_BUCKET")  # povinné

# Cesty v bucketu
ANIME_JSON_CLOUD = os.getenv("ANIME_JSON_CLOUD", os.getenv("ANIME_JSONCLOUD", "data/anime.json"))  # kompat s tvým .env
USERS_JSON_CLOUD = (os.getenv("USERS_JSON_CLOUD") or os.getenv("USERS_DIR_CLOUD") or "private/users").rstrip("/")
FEEDBACK_PREFIX  = os.getenv("FEEDBACK_PREFIX", "private/feedback").rstrip("/")
COVERS_PREFIX    = os.getenv("COVERS_PREFIX", "covers").rstrip("/")
UPLOADS_PREFIX   = os.getenv("UPLOADS_PREFIX", "anime").rstrip("/")

# Admin bootstrap
ADMIN_BOOT_ENABLE   = os.getenv("ADMIN_BOOT_ENABLE","false").lower()=="true"
ADMIN_EMAIL         = (os.getenv("ADMIN_EMAIL","").strip().lower())
ADMIN_BOOT_PASSWORD = os.getenv("ADMIN_BOOT_PASSWORD","")

# SMTP
SMTP_HOST     = os.getenv("SMTP_HOST","smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT","587"))
SMTP_USER     = os.getenv("SMTP_USER")
SMTP_PASS     = os.getenv("SMTP_PASS")
SMTP_FROM     = os.getenv("SMTP_FROM", SMTP_USER or "")
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS","true").lower()=="true"
SMTP_DEBUG    = os.getenv("SMTP_DEBUG","0") in ("1","true","True")

DEV_ECHO_VERIFICATION_LINK = os.getenv("DEV_ECHO_VERIFICATION_LINK","false").lower()=="true"
DEV_SAVE_LAST_EMAIL        = (os.getenv("DEV_SAVE_LAST_EMAIL","false").lower()=="true"
                              or os.getenv("DEV_ECHO_LAST_EMAIL","false").lower()=="true")

DEBUG_AUTH = os.getenv("DEBUG_AUTH","false").lower()=="true"

# ===== GCS =====
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
    try:
        return json.loads(blob.download_as_bytes().decode("utf-8"))
    except Exception:
        return default

def gcs_write_json(path:str, obj:dict, cache_control:str|None=None):
    blob = Bucket.blob(path)
    payload = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    if cache_control:
        blob.cache_control = cache_control
    blob.upload_from_string(payload, content_type="application/json; charset=utf-8")

def gcs_write_bytes(path:str, raw:bytes, content_type:str, cache_control:str|None=None):
    blob = Bucket.blob(path)
    if cache_control:
        blob.cache_control = cache_control
    blob.upload_from_string(raw, content_type=content_type)
    return gcs_public_url(path)

def gcs_list(prefix:str):
    return list(GCS.list_blobs(GCS_BUCKET, prefix=(prefix.rstrip("/") + "/")))

# ===== Helpers: users, feedback, anime =====
def user_path(email:str)->str:
    safe = email.lower().replace("/", "_")
    return f"{USERS_JSON_CLOUD}/{safe}.json"

def load_user(email:str):
    return gcs_read_json(user_path(email), None)

def save_user(u:dict):
    gcs_write_json(user_path(u["email"]), u)  # bez dlouhé cache

def count_users():
    blobs = gcs_list(USERS_JSON_CLOUD)
    total = 0; verified = 0
    for b in blobs:
        if not b.name.endswith(".json"): continue
        total += 1
        try:
            d = json.loads(b.download_as_bytes().decode("utf-8"))
            if d.get("verified"): verified += 1
        except: pass
    return total, verified

def read_anime_list():
    return gcs_read_json(ANIME_JSON_CLOUD, default=[])

def write_anime_list(items:list):
    # krátká cache, ať se nelepí staré verze
    gcs_write_json(ANIME_JSON_CLOUD, items, cache_control="no-cache")

# ===== Passwords & tokens =====
def hash_password(password:str, salt:bytes=None, iterations:int=200_000)->str:
    if salt is None: salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2-sha256:{iterations}:{base64.urlsafe_b64encode(salt).decode()}:{dk.hex()}"

def verify_password(password:str, stored:str)->bool:
    try:
        algo, iters, salt_b64, hexhash = stored.split(":",3)
        if algo!="pbkdf2-sha256": return False
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters)).hex()
        return hmac.compare_digest(calc, hexhash)
    except Exception:
        return False

def gen_token(nbytes=24)->str:
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("=")

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

# ===== MIME + multipart =====
EXT_MIME = {
    ".mp4":"video/mp4",".m4v":"video/x-m4v",".webm":"video/webm",".mkv":"video/x-matroska",".mov":"video/quicktime",
    ".srt":"application/x-subrip",".vtt":"text/vtt",
    ".jpg":"image/jpeg",".jpeg":"image/jpeg",".png":"image/png",".webp":"image/webp",".gif":"image/gif",
}
VIDEO_EXTS = {".mp4",".m4v",".webm",".mkv",".mov"}
def guess_mime(filename:str, sniff:bytes|None=None, default="application/octet-stream"):
    fn=(filename or "").lower()
    for ext,m in EXT_MIME.items():
        if fn.endswith(ext): return m
    if sniff:
        if sniff.startswith(b"\x89PNG"): return "image/png"
        if sniff[:3]==b"\xff\xd8\xff": return "image/jpeg"
        if sniff.startswith(b"RIFF") and b"WEBP" in sniff[:16]: return "image/webp"
        if sniff[:4]==b"\x1a\x45\xdf\xa3": return "video/x-matroska"
        if sniff[:4]==b"ftyp": return "video/mp4"
    return default

def safe_name(name:str)->str:
    if isinstance(name, bytes): name = name.decode("utf-8","ignore")
    keep = "._-()[]{}@+&= "
    name = "".join(ch for ch in name if ch.isalnum() or ch in keep)
    return name.replace("/","").replace("\\","").strip() or "file"

def parse_multipart_request(handler):
    length = int(handler.headers.get("Content-Length","0") or "0")
    body = handler.rfile.read(length)
    ctype = handler.headers.get("Content-Type","")
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
                fields[name+"_name"] = filename
    return fields

# ===== Mail =====
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
    msg.attach(MIMEText(text,"plain","utf-8"))
    msg.attach(MIMEText(html,"html","utf-8"))

    if DEV_SAVE_LAST_EMAIL:
        with open(os.path.join(BASE_DIR, "last_email.eml"), "wb") as f:
            f.write(msg.as_bytes())

    if not (SMTP_HOST and SMTP_PORT and SMTP_USER and SMTP_PASS):
        print("[WARN] SMTP není kompletně nastaven – e-mail se neodeslal.")
        return

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
        if SMTP_DEBUG: s.set_debuglevel(1)
        if SMTP_STARTTLS: s.starttls()
        s.ehlo(); s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(msg["From"], [to_email], msg.as_string())

# ===== HTTP =====
class Handler(SimpleHTTPRequestHandler):
    def _set_cors(self):
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGINS)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def end_headers(self):
        self._set_cors(); super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204); self.end_headers()

    def _read_json_or_form(self):
        ctype = self.headers.get("Content-Type","")
        raw = self.rfile.read(int(self.headers.get("Content-Length","0") or 0))
        if "application/json" in ctype:
            try: return json.loads(raw.decode("utf-8"))
            except: return {}
        if "application/x-www-form-urlencoded" in ctype:
            try:
                qs = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
                return {k:(v[0] if isinstance(v,list) else v) for k,v in qs.items()}
            except: return {}
        return {}

    def _json(self, code:int, obj:dict):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def _html(self, code:int, html:str):
        data = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def _base_url(self)->str:
        if PUBLIC_BASE_URL: return PUBLIC_BASE_URL
        host = self.headers.get("Host") or f"127.0.0.1:{PORT}"
        return f"http://{host}"

    # --- routing ---
    def do_GET(self):
        p = urlparse(self.path)
        try:
            if p.path == "/auth/verify":            return self.handle_verify_page(p)
            if p.path == "/stats":                  return self.handle_stats()
            if p.path == "/feedback/list":          return self.handle_feedback_list()
            return super().do_GET()
        except Exception:
            traceback.print_exc()
            return self._json(500, {"ok":False,"error":"internal"})

    def do_POST(self):
        p = urlparse(self.path)
        try:
            if p.path == "/auth/register":          return self.handle_register()
            if p.path == "/auth/resend":            return self.handle_resend()
            if p.path == "/auth/login":             return self.handle_login()
            if p.path == "/auth/verify/confirm":    return self.handle_verify_confirm()
            if p.path == "/upload":                 return self.handle_upload()
            if p.path == "/feedback":               return self.handle_feedback_submit()
            if p.path == "/feedback/reply":         return self.handle_feedback_reply()
            if p.path == "/feedback/update":        return self.handle_feedback_update()
            if p.path == "/admin/add_anime":        return self.handle_add_anime()
            return self._json(404, {"ok":False,"error":"not_found"})
        except Exception:
            traceback.print_exc()
            return self._json(500, {"ok":False,"error":"internal"})

    # ===== Auth =====
    def handle_register(self):
        d = self._read_json_or_form()
        email = (d.get("email") or "").strip().lower()
        p1    = (d.get("password") or d.get("pass") or "").strip()
        p2    = (d.get("password2") or d.get("confirm") or d.get("pass2") or "").strip()
        name  = (d.get("name") or "").strip() or (email.split("@")[0] if email else "")

        if not email or not p1: return self._json(400, {"error":"missing_fields"})
        if p2 and p1 != p2:     return self._json(400, {"error":"password_mismatch"})
        if len(p1) < 8:         return self._json(400, {"error":"weak_password"})
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email): return self._json(400, {"error":"invalid_email"})
        if load_user(email):    return self._json(409, {"error":"email_exists"})

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
        save_user(u)  # 1) uložit

        verify_url = f"{self._base_url()}/auth/verify?{urlencode({'email': email, 'token': u['verify_token']})}"
        try: send_verification_email(email, verify_url)  # 2) poslat mail
        except Exception as e: print("[MAIL] send error:", e)

        return self._json(200, {"ok": True})

    def handle_resend(self):
        d = self._read_json_or_form()
        email = (d.get("email") or "").strip().lower()
        u = load_user(email)
        if not u: return self._json(404, {"error":"not_found"})
        if u.get("verified"): return self._json(400, {"error":"already_verified"})
        u["verify_token"] = gen_token()
        u["verify_expires"] = int(time.time()) + 60*60*48
        save_user(u)
        verify_url = f"{self._base_url()}/auth/verify?{urlencode({'email': email, 'token': u['verify_token']})}"
        try: send_verification_email(email, verify_url)
        except Exception as e: print("[MAIL] send error:", e)
        return self._json(200, {"ok": True})

    def handle_verify_page(self, parsed):
        qs = parse_qs(parsed.query)
        email = (qs.get("email",[""])[0]).strip().lower()
        token = (qs.get("token",[""])[0]).strip()
        u = load_user(email)
        login_url = f"{self._base_url()}/login.html"

        if not u:
            return self._html(400, self.render_verify_page(False, "Ověření selhalo.<br/>Neplatný odkaz nebo e-mail."))
        if u.get("verified"):
            return self._html(200, self.render_verify_page(True, "Účet je již ověřen ✅<br/>Můžeš se přihlásit.", redirect=login_url, delay_ms=1500))
        exp = int(u.get("verify_expires") or 0)
        if not token or token != (u.get("verify_token") or ""):
            return self._html(400, self.render_verify_page(False, "Ověření selhalo.<br/>Neplatný token."))
        if exp and time.time() > exp:
            return self._html(400, self.render_verify_page(False, "Odkaz vypršel. Nech si poslat nový."))

        # Stránka sama udělá POST /auth/verify/confirm
        html = f"""<!doctype html><html lang="cs"><head>
<meta charset="utf-8"><title>Ověření účtu</title>
<style>body{{background:#0e0e12;color:#fff;font-family:system-ui;}}
.card{{max-width:720px;margin:60px auto;background:#181820;border:1px solid #2a2a36;border-radius:14px;padding:24px}}
.btn{{background:#7c5cff;color:#fff;padding:.6rem 1rem;border:none;border-radius:10px;cursor:pointer}}
.msg{{margin-top:.5rem;opacity:.9}}</style></head>
<body><div class="card">
<h1>Ověření účtu</h1>
<p id="status">Probíhá ověřování…</p>
<form method="post" action="/auth/verify/confirm" style="margin-top:.6rem">
  <input type="hidden" name="email" value="{email}"/>
  <input type="hidden" name="token" value="{token}"/>
  <button class="btn" type="submit">Potvrdit účet ručně</button>
</form>
<script>
(function(){{
  const payload = {{email: {json.dumps(email)}, token: {json.dumps(token)}}};
  const loginUrl = {json.dumps(login_url)};
  fetch('/auth/verify/confirm', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify(payload)}})
    .then(r=>r.json().catch(()=>({{}}))).then(d=>{{
      const st = document.getElementById('status');
      if (d && d.ok) {{ st.innerHTML='Účet ověřen ✅<br/>Přesměrovávám…'; setTimeout(()=>location.href=loginUrl, 1500); }}
      else {{ st.textContent='Ověření selhalo. Zkus tlačítko níže.'; }}
    }}).catch(()=>{{ document.getElementById('status').textContent='Ověření selhalo. Zkus tlačítko níže.'; }});
}})();
</script>
</div></body></html>"""
        return self._html(200, html)

    def handle_verify_confirm(self):
        d = self._read_json_or_form()
        email = (d.get("email") or "").strip().lower()
        token = (d.get("token") or "").strip()
        u = load_user(email)
        if not u: return self._json(400, {"ok": False, "error":"not_found"})
        if u.get("verified"): return self._json(200, {"ok": True, "already": True})
        if not token or token != (u.get("verify_token") or ""): return self._json(400, {"ok": False, "error":"bad_token"})
        exp = int(u.get("verify_expires") or 0)
        if exp and time.time() > exp: return self._json(400, {"ok": False, "error":"expired"})
        u["verified"] = True
        u["verify_token"] = None
        u["verify_expires"] = None
        save_user(u)
        return self._json(200, {"ok": True})

    def handle_login(self):
        d = self._read_json_or_form()
        email = (d.get("email") or "").strip().lower()
        password = (d.get("password") or "").strip()
        if not email or not password: return self._json(400, {"error":"missing_fields"})
        u = load_user(email)
        if not u or not verify_password(password, u.get("password_hash","")):
            return self._json(403, {"error":"invalid_credentials"})
        if not u.get("verified"):
            return self._json(403, {"error":"not_verified"})
        return self._json(200, {"ok": True, "email": u["email"], "name": u.get("name"), "role": u.get("role","user")})

    # ===== Upload (video + titulky) =====
    def handle_upload(self):
        fields = parse_multipart_request(self)
        slug    = (fields.get("anime") or "").strip().lower()
        episode = (fields.get("episode") or "").strip()
        quality = (fields.get("quality") or "").strip()
        video   = fields.get("video")
        vname   = safe_name(fields.get("video_name") or fields.get("videoName") or "video.mp4")
        subs    = fields.get("subs")
        sname   = safe_name(fields.get("subs_name")  or fields.get("subsName")  or "subs.srt")

        if not slug or not episode or not quality or not video:
            return self._json(400, {"ok":False,"error":"missing_fields"})

        try: ep_folder = f"{int(episode):05d}"
        except: return self._json(400, {"ok":False,"error":"bad_episode"})

        v_mime = guess_mime(vname, sniff=video[:8] if isinstance(video,(bytes,bytearray)) else None, default="video/mp4")
        s_mime = guess_mime(sname, sniff=subs[:8] if isinstance(subs,(bytes,bytearray)) else None, default="application/x-subrip")

        video_path = f"{UPLOADS_PREFIX}/{slug}/{ep_folder}/{quality}/{vname}"
        subs_path  = f"{UPLOADS_PREFIX}/{slug}/{ep_folder}/{quality}/{sname}"

        video_url = gcs_write_bytes(video_path, video, v_mime, cache_control="public, max-age=31536000, immutable")
        subs_url  = None
        if subs:
            subs_url = gcs_write_bytes(subs_path, subs, s_mime, cache_control="public, max-age=31536000, immutable")

        return self._json(200, {"ok":True, "video": video_url, "subs": subs_url})

    # ===== Feedback =====
    def handle_feedback_submit(self):
        d = self._read_json_or_form()
        # očekáváme payload jako na FE: { id, user|name, category, priority, message, status, ts, messages[ ... ] }
        fid = (d.get("id") or f"tkt_{int(time.time()*1000)}").strip()
        if not fid: fid = f"tkt_{int(time.time()*1000)}"
        path = f"{FEEDBACK_PREFIX}/{safe_name(fid)}.json"
        gcs_write_json(path, d)  # přepíše/uloží
        return self._json(200, {"ok":True})

    def handle_feedback_list(self):
        blobs = gcs_list(FEEDBACK_PREFIX)
        items = []
        for b in blobs:
            if not b.name.endswith(".json"): continue
            try:
                data = json.loads(b.download_as_bytes().decode("utf-8"))
                items.append(data)
            except: pass
        # seřadit desc dle ts
        items.sort(key=lambda x: x.get("ts",0), reverse=True)
        return self._json(200, {"ok":True, "items": items})

    def handle_feedback_reply(self):
        d = self._read_json_or_form()
        fid = (d.get("id") or "").strip()
        role = (d.get("role") or "admin").strip()
        author = (d.get("author") or "admin").strip()
        text = (d.get("text") or "").strip()
        if not fid or not text:
            return self._json(400, {"ok":False,"error":"missing_fields"})
        path = f"{FEEDBACK_PREFIX}/{safe_name(fid)}.json"
        item = gcs_read_json(path, {})
        msgs = item.get("messages") or []
        msgs.append({"id": f"{fid}_{len(msgs)+1}", "role": role, "author": author, "text": text, "ts": int(time.time()*1000)})
        item["messages"] = msgs
        gcs_write_json(path, item)
        return self._json(200, {"ok":True})

    def handle_feedback_update(self):
        d = self._read_json_or_form()
        fid = (d.get("id") or "").strip()
        status = (d.get("status") or "").strip()
        if not fid or not status:
            return self._json(400, {"ok":False,"error":"missing_fields"})
        path = f"{FEEDBACK_PREFIX}/{safe_name(fid)}.json"
        item = gcs_read_json(path, {})
        if not item: return self._json(404, {"ok":False,"error":"not_found"})
        item["status"] = status
        gcs_write_json(path, item)
        return self._json(200, {"ok":True})

    # ===== Admin: add/update anime =====
    def handle_add_anime(self):
        d = self._read_json_or_form()
        required = ["slug","title","episodes","genres","description","cover","status","year","studio"]
        if not all(k in d for k in required):
            return self._json(400, {"ok":False,"error":"missing_fields"})

        slug = safe_name(str(d["slug"]).lower())
        cover_in = d.get("cover")
        # 1) ulož cover (pokud je data URL)
        if isinstance(cover_in,str) and cover_in.startswith("data:"):
            # data URL -> bytes
            m = re.match(r"^data:(?P<mime>[\w/+.-]+);base64,(?P<b64>.*)$", cover_in, re.DOTALL)
            if not m: return self._json(400, {"ok":False,"error":"bad_cover"})
            mime = m.group("mime").lower()
            raw = base64.b64decode(m.group("b64"), validate=True)
            ext = {"image/jpeg":"jpg","image/jpg":"jpg","image/png":"png","image/webp":"webp","image/gif":"gif"}.get(mime,"jpg")
            cover_url = gcs_write_bytes(f"{COVERS_PREFIX}/{slug}.{ext}", raw, mime, cache_control="public, max-age=31536000, immutable")
        else:
            cover_url = str(cover_in or "")

        # 2) připrav položku
        try:
            item = {
                "slug": slug,
                "title": str(d["title"]),
                "episodes": int(d["episodes"]),
                "genres": list(d["genres"]),
                "description": str(d["description"]),
                "cover": cover_url,
                "status": str(d["status"]),
                "year": int(d["year"]),
                "studio": str(d["studio"]),
            }
        except Exception as e:
            return self._json(400, {"ok":False,"error":f"bad_fields: {e}"})

        # 3) načti list, přepiš dle slug, zapiš zpět
        items = read_anime_list()
        items = [a for a in items if a.get("slug") != slug]
        items.append(item)
        write_anime_list(items)

        return self._json(200, {"ok":True, "saved": item, "anime_json_url": gcs_public_url(ANIME_JSON_CLOUD)})

    # ===== Stats =====
    def handle_stats(self):
        # users
        total_users, verified = count_users()

        # uploads (video soubory) a "nejaktivnější" anime (dle počtu unik. epizod s alespoň jedním videem)
        blobs = gcs_list(UPLOADS_PREFIX)
        uploads_total = 0
        per_slug_eps = {}  # slug -> {ep_set}
        for b in blobs:
            name = b.name  # anime/{slug}/{00001}/{quality}/file.mp4
            if not name.lower().startswith(UPLOADS_PREFIX + "/"):
                continue
            # počítej pouze video soubory
            lower = name.lower()
            if not any(lower.endswith(ext) for ext in VIDEO_EXTS):
                continue
            uploads_total += 1
            try:
                _, slug, ep_folder, *_ = name.split("/")
                per_slug_eps.setdefault(slug, set()).add(ep_folder)
            except Exception:
                pass

        top_slug = None
        top_count = -1
        for slug, eps in per_slug_eps.items():
            c = len(eps)
            if c > top_count:
                top_count = c
                top_slug = slug

        return self._json(200, {
            "ok": True,
            "users_total": total_users,
            "users_verified": verified,
            "uploads_total": uploads_total,
            "top_anime": {"slug": top_slug, "episodes_with_uploads": (top_count if top_slug else 0)}
        })

# ===== Bootstrap admin =====
def bootstrap_admin_if_needed():
    if not ADMIN_BOOT_ENABLE or not ADMIN_EMAIL or not ADMIN_BOOT_PASSWORD: return
    if load_user(ADMIN_EMAIL):
        print("[BOOT] Admin už existuje."); return
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
    print(f"[BOOT] Vytvořen admin účet: {ADMIN_EMAIL}. Nastav ADMIN_BOOT_ENABLE=false po prvním spuštění.")

def main():
    if not GCS_BUCKET:
        raise RuntimeError("Chybí GCS_BUCKET v .env")
    init_gcs()
    if ADMIN_BOOT_ENABLE: bootstrap_admin_if_needed()
    os.chdir(BASE_DIR)
    httpd = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"AnimeCloud server běží na {PUBLIC_BASE_URL or f'http://0.0.0.0:{PORT}'}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()
