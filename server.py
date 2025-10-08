#!/usr/bin/env python3
import os, re, io, json, base64, hashlib, hmac, time, datetime, smtplib, traceback, cgi, datetime as _dt
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
PUBLIC_BASE_URL = (os.getenv("PUBLIC_BASE_URL","").strip().rstrip("/"))

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

def gcs_signed_put_url(path: str, content_type: str, minutes: int = 30) -> str:
    """
    Vygeneruj V4 Signed URL pro přímý PUT upload na GCS.
    """
    blob = Bucket.blob(path)
    url = blob.generate_signed_url(
        version="v4",
        expiration=_dt.timedelta(minutes=minutes),
        method="PUT",
        content_type=content_type or "application/octet-stream",
    )
    return url

# ===== Helpers =====
TOKEN_INDEX_PREFIX = os.getenv("TOKEN_INDEX_PREFIX", "private/tokens").rstrip("/")

def _token_index_path(tok:str) -> str:
    return f"{TOKEN_INDEX_PREFIX}/{tok}.json"

def token_index_put(tok:str, email:str, exp:int):
    rec = {"email": (email or "").lower(), "exp": int(exp or 0)}
    gcs_write_json(_token_index_path(tok), rec)

def token_index_get(tok:str) -> str | None:
    rec = gcs_read_json(_token_index_path(tok), None)
    if not rec:
        return None
    try:
        exp = int(rec.get("exp") or 0)
    except Exception:
        exp = 0
    if exp and time.time() > exp:
        try: gcs_delete(_token_index_path(tok))
        except Exception: pass
        return None
    return (rec.get("email") or "").lower() or None

def token_index_delete(tok:str):
    try: gcs_delete(_token_index_path(tok))
    except Exception:
        pass


def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

def gen_token(nbytes=24)->str:
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("=")

def safe_name(name: str) -> str:
    if isinstance(name, bytes): name = name.decode("utf-8", "ignore")
    keep = "._-()[]{}@+&= "
    name = "".join(ch for ch in name if ch.isalnum() or ch in keep)
    return name.replace("/", "").replace("\\", "").strip() or "file"

def find_user_by_token(tok: str):
    """Najde a vrátí (email, user_dict) podle verify_tokenu napříč private/users/ v GCS."""
    if not tok:
        return None, None
    prefix = USERS_JSON_CLOUD.rstrip("/") + "/"
    for b in gcs_list(prefix):
        if not b.name.endswith(".json"):
            continue
        try:
            u = json.loads(b.download_as_bytes().decode("utf-8"))
        except Exception:
            continue
        if (u or {}).get("verify_token") == tok:
            return u.get("email", "").lower(), u
    return None, None
    
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
            if parsed.path == "/data/anime.json": return self.handle_anime_json()
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
            if parsed.path == "/upload/sign":         return self.handle_upload_sign()
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
            return self._json(400, {"ok": False, "error": "missing_fields"})
        if p1 != p2:
            return self._json(400, {"ok": False, "error": "password_mismatch"})
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return self._json(400, {"ok": False, "error": "invalid_email"})
        if load_user(email):
            return self._json(409, {"ok": False, "error": "email_exists"})
    
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
    
        tok, exp = u["verify_token"], u["verify_expires"]
        try: token_index_put(tok, email, exp)
        except Exception as e: print("[TOKEN-INDEX] put failed:", e)
    
        base = (os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
                or f"http://{self.headers.get('Host') or f'127.0.0.1:{PORT}'}")
        verify_url = f"{base}/auth/verify?t={tok}"
    
        if os.getenv("DEV_ECHO_VERIFICATION_LINK","false").lower() == "true":
            print("[DEV] Verification link:", verify_url)
    
        try: send_verification_email(email, verify_url)
        except Exception as e: print("[MAIL] send error:", e)
    
        return self._json(200, {"ok": True, "verify_url": verify_url})
    
    def handle_upload_sign(self):
        """
        Vrátí podepsané PUT URL pro video a volitelně titulky.
        Frontend pak nahrává přímo na GCS (CORS v bucketu je potřeba mít povolené).
        """
        d = self._read_body() or {}
        anime   = (d.get("anime") or "").strip().lower()
        episode = int(str(d.get("episode") or "0"))
        quality = (d.get("quality") or "").strip()
    
        video_name = safe_name(d.get("videoName") or "")
        video_type = d.get("videoType") or "video/mp4"
        subs_name  = safe_name(d.get("subsName") or "") if d.get("subsName") else None
        subs_type  = d.get("subsType") or "application/x-subrip"
    
        if not anime or not episode or not quality or not video_name:
            return self._json(400, {"ok": False, "error": "missing_fields"})
    
        ep_folder = f"{int(episode):05d}"
        video_path = f"anime/{anime}/{ep_folder}/{quality}/{video_name}"
        subs_path  = f"anime/{anime}/{ep_folder}/{quality}/{subs_name}" if subs_name else None
    
        try:
            v_signed = gcs_signed_put_url(video_path, video_type, minutes=60)
            s_signed = gcs_signed_put_url(subs_path, subs_type, minutes=60) if subs_path else None
            return self._json(200, {
                "ok": True,
                "video": {
                    "put_url": v_signed,
                    "public_url": gcs_public_url(video_path),
                    "content_type": video_type
                },
                "subs": ({"put_url": s_signed, "public_url": gcs_public_url(subs_path), "content_type": subs_type} if s_signed else None)
            })
        except Exception as e:
            # Vrátíme čitelnou chybu do FE (aby nepršelo jen 500 bez detailu)
            return self._json(500, {"ok": False, "error": f"sign_failed: {e.__class__.__name__}: {e}"})

    def handle_resend(self):
        d = self._read_body()
        email = (d.get("email") or "").strip().lower()
    
        u = load_user(email)
        if not u:
            return self._json(404, {"ok": False, "error": "not_found"})
        if u.get("verified"):
            return self._json(400, {"ok": False, "error": "already_verified"})
    
        u["verify_token"] = gen_token()
        u["verify_expires"] = int(time.time()) + 60*60*48
        save_user(u)
    
        tok, exp = u["verify_token"], u["verify_expires"]
        try: token_index_put(tok, email, exp)
        except Exception as e: print("[TOKEN-INDEX] put failed:", e)
    
        base = (os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
                or f"http://{self.headers.get('Host') or f'127.0.0.1:{PORT}'}")
        verify_url = f"{base}/auth/verify?t={tok}"
    
        try: send_verification_email(email, verify_url)
        except Exception as e: print("[MAIL] send error:", e)
    
        return self._json(200, {"ok": True, "verify_url": verify_url})

    def handle_verify(self, parsed):
        qs = parse_qs(parsed.query)
        tok = (qs.get("t", [""])[0]).strip()
        email_q = (qs.get("email", [""])[0]).strip().lower()
        token_q = (qs.get("token", [""])[0]).strip()
    
        # 1) Preferuj nový ?t=token
        if tok:
            email = token_index_get(tok)
            if not email:
                return self._html(400, self._verify_page(False, "Ověření selhalo<br/>Neplatný nebo expirovaný token."))
        # 2) fallback: starý tvar ?email=&token=
        elif email_q and token_q:
            email, tok = email_q, token_q
        else:
            return self._html(400, self._verify_page(False, "Ověření selhalo<br/>Chybí token."))
    
        u = load_user(email)
        if not u:
            return self._html(400, self._verify_page(False, "Ověření selhalo<br/>Uživatel nenalezen."))
    
        # kontrola expirace v user záznamu (pokud je)
        exp = int(u.get("verify_expires") or 0)
        if exp and time.time() > exp:
            return self._html(400, self._verify_page(False, "Odkaz vypršel. Požádej o nový v aplikaci."))
    
        # i když nesouhlasí u['verify_token'], pokud máme platný token index, ověříme
        u["verified"] = True
        u["verify_token"] = None
        u["verify_expires"] = None
        save_user(u)
        token_index_delete(tok)
        print(f"[VERIFY] {email} verified=True")
    
        return self._html(200, self._verify_page(
            True, "Účet ověřen ✅<br/>Nyní se můžeš přihlásit.", redirect="/login.html", delay_ms=1200
        ))
    
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
        # očekáváme multipart/form-data
        ctype = self.headers.get("Content-Type", "")
        if not ctype.startswith("multipart/form-data"):
            return self._json(400, {"ok": False, "error": "expected_multipart"})
    
        # FieldStorage čte přímo ze socketu a spouluje na disk – vhodné pro velké soubory
        env = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": ctype,
        }
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ=env,
            keep_blank_values=True
        )
    
        anime   = (form.getfirst("anime", "") or "").strip().lower()
        episode = int(form.getfirst("episode", "0") or "0")
        quality = (form.getfirst("quality", "") or "").strip()
    
        v_item  = form["video"] if "video" in form else None
        s_item  = form["subs"]  if "subs"  in form else None
    
        # názvy souborů (bezpečně + default přípony)
        vname = safe_name(form.getfirst("videoName", getattr(v_item, "filename", "video.mp4")) or "video.mp4")
        if "." not in vname: vname += ".mp4"
        sname = safe_name(form.getfirst("subsName", getattr(s_item, "filename", "subs.srt")) or "subs.srt")
    
        if not anime or not episode or not quality or not v_item:
            return self._json(400, {"ok": False, "error": "missing_fields"})
    
        ep_folder = f"{int(episode):05d}"
        v_mime = guess_mime(vname, default="video/mp4")
        s_mime = guess_mime(sname, default="application/x-subrip")
    
        v_path = f"anime/{anime}/{ep_folder}/{quality}/{vname}"
        s_path = f"anime/{anime}/{ep_folder}/{quality}/{sname}"
    
        # upload videa (stream → GCS), FieldStorage drží .file otevřený => nepoužívej .read()
        v_blob = Bucket.blob(v_path)
        v_blob.cache_control = "public, max-age=31536000, immutable"
        v_file = v_item.file
        v_blob.upload_from_file(v_file, content_type=v_mime, rewind=True)
    
        s_url = None
        if s_item:
            s_blob = Bucket.blob(s_path)
            s_blob.cache_control = "public, max-age=31536000, immutable"
            s_file = s_item.file
            s_blob.upload_from_file(s_file, content_type=s_mime, rewind=True)
            s_url = gcs_public_url(s_path)
    
        return self._json(200, {"ok": True, "video": gcs_public_url(v_path), "subs": s_url})

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

    def handle_anime_json(self):
        data = gcs_read_json(ANIME_JSON_CLOUD, []) or []
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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

    # ===== KODI =====
    @app.route('/catalog')
    def catalog():
        """
        Vrátí list anime položek s episodes_count.
        Bereme data/anime.json + GET /uploads/counts pro mapu epizod.
        """
        from google.cloud import storage
        import json
    
        # načti anime.json (stejně jako to děláš jinde)
        anime = load_json_from_gcs('data/anime.json')  # TODO: použij svůj helper
        counts = get_upload_counts()                   # TODO: wrap k /uploads/counts logice nebo ji přímo zavolej
    
        out = []
        for a in anime:
            slug = a.get('slug')
            cover_url = public_url_for(f"covers/{slug}.jpg")  # nebo .png/.webp, případně si to už ukládáš jako plnou URL
            out.append({
                'slug': slug,
                'title': a.get('title'),
                'genres': a.get('genres', []),
                'year': a.get('year'),
                'studio': a.get('studio'),
                'plot': a.get('plot', ''),
                'cover': cover_url,
                'episodes_count': counts.get(slug, 0),
            })
        return jsonify(out)

    @app.route('/stream/sign')
    def stream_sign():
        """
        Vstup: slug, ep (00001), q (např. 1080p)
        Najde první přehratelný soubor v anime/{slug}/{ep}/{q}/
        Podepíše na GET a vrátí {url, subtitles_url?, title}
        """
        from google.cloud import storage
        from google.cloud.storage.blob import Blob
        import datetime
    
        slug = request.args.get('slug', '').strip()
        ep   = request.args.get('ep', '').strip()      # očekáváme 00001 (5 znaků)
        q    = request.args.get('q', '').strip()
    
        if not slug or not ep or not q:
            return jsonify({'error': 'missing parameters'}), 400
    
        client = storage.Client()
        bucket = client.bucket(GCS_BUCKET)  # použij svou konstantu
    
        prefix = f"anime/{slug}/{ep}/{q}/"
        blobs  = list(client.list_blobs(GCS_BUCKET, prefix=prefix))
    
        # vyber video podle přípony (priorita .m3u8, .mp4, .mkv)
        def pick(blobs, exts):
            for ext in exts:
                for b in blobs:
                    if b.name.lower().endswith(ext):
                        return b
            return None
    
        video_blob = pick(blobs, ['.m3u8', '.mp4', '.mkv'])
        if not video_blob:
            return jsonify({'error': f'no media in {prefix}'}), 404
    
        # titulky (volitelné)
        sub_blob = None
        for b in blobs:
            if b.name.lower().endswith('.srt'):
                sub_blob = b
                break
    
        expires = datetime.timedelta(hours=6)  # přehrávače si to během sezení stáhnou
        video_url = video_blob.generate_signed_url(version='v4', expiration=expires, method='GET')
        subs_url  = sub_blob.generate_signed_url(version='v4', expiration=expires, method='GET') if sub_blob else None
    
        # hezký název
        title = f"{slug} — {int(ep):02d} ({q})"
    
        return jsonify({'url': video_url, 'subtitles_url': subs_url, 'title': title})















