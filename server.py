#!/usr/bin/env python3
import os, re, json, base64, hashlib, hmac, time, datetime, threading
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
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

# GCS
GCS_BUCKET = os.getenv("GCS_BUCKET")  # required
USERS_STORAGE_MODE = os.getenv("USERS_STORAGE_MODE", "dir").lower()  # 'dir' (per-user JSON)
ANIME_JSON_CLOUD = os.getenv("ANIME_JSON_CLOUD", "data/anime.json")
USERS_JSON_CLOUD = os.getenv("USERS_JSON_CLOUD", "private/users")  # for mode=dir → prefix

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
DEV_SAVE_LAST_EMAIL        = os.getenv("DEV_SAVE_LAST_EMAIL","false").lower() == "true"

DEBUG_AUTH = os.getenv("DEBUG_AUTH","false").lower() == "true"

# ====== GCS client ======
GCS = None
Bucket = None
def init_gcs():
    global GCS, Bucket
    from google.cloud import storage  # needs google-cloud-storage
    GCS = storage.Client()
    Bucket = GCS.bucket(GCS_BUCKET)

def gcs_read_json(path:str, default=None):
    blob = Bucket.blob(path)
    if not blob.exists(): return default
    data = blob.download_as_bytes()
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return default

def gcs_write_json(path:str, obj:dict):
    blob = Bucket.blob(path)
    payload = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    blob.upload_from_string(payload, content_type="application/json")

def gcs_list(prefix:str):
    return [b.name for b in GCS.list_blobs(GCS_BUCKET, prefix=prefix)]

# ====== users storage helpers ======
def user_path(email:str)->str:
    # email jako jméno souboru (požadavek)
    base = USERS_JSON_CLOUD.rstrip("/")
    return f"{base}/{email.lower()}.json"

def load_user(email:str):
    return gcs_read_json(user_path(email), default=None)

def save_user(u:dict):
    gcs_write_json(user_path(u["email"]), u)

def count_users():
    if USERS_STORAGE_MODE == "dir":
        names = [n for n in gcs_list(USERS_JSON_CLOUD.rstrip("/") + "/") if n.endswith(".json")]
        total = len(names)
        verified = 0
        for n in names:
            data = gcs_read_json(n, {})
            if data.get("verified"): verified += 1
        return total, verified
    return 0,0

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

# ====== tokeny ======
def gen_token(nbytes=24)->str:
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("=")

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

# ====== mail ======
def send_verification_email(to_email:str, verify_url:str):
    if DEV_ECHO_VERIFICATION_LINK:
        print("[DEV] Verification link:", verify_url)

    msg = MIMEMultipart("alternative")
    # hezčí From pokud je definovaný SMTP_FROM "AnimeCloud <mail@...>"
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
            return self._json(200, {"users_total": total, "users_verified": verified})
        # default: statické soubory z rootu
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/auth/register":
            return self.handle_register()
        if parsed.path == "/auth/login":
            return self.handle_login()
        if parsed.path == "/auth/resend":
            return self.handle_resend()
        self.send_error(404, "Not found")

    # --- endpoints ---
    def handle_register(self):
        data = self._read_body()
        email = (data.get("email") or "").strip().lower()
        name  = (data.get("name")  or "").strip()
        p1 = (data.get("password") or data.get("pass") or "").strip()
        p2 = (data.get("password2") or data.get("password_confirm") or data.get("confirm") or data.get("pass2") or "").strip()

        if not email or not name or not p1 or not p2:
            return self._json(400, {"error":"missing_fields"})
        if p1 != p2:
            if DEBUG_AUTH: print(f"[DEBUG] password mismatch for {email} (len1={len(p1)}, len2={len(p2)})")
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
            "verify_expires": int(time.time()) + 60*60*48  # 48h
        }
        save_user(u)

        # poslat ověřovací e-mail
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

        # označit jako ověřeno
        u["verified"] = True
        u["verify_token"] = None
        u["verify_expires"] = None
        save_user(u)

        # 1s auto-redirect na login.html
        return self._html(200, self.render_verify_page(ok=True, msg="Účet ověřen ✅<br/>Nyní se můžeš přihlásit.", redirect="/login.html", delay_ms=1000))

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

        # v jednoduché verzi jen potvrzení (tokeny/session neřešíme)
        return self._json(200, {"ok":True, "email":u["email"], "name":u.get("name"), "role":u.get("role","user")})

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

    os.chdir(BASE_DIR)  # servíruj statické soubory z kořene repo
    httpd = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"AnimeCloud server běží na portu {PORT}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()
