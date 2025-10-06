#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnimeCloud microserver
- Static file server for UI
- JSON "database" of users either in local dir or in Google Cloud Storage (optional)
- Register + e-mail verification + login
- Simple /stats endpoint

No external dependencies unless you set USERS_STORAGE_MODE=gcs
(in that case the package `google-cloud-storage` must be installed).

Author: ChatGPT
"""
from http.server import SimpleHTTPRequestHandler, HTTPServer
import os, json, re, hmac, base64, hashlib, secrets, time, datetime, urllib.parse, pathlib, sys, io
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

# --------------------
# Configuration loader
# --------------------
def load_env(path):
    env = {}
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): 
                    continue
                if '=' in line:
                    k, v = line.split('=', 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
    # process booleans with defaults
    def b(name, default=False):
        v = env.get(name)
        if v is None: 
            return default
        return v.lower() in ('1','true','yes','y','on')
    # ints
    def i(name, default=0):
        v = env.get(name)
        try:
            return int(v)
        except:
            return default
    cfg = {
        'PORT': i('PORT', 8080),
        'USERS_STORAGE_MODE': env.get('USERS_STORAGE_MODE', 'dir'),
        'USERS_JSON_CLOUD': env.get('USERS_JSON_CLOUD', 'private/users'),
        'ANIME_JSON_CLOUD': env.get('ANIME_JSON_CLOUD', 'data/anime.json'),
        'GCS_BUCKET': env.get('GCS_BUCKET'),
        'ADMIN_BOOT_ENABLE': b('ADMIN_BOOT_ENABLE', False),
        'ADMIN_EMAIL': env.get('ADMIN_EMAIL','admin@localanim'),
        'ADMIN_BOOT_PASSWORD': env.get('ADMIN_BOOT_PASSWORD','12345'),
        # SMTP
        'SMTP_HOST': env.get('SMTP_HOST','smtp.gmail.com'),
        'SMTP_PORT': i('SMTP_PORT',587),
        'SMTP_USER': env.get('SMTP_USER'),
        'SMTP_PASS': env.get('SMTP_PASS'),
        'SMTP_FROM': env.get('SMTP_FROM', env.get('SMTP_USER','AnimeCloud <noreply@example.com>')),
        'SMTP_STARTTLS': b('SMTP_STARTTLS', True),
        'SMTP_DEBUG': i('SMTP_DEBUG', 0),
        # DEV
        'DEV_ECHO_VERIFICATION_LINK': b('DEV_ECHO_VERIFICATION_LINK', False),
        'DEV_SAVE_LAST_EMAIL': b('DEV_SAVE_LAST_EMAIL', False),
        'DEBUG_AUTH': b('DEBUG_AUTH', False),
    }
    return cfg

ROOT = os.getcwd()
ENV_PATH = os.path.join(ROOT, '.env')
CFG = load_env(ENV_PATH)

# paths for local "dir" storage
USERS_DIR = os.path.join(ROOT, CFG['USERS_JSON_CLOUD'].lstrip('/'))
os.makedirs(USERS_DIR, exist_ok=True)

LAST_EMAIL_PATH = '/var/tmp/animecloud_last_email.eml'

# ----------
# Utilities
# ----------
def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'

def json_response(handler, status, payload, ctype='application/json'):
    data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    handler.send_response(status)
    handler.send_header('Content-Type', ctype)
    handler.send_header('Access-Control-Allow-Origin', '*')
    handler.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
    handler.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    handler.send_header('Content-Length', str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)

def read_json(handler):
    length = int(handler.headers.get('Content-Length', '0') or '0')
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        return json.loads(raw.decode('utf-8'))
    except Exception:
        return {}

def urlsafe_email_filename(email: str) -> str:
    # keep '@' and '.' – they are valid on Linux – just remove path separators
    safe = email.strip().lower().replace('/', '_').replace('\\','_')
    return safe + '.json'

def user_file_path(email: str) -> str:
    return os.path.join(USERS_DIR, urlsafe_email_filename(email))

# ---- Password hashing (pbkdf2_sha256) ----
def hash_password(password: str, iterations: int = 200_000) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=32)
    return 'pbkdf2_sha256$%d$%s$%s' % (
        iterations,
        base64.urlsafe_b64encode(salt).decode().rstrip('='),
        base64.urlsafe_b64encode(dk).decode().rstrip('=')
    )

def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iter_s, salt_b64, hash_b64 = encoded.split('$', 3)
        assert scheme == 'pbkdf2_sha256'
        iterations = int(iter_s)
        salt = base64.urlsafe_b64decode(salt_b64 + '==')
        expected = base64.urlsafe_b64decode(hash_b64 + '==')
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception as e:
        return False

# ---------------
# User storage IO
# ---------------
class UserStore:
    def __init__(self, mode='dir'):
        self.mode = mode
        if self.mode == 'gcs':
            try:
                from google.cloud import storage  # type: ignore
            except Exception as e:
                print('[WARN] google-cloud-storage not available, falling back to DIR mode.')
                self.mode = 'dir'
            else:
                self._gcs = storage.Client()
                self._bucket = self._gcs.bucket(CFG['GCS_BUCKET'])
                print('[INFO] Using GCS bucket:', CFG['GCS_BUCKET'])
        if self.mode == 'dir':
            os.makedirs(USERS_DIR, exist_ok=True)
            print('[INFO] Using DIR storage at', USERS_DIR)

    def _gcs_blob(self, email):
        name = CFG['USERS_JSON_CLOUD'].rstrip('/') + '/' + urlsafe_email_filename(email)
        return self._bucket.blob(name)

    def exists(self, email):
        if self.mode == 'dir':
            return os.path.exists(user_file_path(email))
        b = self._gcs_blob(email)
        return b.exists()

    def read(self, email):
        if self.mode == 'dir':
            p = user_file_path(email)
            if not os.path.exists(p): 
                return None
            with open(p, 'r', encoding='utf-8') as f:
                return json.load(f)
        # gcs
        b = self._gcs_blob(email)
        if not b.exists(): 
            return None
        data = b.download_as_text(encoding='utf-8')
        return json.loads(data)

    def write(self, email, doc):
        if self.mode == 'dir':
            p = user_file_path(email)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            tmp = p + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(doc, f, ensure_ascii=False, indent=2)
            os.replace(tmp, p)
            return
        # gcs
        b = self._gcs_blob(email)
        b.upload_from_string(json.dumps(doc, ensure_ascii=False), content_type='application/json')

    def list_all(self):
        if self.mode == 'dir':
            for fname in os.listdir(USERS_DIR):
                if not fname.endswith('.json'): 
                    continue
                path = os.path.join(USERS_DIR, fname)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        yield json.load(f)
                except Exception:
                    continue
        else:
            prefix = CFG['USERS_JSON_CLOUD'].rstrip('/') + '/'
            for blob in self._bucket.list_blobs(prefix=prefix):
                try:
                    data = blob.download_as_text(encoding='utf-8')
                    yield json.loads(data)
                except Exception:
                    continue

STORE = UserStore(CFG['USERS_STORAGE_MODE'])

# --------------
# Email sending
# --------------
def send_email(to_email: str, subject: str, html: str, text: str):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = CFG['SMTP_FROM']
    msg['To'] = to_email
    msg.attach(MIMEText(text, 'plain', 'utf-8'))
    msg.attach(MIMEText(html, 'html', 'utf-8'))

    if CFG['DEV_SAVE_LAST_EMAIL']:
        try:
            with open(LAST_EMAIL_PATH, 'wb') as f:
                f.write(msg.as_bytes())
            print('[DEV] Saved last email to', LAST_EMAIL_PATH)
        except Exception as e:
            print('[DEV] Failed saving last email:', e)

    if not CFG['SMTP_HOST']:
        print('[WARN] SMTP_HOST not set; skipping real send.')
        return

    with smtplib.SMTP(CFG['SMTP_HOST'], CFG['SMTP_PORT']) as server:
        if CFG['SMTP_DEBUG']:
            server.set_debuglevel(1)
        if CFG['SMTP_STARTTLS']:
            server.starttls()
        if CFG['SMTP_USER'] and CFG['SMTP_PASS']:
            server.login(CFG['SMTP_USER'], CFG['SMTP_PASS'])
        server.sendmail(CFG['SMTP_FROM'], [to_email], msg.as_string())

def send_verification_email(to_email: str, token: str):
    link = f"http://{HOST_AND_PORT}/auth/verify?email={urllib.parse.quote(to_email)}&token={urllib.parse.quote(token)}"
    if CFG['DEV_ECHO_VERIFICATION_LINK']:
        print('[DEV] Verification link:', link)
    html = f"""
    <div style="font-family:sans-serif;line-height:1.5">
      <h2>Vítej v AnimeCloud 👋</h2>
      <p>Potvrď prosím svůj e-mail kliknutím na tlačítko:</p>
      <p><a href="{link}" style="background:#7c5cff;color:#fff;padding:10px 14px;border-radius:8px;text-decoration:none">Ověřit účet</a></p>
      <p>Pokud tlačítko nefunguje, použij tento odkaz: <a href="{link}">{link}</a></p>
    </div>
    """.strip()
    text = f"Ověř svůj účet: {link}"
    send_email(to_email, "Ověření účtu • AnimeCloud", html, text)

# --------------
# Bootstrap admin
# --------------
def bootstrap_admin():
    if not CFG['ADMIN_BOOT_ENABLE']:
        return
    email = CFG['ADMIN_EMAIL'].strip().lower()
    if STORE.exists(email):
        print('[BOOT] Admin already exists -> skipping.')
        return
    doc = {
        'email': email,
        'display_name': 'Admin',
        'role': 'admin',
        'created': now_iso(),
        'verified': True,
        'password': hash_password(CFG['ADMIN_BOOT_PASSWORD']),
    }
    STORE.write(email, doc)
    print('[BOOT] Admin created:', email)

# host:port detection for links
def compute_host_and_port():
    host = os.environ.get('PUBLIC_HOST')  # you can set PUBLIC_HOST if behind proxy
    if host:
        return host
    return f"{SERVER_HOST}:{CFG['PORT']}"

# -----------------------
# HTTP request handler
# -----------------------
class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # CORS
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    # ---- Helpers ----
    def _parse_json(self):
        return read_json(self)

    # ---- Routes ----
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        q = urllib.parse.parse_qs(parsed.query)

        if path == '/auth/verify':
            email = (q.get('email', [''])[0]).strip().lower()
            token = (q.get('token', [''])[0]).strip()
            doc = STORE.read(email)
            if not doc:
                return json_response(self, 400, {'ok': False, 'error': 'not_found'})
            vt = doc.get('verify_token')
            if not vt or token != vt:
                return json_response(self, 400, {'ok': False, 'error': 'bad_token'})
            # success -> mark verified, delete token
            doc['verified'] = True
            doc.pop('verify_token', None)
            doc.pop('verify_expires', None)
            STORE.write(email, doc)
            # small HTML with auto-redirect
            html = """
            <!doctype html><meta charset="utf-8">
            <title>Účet ověřen</title>
            <style>body{font-family:system-ui;margin:40px;}</style>
            <h2>Účet ověřen ✅</h2>
            <p>Nyní se můžete přihlásit.</p>
            <script>setTimeout(()=>{ location.href='/login.html'; }, 1000);</script>
            """
            data = html.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path == '/stats':
            # very small stats
            users = list(STORE.list_all())
            total = len(users)
            verified = sum(1 for u in users if u.get('verified'))
            resp = {'users_total': total, 'users_verified': verified}
            return json_response(self, 200, resp)

        # dev helper to fetch last sent email
        if path == '/dev/last-email' and CFG['DEBUG_AUTH']:
            if os.path.exists(LAST_EMAIL_PATH):
                with open(LAST_EMAIL_PATH,'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type','message/rfc822')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            return json_response(self, 404, {'ok': False, 'error':'no_last_email'})

        # default -> static files
        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == '/auth/register':
            body = self._parse_json()
            email = (body.get('email','') or '').strip().lower()
            password = (body.get('password','') or '')
            password2 = (body.get('password2','') or '')
            display_name = (body.get('name','') or '').strip() or email.split('@')[0]

            if not email or not password:
                return json_response(self, 400, {'ok': False, 'error': 'missing_fields'})
            if password != password2:
                return json_response(self, 400, {'ok': False, 'error': 'password_mismatch'})
            if STORE.exists(email):
                return json_response(self, 409, {'ok': False, 'error': 'already_exists'})

            doc = {
                'email': email,
                'display_name': display_name,
                'role': 'user',
                'created': now_iso(),
                'verified': False,
                'password': hash_password(password),
            }
            # token valid 48h
            token = secrets.token_urlsafe(32)
            doc['verify_token'] = token
            doc['verify_expires'] = int(time.time()) + 48*3600

            STORE.write(email, doc)
            try:
                send_verification_email(email, token)
            except Exception as e:
                print('[EMAIL] Send failed:', e)

            return json_response(self, 200, {'ok': True})

        if path == '/auth/login':
            body = self._parse_json()
            email = (body.get('email','') or '').strip().lower()
            password = (body.get('password','') or '')
            if not email or not password:
                return json_response(self, 400, {'ok': False, 'error': 'missing_fields'})
            doc = STORE.read(email)
            if not doc:
                return json_response(self, 403, {'ok': False, 'error': 'bad_credentials', 'reason':'user_not_found' if CFG['DEBUG_AUTH'] else 'bad'})
            if not doc.get('verified'):
                return json_response(self, 403, {'ok': False, 'error': 'not_verified'})
            ok = verify_password(password, doc.get('password',''))
            if not ok:
                return json_response(self, 403, {'ok': False, 'error': 'bad_credentials'})
            # Success -> create a very simple pseudo-session token (do not use in prod!)
            sess = secrets.token_urlsafe(24)
            doc['last_login'] = now_iso()
            doc['session'] = sess
            STORE.write(email, doc)
            return json_response(self, 200, {'ok': True, 'session': sess, 'email': email})

        return json_response(self, 404, {'ok': False, 'error': 'not_found'})

# -----------------------
# Server bootstrap
# -----------------------
SERVER_HOST = '0.0.0.0'
HOST_AND_PORT = None  # filled after server starts

def run():
    global HOST_AND_PORT
    httpd = HTTPServer((SERVER_HOST, CFG['PORT']), Handler)
    HOST_AND_PORT = compute_host_and_port()
    print(f"[INFO] AnimeCloud server listening on http://{SERVER_HOST}:{CFG['PORT']} (public host: {HOST_AND_PORT})")
    bootstrap_admin()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    run()
