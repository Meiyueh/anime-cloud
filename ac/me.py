# ac/me.py
import os, json, re, sys
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

# === Konfigurace ===
USERS_PREFIX = os.getenv("USERS_JSON_CLOUD", "private/users").strip("/")

# GCS klient (lazy)
_GCS_CLIENT = None
_GCS_BUCKET = None
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET", "").strip()

def _get_bucket():
    global _GCS_CLIENT, _GCS_BUCKET
    if not GCS_BUCKET_NAME:
        return None
    if _GCS_BUCKET is not None:
        return _GCS_BUCKET
    try:
        from google.cloud import storage
        _GCS_CLIENT = storage.Client()
        _GCS_BUCKET = _GCS_CLIENT.bucket(GCS_BUCKET_NAME)
        return _GCS_BUCKET
    except Exception as e:
        print(f"[ME] WARN: GCS unavailable: {e}", file=sys.stderr)
        return None

# === Utility: cesty/serializace ===
def _email_key(email:str) -> str:
    email = (email or "").strip().lower()
    if not email: return ""
    if not email.endswith(".json"): email += ".json"
    return f"{USERS_PREFIX}/{email}"

def _gcs_read_json(path:str):
    b = _get_bucket()
    if not b: return None
    blob = b.blob(path)
    if not blob.exists(): return None
    try:
        data = blob.download_as_text(encoding="utf-8")
        return json.loads(data), blob
    except Exception as e:
        print(f"[ME] WARN: read json {path} failed: {e}", file=sys.stderr)
        return None

def _gcs_write_json(path: str, data: dict):
    b = _get_bucket()
    payload = json.dumps(data, ensure_ascii=False, indent=2)  # <- STRING
    if b:
        try:
            blob = b.blob(path)
            # ať se nelepí cache
            blob.cache_control = "public, max-age=0, no-cache"
            # KLÍČOVÉ: předej content_type do uploadu (media část)
            blob.upload_from_string(payload, content_type="application/json; charset=utf-8")
            try:
                blob.patch()  # uloží cache_control
            except Exception:
                pass
            return True
        except Exception as e:
            print(f"[ME] ERROR: write json {path} failed: {e}", file=sys.stderr)
            return False
    # lokální fallback
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    dst  = os.path.join(root, path)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "w", encoding="utf-8") as f:
        f.write(payload)
    return True

def _local_read_json(path:str):
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    p = os.path.join(root, path)
    if not os.path.exists(p): return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f), None
    except Exception as e:
        print(f"[ME] WARN: local read {p} failed: {e}", file=sys.stderr)
        return None

def _local_mtime_iso(path:str):
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    p = os.path.join(root, path)
    try:
        ts = os.path.getmtime(p)
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00","Z")
    except Exception:
        return None

def _blob_updated_iso(blob):
    try:
        # blob.updated je datetime s TZ
        dt = blob.updated
        if not dt: return None
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00","Z")
    except Exception:
        return None

# === Normalizace / migrace ===
def _normalize_user(email:str, data:dict, created_iso:str|None) -> tuple[dict,bool]:
    changed=False
    email = (email or data.get("email") or "").lower()

    if not data.get("slug"):
        data["slug"] = (email.split("@")[0] if email else (data.get("name") or "")).lower()
        changed=True
    if not data.get("display_name"):
        data["display_name"] = data.get("name") or email
        changed=True
    if not data.get("visibility"):
        data["visibility"] = "private"
        changed=True
    if not isinstance(data.get("stats"), dict):
        data["stats"] = {"uploads":0,"favorites":0}
        changed=True
    if not (data.get("joined_at") or data.get("created_at")) and created_iso:
        data["joined_at"] = created_iso
        data["created_at"] = created_iso
        changed=True
    if email and data.get("email") != email:
        data["email"] = email
        changed=True
    # sjednocení titles
    if not isinstance(data.get("titles"), list) and isinstance(data.get("title"), str):
        data["titles"] = [data["title"]]
        changed=True
    return data, changed

# === Lookupy ===
def _load_user_by_email(email:str):
    key = _email_key(email)
    # GCS
    g = _gcs_read_json(key)
    if g:
        data, blob = g
        created_iso = _blob_updated_iso(blob)
        data, changed = _normalize_user(email, data, created_iso)
        if changed:
            _gcs_write_json(key, data)
        return data

    # lokální fallback
    l = _local_read_json(key)
    if l:
        data, _ = l
        created_iso = _local_mtime_iso(key)
        data, changed = _normalize_user(email, data, created_iso)
        if changed:
            _gcs_write_json(key, data) if _get_bucket() else _local_write_json(key, data)
        return data
    return None

def _local_write_json(path:str, data:dict):
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    dst  = os.path.join(root, path)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def _find_user_by_slug(slug:str):
    """Najde uživatele podle slugu (prefix před @ v názvu souboru) – GCS i lokálně."""
    slug = (slug or "").strip().lower()
    if not slug: return None, None

    # 1) GCS – projít objekty pod prefixem
    b = _get_bucket()
    prefix = USERS_PREFIX + "/"
    if b:
        for blob in b.list_blobs(prefix=prefix):
            name = blob.name  # e.g. private/users/user@example.com.json
            if not name.lower().endswith(".json"): continue
            base = name.split("/")[-1][:-5].lower()
            if base.split("@")[0] == slug:
                # máme kandidáta
                g = _gcs_read_json(name)
                data = g[0] if g else {}
                created_iso = _blob_updated_iso(blob)
                data, changed = _normalize_user(base, data, created_iso)
                if changed:
                    _gcs_write_json(name, data)
                return base, data
        # 2) JSON pole "slug"
        for blob in b.list_blobs(prefix=prefix):
            if not blob.name.lower().endswith(".json"): continue
            g = _gcs_read_json(blob.name)
            if not g: continue
            data, blob2 = g
            if (data.get("slug") or "").strip().lower() == slug:
                base = blob.name.split("/")[-1][:-5].lower()
                created_iso = _blob_updated_iso(blob)
                data, changed = _normalize_user(base, data, created_iso)
                if changed:
                    _gcs_write_json(blob.name, data)
                return base, data

    # Lokální fallback – projít soubory
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", USERS_PREFIX))
    if os.path.isdir(root):
        for fn in os.listdir(root):
            if not fn.lower().endswith(".json"): continue
            base = fn[:-5].lower()
            if base.split("@")[0] == slug:
                path = os.path.join(root, fn)
                try: data = json.load(open(path, encoding="utf-8"))
                except: data = {}
                created_iso = _local_mtime_iso(f"{USERS_PREFIX}/{fn}")
                data, changed = _normalize_user(base, data, created_iso)
                if changed:
                    _local_write_json(f"{USERS_PREFIX}/{fn}", data)
                return base, data
        # JSON pole "slug"
        for fn in os.listdir(root):
            if not fn.lower().endswith(".json"): continue
            path = os.path.join(root, fn)
            try: data = json.load(open(path, encoding="utf-8"))
            except: data = {}
            if (data.get("slug") or "").strip().lower() == slug:
                base = fn[:-5].lower()
                created_iso = _local_mtime_iso(f"{USERS_PREFIX}/{fn}")
                data, changed = _normalize_user(base, data, created_iso)
                if changed:
                    _local_write_json(f"{USERS_PREFIX}/{fn}", data)
                return base, data

    return None, None

# === Veřejný tvar ===
def _public_me(email, data):
    slug = data.get("slug") or (email.split("@")[0] if email else "")
    display = data.get("display_name") or data.get("nickname") or data.get("name") or email
    avatar = data.get("avatar_url") or data.get("avatar") or ""
    joined = data.get("joined_at") or data.get("created_at")
    return {
        "email": email,
        "slug": slug,
        "display_name": display,
        "avatar_url": avatar,
        "joined_at": joined,
        "created_at": data.get("created_at") or joined,
        "visibility": data.get("visibility","private"),
        "titles": data.get("titles") or ([data["title"]] if data.get("title") else []),
        "stats": data.get("stats") or {"uploads": 0, "favorites": 0},
    }

# === HTTP handlery ===
def _extract_identity(handler):
    auth = handler.headers.get("Authorization") or ""
    m = re.match(r"Bearer\s+(.+)", auth, flags=re.I)
    if m:
        token = m.group(1).strip()
        if "@" in token:
            return token, token.split("@")[0]
        email, data = _find_user_by_slug(token)
        if email: return email, token

    xemail = handler.headers.get("X-Auth-Email") or ""
    if xemail:
        return xemail, xemail.split("@")[0] if "@" in xemail else xemail

    return None, None

def handle_me_get(handler, parsed):
    email, _ = _extract_identity(handler)
    if not email:
        qs = parse_qs(parsed.query or "")
        email = (qs.get("email") or [None])[0]

    if not email:
        return handler._json(401, {"ok": False, "error": "unauthorized"})

    data = _load_user_by_email(email) or {}
    return handler._json(200, {"ok": True, "me": _public_me(email, data)})

def handle_me_update(handler, parsed):
    body = handler._read_body() or {}
    email, _ = _extract_identity(handler)
    if not email:
        qs = parse_qs(parsed.query or "")
        email = (qs.get("email") or [None])[0]

    if not email:
        return handler._json(401, {"ok": False, "error": "unauthorized"})

    key = _email_key(email)
    # načti stávající
    current = _load_user_by_email(email) or {"email": email.lower()}
    # patche
    dn = (body.get("display_name") or "").strip()
    if dn: current["display_name"] = dn
    if body.get("avatar_url"): current["avatar_url"] = body["avatar_url"]
    if isinstance(body.get("titles"), list): current["titles"] = body["titles"]
    if not current.get("created_at") and not current.get("joined_at"):
        now = datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
        current["created_at"] = now
        current["joined_at"]  = now

    _gcs_write_json(key, current)
    return handler._json(200, {"ok": True, "me": _public_me(email, current)})

def handle_profile_visibility(handler, parsed):
    body = handler._read_body() or {}
    email, _ = _extract_identity(handler)
    if not email:
        qs = parse_qs(parsed.query or "")
        email = (qs.get("email") or [None])[0]
    if not email:
        return handler._json(401, {"ok": False, "error": "unauthorized"})

    key = _email_key(email)
    data = _load_user_by_email(email) or {"email": email.lower()}
    vis = (body.get("visibility") or "private").lower()
    if vis not in ("public","private","link"): vis = "private"
    data["visibility"] = vis
    _gcs_write_json(key, data)
    return handler._json(200, {"ok": True, "visibility": vis})

