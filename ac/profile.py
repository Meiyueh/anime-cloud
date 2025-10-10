# ac/profile.py
import os, json, sys, html
from datetime import datetime, timezone
from urllib.parse import unquote

USERS_PREFIX = os.getenv("USERS_JSON_CLOUD", "private/users").strip("/")
PROFILE_HTML = os.getenv("AC_PROFILE_HTML", "profile.html").strip()

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
        print(f"[PROFILE] WARN: GCS unavailable: {e}", file=sys.stderr)
        return None

def _blob_updated_iso(blob):
    try:
        dt = blob.updated
        if not dt: return None
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00","Z")
    except Exception:
        return None

def _read_json_gcs(path):
    b = _get_bucket()
    if not b: return None
    blob = b.blob(path)
    if not blob.exists(): return None
    try:
        data = blob.download_as_text(encoding="utf-8")
        return json.loads(data), blob
    except Exception as e:
        print(f"[PROFILE] WARN: read json {path} failed: {e}", file=sys.stderr)
        return None

def _write_json_gcs(path, data: dict):
    b = _get_bucket()
    payload = json.dumps(data, ensure_ascii=False, indent=2)  # <- STRING
    if b:
        try:
            blob = b.blob(path)
            blob.cache_control = "public, max-age=0, no-cache"
            # KLÍČOVÉ: content_type přímo v uploadu
            blob.upload_from_string(payload, content_type="application/json; charset=utf-8")
            try:
                blob.patch()
            except Exception:
                pass
            return True
        except Exception as e:
            print(f"[PROFILE] ERROR: write json {path} failed: {e}", file=sys.stderr)
            return False
    # fallback local
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    dst  = os.path.join(root, path)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "w", encoding="utf-8") as f:
        f.write(payload)
    return True

def _normalize_for_profile(email:str, data:dict, created_iso:str|None) -> tuple[dict,bool]:
    changed=False
    email = (email or data.get("email") or "").lower()
    if not data.get("slug"):
        data["slug"] = (email.split("@")[0] if email else (data.get("name") or "")).lower()
        changed=True
    if not data.get("display_name"):
        data["display_name"] = data.get("name") or email
        changed=True
    if not data.get("visibility"):
        data["visibility"] = "public"  # veřejné zobrazení
        changed=True
    if not isinstance(data.get("titles"), list) and isinstance(data.get("title"), str):
        data["titles"] = [data["title"]]
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
    return data, changed

def _find_by_email(email_key:str):
    key = email_key.strip().lower()
    if not key.endswith(".json"): key += ".json"
    path = f"{USERS_PREFIX}/{key}"
    # GCS
    g = _read_json_gcs(path)
    if g:
        data, blob = g
        data, ch = _normalize_for_profile(email_key.lower(), data, _blob_updated_iso(blob))
        if ch: _write_json_gcs(path, data)
        return path, data
    # fallback local
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    p = os.path.join(root, path)
    if os.path.exists(p):
        try: data = json.load(open(p, encoding="utf-8"))
        except: data = {}
        from os.path import getmtime
        try:
            created_iso = datetime.fromtimestamp(getmtime(p), tz=timezone.utc).isoformat().replace("+00:00","Z")
        except:
            created_iso = None
        data, ch = _normalize_for_profile(email_key.lower(), data, created_iso)
        if ch:
            with open(p, "w", encoding="utf-8") as f: json.dump(data, f, ensure_ascii=False, indent=2)
        return path, data
    return None, None

def _find_by_slug(slug:str):
    slug = (slug or "").strip().lower()
    if not slug: return None, None
    b = _get_bucket()
    prefix = USERS_PREFIX + "/"

    if b:
        # 1) podle prefixu názvu souboru
        for blob in b.list_blobs(prefix=prefix):
            name = blob.name
            if not name.lower().endswith(".json"): continue
            base = name.split("/")[-1][:-5].lower()  # email
            if base.split("@")[0] == slug:
                g = _read_json_gcs(name)
                data = g[0] if g else {}
                data, ch = _normalize_for_profile(base, data, _blob_updated_iso(blob))
                if ch: _write_json_gcs(name, data)
                return name, data
        # 2) podle JSON pole "slug"
        for blob in b.list_blobs(prefix=prefix):
            name = blob.name
            if not name.lower().endswith(".json"): continue
            g = _read_json_gcs(name)
            if not g: continue
            data, b2 = g
            if (data.get("slug") or "").strip().lower() == slug:
                base = name.split("/")[-1][:-5].lower()
                data, ch = _normalize_for_profile(base, data, _blob_updated_iso(blob))
                if ch: _write_json_gcs(name, data)
                return name, data

    # lokální fallback
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", USERS_PREFIX))
    if os.path.isdir(root):
        # 1) dle názvu
        for fn in os.listdir(root):
            if not fn.lower().endswith(".json"): continue
            base = fn[:-5].lower()
            if base.split("@")[0] == slug:
                p = os.path.join(root, fn)
                try: data = json.load(open(p, encoding="utf-8"))
                except: data = {}
                try:
                    created_iso = datetime.fromtimestamp(os.path.getmtime(p), tz=timezone.utc).isoformat().replace("+00:00","Z")
                except:
                    created_iso = None
                data, ch = _normalize_for_profile(base, data, created_iso)
                if ch: json.dump(data, open(p,"w",encoding="utf-8"), ensure_ascii=False, indent=2)
                return p, data
        # 2) dle JSON slug
        for fn in os.listdir(root):
            if not fn.lower().endswith(".json"): continue
            p = os.path.join(root, fn)
            try: data = json.load(open(p, encoding="utf-8"))
            except: data = {}
            if (data.get("slug") or "").strip().lower() == slug:
                base = fn[:-5].lower()
                try:
                    created_iso = datetime.fromtimestamp(os.path.getmtime(p), tz=timezone.utc).isoformat().replace("+00:00","Z")
                except:
                    created_iso = None
                data, ch = _normalize_for_profile(base, data, created_iso)
                if ch: json.dump(data, open(p,"w",encoding="utf-8"), ensure_ascii=False, indent=2)
                return p, data

    return None, None

# === HTTP ===
def handle_profile_api(handler, parsed):
    raw = parsed.path.split("/api/profile/", 1)[1]
    key = unquote(raw.strip("/").split("/", 1)[0])

    if "@" in key:
        path, data = _find_by_email(key)
    else:
        path, data = _find_by_slug(key)

    print(f"[PROFILE] lookup key='{key}' -> path={path}", file=sys.stderr)

    if not path or data is None:
        return handler._json(404, {"ok": False, "error": "user not found"})

    out = {
        "slug": data.get("slug") or key.split("@")[0],
        "display_name": data.get("display_name") or data.get("nickname") or data.get("name") or (key.split("@")[0] if "@" in key else key),
        "avatar_url": data.get("avatar_url") or data.get("avatar") or "",
        "joined_at": data.get("joined_at") or data.get("created_at"),
        "titles": data.get("titles") or ([data["title"]] if data.get("title") else []),
        "visibility": (data.get("visibility") or "public").lower()
    }
    return handler._json(200, {"ok": True, "profile": out})

def handle_profile_page(handler, parsed):
    slug = unquote(parsed.path.split("/u/", 1)[1].strip("/").split("/", 1)[0])
    try:
        with open(PROFILE_HTML, "r", encoding="utf-8") as f:
            tpl = f.read()
    except FileNotFoundError:
        safe = html.escape(slug)
        return handler._html(
            200,
            f"<!doctype html><meta charset='utf-8'><title>@{safe}</title>"
            f"<h1 style='font-family:sans-serif'>Načítám profil @{safe}…</h1>"
            f"<script>location.href='/api/profile/{safe}'</script>"
        )
    return handler._html(200, tpl.replace("{{SLUG}}", slug))

