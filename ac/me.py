# ac/me.py
import json, datetime
from urllib.parse import urlparse, parse_qs
from google.cloud import storage
from . import settings
from . import auth  # sdílený parse_body()

BUCKET_NAME  = settings.GCS_BUCKET or "anime-cloud"
USERS_PREFIX = settings.USERS_JSON_CLOUD or "private/users"
SLUGS_PREFIX = "private/slugs"  # volitelná cache: <slug>.json -> {"email":"..."}

_storage = None
def bucket():
    global _storage
    if _storage is None:
        _storage = storage.Client()
    return _storage.bucket(BUCKET_NAME)

def _json(handler, code, obj):
    payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type","application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)

def _load_blob_text(path: str):
    b = bucket().blob(path)
    if not b.exists(): return None
    return b.download_as_text(encoding="utf-8")

def _save_blob_json(path: str, data_obj: dict):
    b = bucket().blob(path)
    data = json.dumps(data_obj, ensure_ascii=False, separators=(",",":"))
    b.upload_from_string(data, content_type="application/json; charset=utf-8")
    return True

# ---------- Helpers: cesty / slug / IO ----------

def _user_path(email: str) -> str:
    """Kanonická cesta: private/users/<email>.json"""
    return f"{USERS_PREFIX}/{email}.json"

def _sanitize_slug(s: str) -> str:
    s = (s or "").strip().lower()
    out = []
    prev_dash = False
    for ch in s:
        if "a" <= ch <= "z" or "0" <= ch <= "9":
            out.append(ch); prev_dash = False
        else:
            if not prev_dash:
                out.append("-"); prev_dash = True
    slug = "".join(out).strip("-")
    return slug or "user"

def _read_user(email: str) -> dict | None:
    """Načti uživatele z kanonické cesty <email>.json (již bez fallbacků)."""
    txt = _load_blob_text(_user_path(email))
    if not txt: return None
    try:
        doc = json.loads(txt)
    except Exception:
        return None
    # Transformace do jednotné "me" podoby pro FE
    me = {
        "email":        doc.get("email")     or email,
        "slug":         doc.get("slug")      or (doc.get("name") or email.split("@")[0]),
        "display_name": doc.get("display_name") or doc.get("nickname") or doc.get("name") or email,
        "avatar_url":   doc.get("avatar_url")   or doc.get("avatar") or "",
        "joined_at":    doc.get("joined_at")    or doc.get("created_at"),
        "created_at":   doc.get("created_at")   or doc.get("joined_at"),
        "visibility":   (doc.get("visibility") or "private").lower(),
        "titles":       doc.get("titles") or ([] if not doc.get("secondaryTitle") else [doc["secondaryTitle"]]),
        "stats":        doc.get("stats") or {"uploads": 0, "favorites": 0},
    }
    if not me["created_at"] and me["joined_at"]:
        me["created_at"] = me["joined_at"]
    if not me["joined_at"] and me["created_at"]:
        me["joined_at"] = me["created_at"]
    return me

def _save_slug_map(slug: str, email: str):
    if not slug: return
    path = f"{SLUGS_PREFIX}/{slug}.json"
    try:
        _save_blob_json(path, {"email": email})
    except Exception:
        # volitelné; když selže, vyhledávání si poradí přes list_blobs
        pass

def _write_user(email: str, patch: dict) -> dict:
    """Merge a zápis na kanonickou cestu <email>.json. Slug je stabilní."""
    # načti existující dokument (pokud existuje)
    base = {}
    txt = _load_blob_text(_user_path(email))
    if txt:
        try: base = json.loads(txt)
        except Exception: base = {}

    # displej jméno
    if "display_name" in patch:
        base["display_name"] = patch["display_name"]
        # kompatibilita se starším FE
        base["nickname"] = patch["display_name"]
        base["name"] = base.get("name") or patch["display_name"]

    # avatar
    if "avatar_url" in patch:
        base["avatar_url"] = patch["avatar_url"]
        base["avatar"] = patch["avatar_url"]

    # tituly
    if "titles" in patch and isinstance(patch["titles"], list):
        base["titles"] = patch["titles"]
        base["secondaryTitle"] = patch["titles"][0] if patch["titles"] else None

    # viditelnost
    if "visibility" in patch and patch["visibility"]:
        base["visibility"] = patch["visibility"]

    # základní pole
    now_iso = datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
    base["email"]      = email
    base["created_at"] = base.get("created_at") or now_iso
    base["joined_at"]  = base.get("joined_at")  or base["created_at"]
    base["stats"]      = base.get("stats") or {"uploads": 0, "favorites": 0}
    base["visibility"] = (base.get("visibility") or "private").lower()

    # stabilní slug – nastav jen když chybí
    if not base.get("slug"):
        base["slug"] = _sanitize_slug(email.split("@")[0])

    _save_blob_json(_user_path(email), base)
    _save_slug_map(base.get("slug"), email)

    return _read_user(email)

def find_by_slug(slug: str) -> dict | None:
    """Najdi uživatele podle slugu (nejdřív mapou, pak prohledáním users/)."""
    slug = (slug or "").strip().lower()
    # 1) mapa
    txt = _load_blob_text(f"{SLUGS_PREFIX}/{slug}.json")
    email = None
    if txt:
        try:
            email = (json.loads(txt) or {}).get("email")
        except Exception:
            email = None
    # 2) průchod uživateli, když mapa není
    if not email:
        bkt = bucket()
        for blob in bkt.list_blobs(prefix=f"{USERS_PREFIX}/"):
            if not blob.name.endswith(".json"):  # jen json uživatele
                continue
            try:
                doc = json.loads(blob.download_as_text(encoding="utf-8"))
            except Exception:
                continue
            s = (doc.get("slug") or doc.get("name") or (doc.get("email","").split("@")[0] or "")).lower()
            if s == slug:
                email = doc.get("email")
                break
    if not email:
        return None
    return _read_user(email)

# ---------- Routery volané ze server.py ----------

def route_get(handler, path) -> bool:
    # /api/me?email=...
    if path.startswith("/api/me"):
        q = parse_qs(urlparse(handler.path).query)
        email = (q.get("email") or [None])[0]
        if not email:
            return _json(handler, 401, {"ok": False, "error": "unauthorized"})
        me = _read_user(email)
        if not me:
            return _json(handler, 404, {"ok": False, "error": "user not found"})
        return _json(handler, 200, {"ok": True, "me": me})

    # /api/profile/<slug_or_email>
    if path.startswith("/api/profile/"):
        slug_or_email = path.split("/api/profile/",1)[1]
        if "@" in slug_or_email:
            me = _read_user(slug_or_email)
        else:
            me = find_by_slug(slug_or_email)
        if not me:
            return _json(handler, 404, {"ok": False, "error":"user not found"})
        out = {
            "slug":        me["slug"],
            "display_name":me["display_name"],
            "avatar_url":  me["avatar_url"],
            "joined_at":   me["joined_at"],
            "titles":      me.get("titles", []),
            "visibility":  me.get("visibility","private"),
        }
        return _json(handler, 200, {"ok": True, "profile": out})

    return False

def route_post(handler, path) -> bool:
    # /api/me/update?email=...
    if path.startswith("/api/me/update"):
        q = parse_qs(urlparse(handler.path).query)
        email = (q.get("email") or [None])[0]
        if not email:
            return _json(handler, 401, {"ok": False, "error": "unauthorized"})
        body = auth.parse_body(handler.rfile.read(int(handler.headers.get("Content-Length") or 0)),
                               (handler.headers.get("Content-Type") or ""))
        patch = {}
        if body is not None:
            if "display_name" in body: patch["display_name"] = body["display_name"]
            if "avatar_url"   in body: patch["avatar_url"]   = body["avatar_url"]
            if isinstance(body.get("titles"), list): patch["titles"] = body["titles"]
            if body.get("visibility"): patch["visibility"] = body["visibility"]
        me = _write_user(email, patch)
        return _json(handler, 200, {"ok": True, "me": me})

    # /api/me/visibility?email=...
    if path.startswith("/api/me/visibility"):
        q = parse_qs(urlparse(handler.path).query)
        email = (q.get("email") or [None])[0]
        if not email:
            return _json(handler, 401, {"ok": False, "error": "unauthorized"})
        body = auth.parse_body(handler.rfile.read(int(handler.headers.get("Content-Length") or 0)),
                               (handler.headers.get("Content-Type") or ""))
        vis = ((body or {}).get("visibility") or "").lower()
        if vis not in ("public","private","link"):
            return _json(handler, 400, {"ok": False, "error": "invalid visibility"})
        me = _write_user(email, {"visibility": vis})
        return _json(handler, 200, {"ok": True, "me": me})

    return False
