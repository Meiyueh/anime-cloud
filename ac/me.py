# ac/me.py
# Jediný zdroj pravdy pro /api/me* a /api/profile/*.
# Všechny profily jsou v GCS: private/users/<email>.json

import json
import datetime
from urllib.parse import urlparse, parse_qs, unquote
from google.cloud import storage

from . import settings
from . import auth  # sdílený parser body

BUCKET_NAME  = settings.GCS_BUCKET or "anime-cloud"
USERS_PREFIX = settings.USERS_JSON_CLOUD or "private/users"

_storage = None


def bucket():
    """GCS bucket client (lazy)."""
    global _storage
    if _storage is None:
        _storage = storage.Client()
    return _storage.bucket(BUCKET_NAME)


def _json(handler, code, obj):
    payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def _load_blob_text(path: str):
    b = bucket().blob(path)
    if not b.exists():
        return None
    return b.download_as_text(encoding="utf-8")


def _save_blob_json(path: str, data_obj: dict) -> bool:
    b = bucket().blob(path)
    data = json.dumps(data_obj, ensure_ascii=False, separators=(",", ":"))
    b.upload_from_string(data, content_type="application/json; charset=utf-8")
    return True


# ---------- Jednotná cesta: private/users/<email>.json ----------

def _user_path(email: str) -> str:
    """Kanonic­ká cesta k JSON profilu."""
    return f"{USERS_PREFIX}/{email}.json"


def _load_user_raw(email: str) -> str | None:
    """Načti obsah profilu (nejdřív <email>.json, případně legacy <email>)."""
    txt = _load_blob_text(_user_path(email))
    if txt is not None:
        return txt
    legacy = f"{USERS_PREFIX}/{email}"  # starý tvar bez přípony
    return _load_blob_text(legacy)


# ---------- Transformace starého schématu -> 'me' pohled ----------

def _read_user(email: str) -> dict | None:
    txt = _load_user_raw(email)
    if not txt:
        return None
    try:
        doc = json.loads(txt)
    except Exception:
        return None

    me = {
        "email":        doc.get("email") or email,
        "slug":         doc.get("slug") or (doc.get("name") or email.split("@")[0]),
        "display_name": doc.get("display_name") or doc.get("nickname") or doc.get("name") or email,
        "avatar_url":   doc.get("avatar_url") or doc.get("avatar") or "",
        "joined_at":    doc.get("joined_at") or doc.get("created_at"),
        "created_at":   doc.get("created_at") or doc.get("joined_at"),
        "visibility":   (doc.get("visibility") or "private").lower(),
        "titles":       doc.get("titles") or ([] if not doc.get("secondaryTitle") else [doc["secondaryTitle"]]),
        "stats":        doc.get("stats") or {"uploads": 0, "favorites": 0},
    }

    # doplň chybějící datumy
    if not me["created_at"] and me["joined_at"]:
        me["created_at"] = me["joined_at"]
    if not me["joined_at"] and me["created_at"]:
        me["joined_at"] = me["created_at"]

    return me


def _write_user(email: str, patch: dict) -> dict:
    """Merge patch do uživatele a ulož do <email>.json. Legacy bez přípony uklidí."""
    txt = _load_user_raw(email)
    base = {}
    if txt:
        try:
            base = json.loads(txt)
        except Exception:
            base = {}

    # ---- merge změn ----
    if "display_name" in patch:
        base["display_name"] = patch["display_name"]
        # kompatibilita pro starší FE:
        base["nickname"] = patch["display_name"]
        # pole "name" necháme, ale pokud chybělo, doplníme; slug se z display_name NIKDY nepřepisuje
        base["name"] = base.get("name") or patch["display_name"]

    if "avatar_url" in patch:
        base["avatar_url"] = patch["avatar_url"]
        base["avatar"] = patch["avatar_url"]  # kompatibilita

    if "titles" in patch and isinstance(patch["titles"], list):
        base["titles"] = patch["titles"]
        base["secondaryTitle"] = patch["titles"][0] if patch["titles"] else None

    if "visibility" in patch:
        base["visibility"] = (patch["visibility"] or "private").lower()

    # slug má být stabilní — nikdy ho nepřepisujeme display_name
    if not base.get("slug"):
        base["slug"] = base.get("name") or email.split("@")[0]

    # minimální metadata
    now_iso = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    base["email"] = email
    base["created_at"] = base.get("created_at") or now_iso
    base["joined_at"] = base.get("joined_at") or base["created_at"]
    base["stats"] = base.get("stats") or {"uploads": 0, "favorites": 0}
    base["visibility"] = (base.get("visibility") or "private").lower()

    # zapiš vždy do <email>.json
    _save_blob_json(_user_path(email), base)

    # úklid legacy souboru bez přípony (pokud existoval)
    legacy = f"{USERS_PREFIX}/{email}"
    if legacy != _user_path(email):
        lb = bucket().blob(legacy)
        if lb.exists():
            try:
                lb.delete()
            except Exception:
                pass

    return _read_user(email)


# ---------- Vyhledání podle slugu (bez indexu, čistě scan JSONů) ----------

def find_by_slug(slug: str) -> dict | None:
    bkt = bucket()
    # projdeme jen objekty končící na .json
    for blob in bkt.list_blobs(prefix=f"{USERS_PREFIX}/"):
        name = blob.name or ""
        if not name.endswith(".json"):
            continue
        try:
            doc = json.loads(blob.download_as_text(encoding="utf-8"))
        except Exception:
            continue
        s = doc.get("slug") or doc.get("name") or (doc.get("email", "").split("@")[0])
        if s == slug:
            email = doc.get("email")
            return _read_user(email) if email else None
    return None


# ---------- Router pro server.py ----------

def route_get(handler, path) -> bool:
    """
    Obslouží GET, vrací True pokud odpověděl.
    - /api/me?email=...
    - /api/profile/<slug_or_email>
    """
    # /api/me
    if path == "/api/me":
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
        slug_or_email = unquote(path.split("/api/profile/", 1)[1] or "")
        me_obj = _read_user(slug_or_email) if "@" in slug_or_email else find_by_slug(slug_or_email)
        if not me_obj:
            return _json(handler, 404, {"ok": False, "error": "user not found"})
        out = {
            "slug":        me_obj["slug"],
            "display_name": me_obj["display_name"],
            "avatar_url":  me_obj["avatar_url"],
            "joined_at":   me_obj["joined_at"],
            "titles":      me_obj.get("titles", []),
            "visibility":  me_obj.get("visibility", "private"),
        }
        return _json(handler, 200, {"ok": True, "profile": out})

    return False


def route_post(handler, path) -> bool:
    """
    Obslouží POST, vrací True pokud odpověděl.
    - /api/me/update?email=...
    - /api/me/visibility?email=...   (alias: /api/me/profile_visibility)
    """
    # /api/me/update
    if path.startswith("/api/me/update"):
        q = parse_qs(urlparse(handler.path).query)
        email = (q.get("email") or [None])[0]
        if not email:
            return _json(handler, 401, {"ok": False, "error": "unauthorized"})

        length = int(handler.headers.get("Content-Length") or 0)
        body = auth.parse_body(handler.rfile.read(length), (handler.headers.get("Content-Type") or ""))

        display_name = (body or {}).get("display_name")
        avatar_url   = (body or {}).get("avatar_url")
        titles       = (body or {}).get("titles")
        visibility   = (body or {}).get("visibility")

        patch = {}
        if display_name is not None: patch["display_name"] = display_name
        if avatar_url   is not None: patch["avatar_url"]   = avatar_url
        if isinstance(titles, list): patch["titles"]       = titles
        if visibility:               patch["visibility"]   = visibility

        me_obj = _write_user(email, patch)
        return _json(handler, 200, {"ok": True, "me": me_obj})

    # /api/me/visibility  (a alias /api/me/profile_visibility pro staré FE)
    if path.startswith("/api/me/visibility") or path.startswith("/api/me/profile_visibility"):
        q = parse_qs(urlparse(handler.path).query)
        email = (q.get("email") or [None])[0]
        if not email:
            return _json(handler, 401, {"ok": False, "error": "unauthorized"})

        length = int(handler.headers.get("Content-Length") or 0)
        body = auth.parse_body(handler.rfile.read(length), (handler.headers.get("Content-Type") or ""))

        vis = ((body or {}).get("visibility") or "").lower()
        if vis not in ("public", "private", "link"):
            return _json(handler, 400, {"ok": False, "error": "invalid visibility"})

        me_obj = _write_user(email, {"visibility": vis})
        return _json(handler, 200, {"ok": True, "me": me_obj})

    return False


# ---------- Tenké wrappery (pro kompatibilitu se staršími server.py) ----------

def handle_me_get(handler, _p):
    """Kompatibilita: starý server.py volal me.handle_me_get."""
    return route_get(handler, urlparse(handler.path).path)

def handle_me_update(handler, _p):
    """Kompatibilita: starý server.py volal me.handle_me_update."""
    return route_post(handler, urlparse(handler.path).path)

def handle_profile_visibility(handler, _p):
    """Kompatibilita: starý server.py volal me.handle_profile_visibility."""
    return route_post(handler, urlparse(handler.path).path)
