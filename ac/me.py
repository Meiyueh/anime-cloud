# ac/me.py
import json, io, re, datetime
from urllib.parse import urlparse, parse_qs, quote
from google.cloud import storage
from . import settings
from . import auth  # kvůli shared parse_body()

BUCKET_NAME = settings.GCS_BUCKET or "anime-cloud"
USERS_PREFIX = settings.USERS_JSON_CLOUD or "private/users"
SLUGS_PREFIX = "private/slugs"  # volitelná cache (zatím jen fallback)

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

def _load_blob_text(path):
    b = bucket().blob(path)
    if not b.exists(): return None
    return b.download_as_text(encoding="utf-8")

def _save_blob_json(path, data_obj):
    b = bucket().blob(path)
    data = json.dumps(data_obj, ensure_ascii=False, separators=(",",":"))
    b.upload_from_string(data, content_type="application/json; charset=utf-8")
    return True

# --- helpers: user IO + transformace starého schématu ---
def _user_path(email:str)->str:
    return f"{USERS_PREFIX}/{email}"

def _read_user(email:str)->dict|None:
    txt = _load_blob_text(_user_path(email))
    if not txt: return None
    try:
        doc = json.loads(txt)
    except Exception:
        return None
    # transformace starého schématu -> nové pole 'me' očekávané FE
    # staré: {email,name,password_hash,role,created_at,...}
    # nové:  {email, slug, display_name, avatar_url, joined_at, created_at, visibility, titles, stats}
    me = {
        "email": doc.get("email") or email,
        "slug":  doc.get("slug") or (doc.get("name") or (email.split("@")[0])),
        "display_name": doc.get("display_name") or doc.get("nickname") or doc.get("name") or email,
        "avatar_url": doc.get("avatar_url") or doc.get("avatar") or "",
        "joined_at": doc.get("joined_at") or doc.get("created_at"),
        "created_at": doc.get("created_at") or doc.get("joined_at"),
        "visibility": (doc.get("visibility") or "private").lower(),
        "titles": doc.get("titles") or ([] if not doc.get("secondaryTitle") else [doc["secondaryTitle"]]),
        "stats": doc.get("stats") or {"uploads": 0, "favorites": 0},
    }
    # doplň 'created_at' pokud chybí (z joined_at) a naopak
    if not me["created_at"] and me["joined_at"]:
        me["created_at"] = me["joined_at"]
    if not me["joined_at"] and me["created_at"]:
        me["joined_at"] = me["created_at"]
    return me

def _write_user(email:str, patch:dict)->dict:
    # načti původní raw json (abychom zachovali staré klíče, které nepotřebujeme přepisovat)
    txt = _load_blob_text(_user_path(email))
    base = {}
    if txt:
        try: base = json.loads(txt)
        except Exception: base = {}

    # merge: respektuj nové klíče, ale staré nech klidně vedle – kompatibilita
    if "display_name" in patch:
        base["display_name"] = patch["display_name"]
        # pro kompatibilitu se starším FE uložíme i nickname/name
        base["nickname"] = patch["display_name"]
        base["name"] = base.get("name") or patch["display_name"]

    if "avatar_url" in patch:
        base["avatar_url"] = patch["avatar_url"]
        base["avatar"] = patch["avatar_url"]  # pro starší FE

    if "titles" in patch and isinstance(patch["titles"], list):
        base["titles"] = patch["titles"]
        # kompatibilita: sekundární titul uložíme vedle (pokud existuje jen 1)
        base["secondaryTitle"] = patch["titles"][0] if patch["titles"] else None

    if "visibility" in patch:
        base["visibility"] = patch["visibility"]

    # slug je stabilní – nedělat „rename slug“ kvůli display_name
    if "slug" not in base or not base["slug"]:
        base["slug"] = (base.get("name") or email.split("@")[0])

    # datumy
    now_iso = datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
    base["email"] = email
    base["created_at"] = base.get("created_at") or now_iso
    base["joined_at"]  = base.get("joined_at")  or base["created_at"]
    base["stats"] = base.get("stats") or {"uploads": 0, "favorites": 0}
    base["visibility"] = (base.get("visibility") or "private").lower()

    _save_blob_json(_user_path(email), base)

    # vrátíme „me“ pohled
    return _read_user(email)

# --- vyhledání profilu pro veřejné / api/profile/<slug|email> (používá i profile.py) ---
def find_by_slug(slug:str)->dict|None:
    # 1) zkus mapu private/slugs/<slug>.json -> {"email":"..."}
    sl_path = f"{SLUGS_PREFIX}/{slug}.json"
    txt = _load_blob_text(sl_path)
    email = None
    if txt:
        try:
            email = (json.loads(txt) or {}).get("email")
        except Exception:
            email = None
    # 2) pokud není mapování, projdi uživatele a najdi shodu slug
    if not email:
        bkt = bucket()
        for blob in bkt.list_blobs(prefix=f"{USERS_PREFIX}/"):
            try:
                doc = json.loads(blob.download_as_text(encoding="utf-8"))
            except Exception:
                continue
            s = doc.get("slug") or doc.get("name") or (doc.get("email","").split("@")[0])
            if s == slug:
                email = doc.get("email")
                break
    if not email: return None
    return _read_user(email)

# --- ROUTERY pro server.py ---
def route_get(handler, path)->bool:
    """
    Vrací True, když jsme požadavek obsloužili.
    """
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
        who = slug_or_email
        me = None
        if "@" in who:
            me = _read_user(who)
        else:
            me = find_by_slug(who)
        if not me:
            return _json(handler, 404, {"ok": False, "error":"user not found"})
        # respektuj viditelnost jen pro info; (veřejná stránka to řeší v profile.py)
        out = {
            "slug": me["slug"],
            "display_name": me["display_name"],
            "avatar_url": me["avatar_url"],
            "joined_at": me["joined_at"],
            "titles": me.get("titles", []),
            "visibility": me.get("visibility","private"),
        }
        return _json(handler, 200, {"ok": True, "profile": out})

    return False

def route_post(handler, path)->bool:
    # /api/me/update?email=...
    if path.startswith("/api/me/update"):
        q = parse_qs(urlparse(handler.path).query)
        email = (q.get("email") or [None])[0]
        if not email:
            return _json(handler, 401, {"ok": False, "error": "unauthorized"})
        body = auth.parse_body(handler.rfile.read(int(handler.headers.get("Content-Length") or 0)), (handler.headers.get("Content-Type") or ""))
        display_name = (body or {}).get("display_name")
        avatar_url   = (body or {}).get("avatar_url")
        titles       = (body or {}).get("titles")
        visibility   = (body or {}).get("visibility")
        patch = {}
        if display_name is not None: patch["display_name"] = display_name
        if avatar_url is not None:   patch["avatar_url"] = avatar_url
        if isinstance(titles, list): patch["titles"] = titles
        if visibility:               patch["visibility"] = visibility
        me = _write_user(email, patch)
        return _json(handler, 200, {"ok": True, "me": me})

    # /api/me/visibility?email=...
    if path.startswith("/api/me/visibility"):
        q = parse_qs(urlparse(handler.path).query)
        email = (q.get("email") or [None])[0]
        if not email:
            return _json(handler, 401, {"ok": False, "error": "unauthorized"})
        body = auth.parse_body(handler.rfile.read(int(handler.headers.get("Content-Length") or 0)), (handler.headers.get("Content-Type") or ""))
        vis = ((body or {}).get("visibility") or "").lower()
        if vis not in ("public","private","link"):
            return _json(handler, 400, {"ok": False, "error": "invalid visibility"})
        me = _write_user(email, {"visibility": vis})
        return _json(handler, 200, {"ok": True, "me": me})

    return False
