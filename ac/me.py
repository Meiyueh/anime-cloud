# ac/me.py
import os, json, glob, re, sys
from datetime import datetime
from urllib.parse import urlparse, parse_qs

USERS_DIR = os.getenv("AC_USERS_DIR", "private/users")
os.makedirs(USERS_DIR, exist_ok=True)

def _email_to_path(email:str) -> str:
    email = (email or "").strip().lower()
    if not email: return ""
    if not email.endswith(".json"): email += ".json"
    email = email.replace("/", "_")
    return os.path.join(USERS_DIR, email)

def _safe_mtime_iso(path:str):
    try:
        ts = os.path.getmtime(path)
        return datetime.utcfromtimestamp(ts).isoformat() + "Z"
    except Exception:
        return None

def _normalize_user(email:str, data:dict, path:str) -> tuple[dict, bool]:
    """Doplní chybějící pole u starých záznamů. Vrací (data, changed)."""
    changed = False
    email = (email or data.get("email") or "").lower()

    # slug
    if not data.get("slug"):
        data["slug"] = (email.split("@")[0] if email else (data.get("name") or "")).lower()
        changed = True

    # display_name
    if not data.get("display_name"):
        # preferuj 'name' (starý formát), jinak e-mail
        data["display_name"] = data.get("name") or email
        changed = True

    # visibility
    if not data.get("visibility"):
        data["visibility"] = "private"   # konzervativně
        changed = True

    # stats
    if not isinstance(data.get("stats"), dict):
        data["stats"] = {"uploads": 0, "favorites": 0}
        changed = True

    # joined/created
    if not (data.get("joined_at") or data.get("created_at")):
        mt = _safe_mtime_iso(path) if path else None
        if mt:
            data["joined_at"] = mt
            data["created_at"] = mt
            changed = True

    # email uvnitř
    if email and data.get("email") != email:
        data["email"] = email
        changed = True

    return data, changed

def _load_user_by_email(email:str):
    p = _email_to_path(email)
    if not p or not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ME] WARN: JSON read failed for {p}: {e}", file=sys.stderr)
        data = {}
    # auto-migrace
    new_data, changed = _normalize_user(email, data, p)
    if changed:
        _save_user_by_email(email, new_data)
    return new_data

def _save_user_by_email(email:str, data:dict):
    p = _email_to_path(email)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, p)
    return True

def _find_user_by_slug(slug:str):
    """Najde uživatele podle slugu. Pokud slug v JSON chyběl, po normalizaci odpovídá prefixu před @."""
    slug = (slug or "").strip().lower()
    for path in glob.glob(os.path.join(USERS_DIR, "*.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                u = json.load(f)
        except Exception:
            u = {}
        # odvoď email z názvu souboru
        base = os.path.basename(path)[:-5]
        email = base
        # auto-migrace na čtení
        u, ch = _normalize_user(email, u, path)
        if ch:
            # zapiš změny
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(u, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        # test shody
        u_slug = (u.get("slug") or base.split("@")[0]).lower()
        if u_slug == slug:
            return email, u
    return None, None

def _public_me(email, data, path=None):
    slug = data.get("slug") or (email.split("@")[0] if email else "")
    display = data.get("display_name") or data.get("nickname") or data.get("name") or email
    avatar = data.get("avatar_url") or data.get("avatar") or ""
    joined = data.get("joined_at") or data.get("created_at")
    if not joined and path:
        joined = _safe_mtime_iso(path)

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

def _extract_identity(handler):
    """Pokus o identitu z Authorization: Bearer <email|slug> nebo X-Auth-Email."""
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
    email, slug = _extract_identity(handler)
    if not email:
        qs = parse_qs(parsed.query or "")
        qemail = (qs.get("email") or [None])[0]
        if qemail:
            email = qemail
            slug = email.split("@")[0] if "@" in email else email

    if not email:
        return handler._json(401, {"ok": False, "error": "unauthorized"})

    p = _email_to_path(email)
    data = _load_user_by_email(email) or {}
    return handler._json(200, {"ok": True, "me": _public_me(email, data, p)})

def handle_me_update(handler, parsed):
    body = handler._read_body() or {}
    email, slug = _extract_identity(handler)

    if not email:
        qs = parse_qs(parsed.query or "")
        email = (qs.get("email") or [None])[0]
        slug  = email.split("@")[0] if (email and "@" in email) else slug

    if not email:
        return handler._json(401, {"ok": False, "error": "unauthorized"})

    p = _email_to_path(email)
    data = _load_user_by_email(email) or {}
    data.setdefault("email", email)
    data, ch = _normalize_user(email, data, p)

    # patche z těla
    dn = (body.get("display_name") or "").strip()
    if dn:
        data["display_name"] = dn

    if body.get("avatar_url"):
        data["avatar_url"] = body["avatar_url"]

    titles = body.get("titles")
    if isinstance(titles, list):
        data["titles"] = titles
    elif isinstance(body.get("title"), str):
        data["title"] = body["title"]

    if not data.get("created_at") and not data.get("joined_at"):
        data["created_at"] = datetime.utcnow().isoformat() + "Z"

    _save_user_by_email(email, data)
    return handler._json(200, {"ok": True, "me": _public_me(email, data, p)})

def handle_profile_visibility(handler, parsed):
    body = handler._read_body() or {}
    email, _ = _extract_identity(handler)
    if not email:
        qs = parse_qs(parsed.query or "")
        email = (qs.get("email") or [None])[0]
    if not email:
        return handler._json(401, {"ok": False, "error": "unauthorized"})

    p = _email_to_path(email)
    data = _load_user_by_email(email) or {}
    vis = (body.get("visibility") or "private").lower()
    if vis not in ("public", "private", "link"):
        vis = "private"
    data["visibility"] = vis
    _save_user_by_email(email, data)
    return handler._json(200, {"ok": True, "visibility": vis})
