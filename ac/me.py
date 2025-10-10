# ac/me.py
import os, json, glob, re
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

def _load_user_by_email(email:str):
    p = _email_to_path(email)
    if not p or not os.path.exists(p):
        return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

def _save_user_by_email(email:str, data:dict):
    p = _email_to_path(email)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, p)
    return True

def _find_user_by_slug(slug:str):
    """Najde uživatele podle slug. Pokud slug v JSON chybí, bere prefix e-mailu před @."""
    slug = (slug or "").strip().lower()
    for path in glob.glob(os.path.join(USERS_DIR, "*.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                u = json.load(f)
            u_slug = (u.get("slug") or "").lower()
            if not u_slug:
                # fallback: email prefix
                base = os.path.basename(path)[:-5]  # xxx@yyy.zzz
                u_slug = base.split("@")[0].lower()
            if u_slug == slug:
                email = os.path.basename(path)[:-5]
                return email, u
        except:
            pass
    return None, None

def _public_me(email, data):
    slug = data.get("slug") or (email.split("@")[0] if email else "")
    display = data.get("display_name") or data.get("nickname") or email
    avatar = data.get("avatar_url") or data.get("avatar") or ""
    joined = data.get("joined_at") or data.get("created_at")

    if not joined:
        # fallback z mtime souboru
        p = _email_to_path(email)
        try:
            ts = os.path.getmtime(p)
            joined = datetime.utcfromtimestamp(ts).isoformat() + "Z"
        except:
            joined = None

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
    # Authorization
    auth = handler.headers.get("Authorization") or ""
    m = re.match(r"Bearer\s+(.+)", auth, flags=re.I)
    if m:
        token = m.group(1).strip()
        if "@" in token:
            return token, token.split("@")[0]
        email, data = _find_user_by_slug(token)
        if email: return email, token

    # Custom hlavička (volitelně)
    xemail = handler.headers.get("X-Auth-Email") or ""
    if xemail:
        return xemail, xemail.split("@")[0] if "@" in xemail else xemail

    return None, None

def handle_me_get(handler, parsed):
    # 1) standardně – z headerů
    email, slug = _extract_identity(handler)

    # 2) fallback – z query param ?email=...
    if not email:
        qs = parse_qs(parsed.query or "")
        qemail = (qs.get("email") or [None])[0]
        if qemail:
            email = qemail
            slug = email.split("@")[0] if "@" in email else email

    if not email:
        return handler._json(401, {"ok": False, "error": "unauthorized"})

    data = _load_user_by_email(email) or {}
    # zajistit slug/email uvnitř souboru
    if not data.get("slug"):
        data["slug"] = slug or email.split("@")[0]
    if not data.get("email"):
        data["email"] = email

    return handler._json(200, {"ok": True, "me": _public_me(email, data)})

def handle_me_update(handler, parsed):
    body = handler._read_body() or {}
    email, slug = _extract_identity(handler)

    # povolíme i ?email=...
    if not email:
        qs = parse_qs(parsed.query or "")
        email = (qs.get("email") or [None])[0]
        slug = email.split("@")[0] if (email and "@" in email) else slug

    if not email:
        return handler._json(401, {"ok": False, "error": "unauthorized"})

    data = _load_user_by_email(email) or {}
    data.setdefault("email", email)
    data.setdefault("slug", slug or email.split("@")[0])

    # patche
    display_name = (body.get("display_name") or "").strip()
    if display_name:
        data["display_name"] = display_name

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
    return handler._json(200, {"ok": True, "me": _public_me(email, data)})

def handle_profile_visibility(handler, parsed):
    body = handler._read_body() or {}
    email, slug = _extract_identity(handler)
    if not email:
        # povolit i ?email=...
        qs = parse_qs(parsed.query or "")
        email = (qs.get("email") or [None])[0]
    if not email:
        return handler._json(401, {"ok": False, "error": "unauthorized"})
    data = _load_user_by_email(email) or {}
    vis = (body.get("visibility") or "private").lower()
    if vis not in ("public", "private", "link"):
        vis = "private"
    data["visibility"] = vis
    _save_user_by_email(email, data)
    return handler._json(200, {"ok": True, "visibility": vis})
