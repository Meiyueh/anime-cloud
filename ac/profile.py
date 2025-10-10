# ac/profile.py
import os, json, sys, html
from datetime import datetime
from urllib.parse import unquote

USERS_DIR = os.getenv("AC_USERS_DIR", "private/users")
PROFILE_HTML = os.getenv("AC_PROFILE_HTML", "profile.html")

def _list_user_files():
    try:
        return [os.path.join(USERS_DIR, e.name)
                for e in os.scandir(USERS_DIR)
                if e.is_file() and e.name.lower().endswith(".json")]
    except FileNotFoundError:
        return []

def _open_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[PROFILE] WARN: JSON read failed for {path}: {e}", file=sys.stderr)
        return {}

def _mtime_iso(path):
    try:
        ts = os.path.getmtime(path)
        return datetime.utcfromtimestamp(ts).isoformat() + "Z"
    except Exception:
        return None

def _normalize_for_profile(email:str, data:dict, path:str) -> tuple[dict, bool]:
    """Stejné doplňování jako v me.py, ale lokálně (žádná importní závislost)."""
    changed = False
    email = (email or data.get("email") or "").lower()

    if not data.get("slug"):
        data["slug"] = (email.split("@")[0] if email else (data.get("name") or "")).lower()
        changed = True
    if not data.get("display_name"):
        data["display_name"] = data.get("name") or email
        changed = True
    if not data.get("visibility"):
        data["visibility"] = "public"  # veřejný profil defaultně ukážeme
        changed = True
    if not isinstance(data.get("titles"), list) and "title" in data:
        data["titles"] = [data["title"]]
        changed = True
    if not isinstance(data.get("stats"), dict):
        data["stats"] = {"uploads": 0, "favorites": 0}
        changed = True
    if not (data.get("joined_at") or data.get("created_at")):
        mt = _mtime_iso(path) if path else None
        if mt:
            data["joined_at"] = mt
            data["created_at"] = mt
            changed = True
    if email and data.get("email") != email:
        data["email"] = email
        changed = True
    return data, changed

def _find_by_email(email_key: str):
    key = email_key.strip().lower()
    if not key.endswith(".json"):
        key += ".json"
    p = os.path.join(USERS_DIR, key)
    return p if os.path.exists(p) else None

def _find_by_slug(slug: str):
    slug = (slug or "").strip().lower()
    if not slug:
        return None
    files = _list_user_files()

    # 1) shoda prefixu názvu souboru (before @)
    for p in files:
        base = os.path.basename(p)[:-5].lower()
        if base.split("@")[0] == slug:
            return p

    # 2) shoda JSON pole "slug"
    for p in files:
        u = _open_json(p)
        if (u.get("slug") or "").strip().lower() == slug:
            return p

    return None

def handle_profile_api(handler, parsed):
    raw = parsed.path.split("/api/profile/", 1)[1]
    key = unquote(raw.strip("/").split("/", 1)[0])

    path = _find_by_email(key) if "@" in key else _find_by_slug(key)
    print(f"[PROFILE] lookup key='{key}' -> path={path}", file=sys.stderr)

    if not path:
        return handler._json(404, {"ok": False, "error": "user not found"})

    base = os.path.basename(path)[:-5]
    email = base.lower()

    data = _open_json(path)
    data, ch = _normalize_for_profile(email, data, path)
    if ch:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

    out = {
        "slug": data.get("slug") or base.split("@")[0],
        "display_name": data.get("display_name") or data.get("nickname") or data.get("name") or email,
        "avatar_url": data.get("avatar_url") or data.get("avatar") or "",
        "joined_at": data.get("joined_at") or data.get("created_at") or _mtime_iso(path),
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
