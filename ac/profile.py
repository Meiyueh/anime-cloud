# ac/profile.py
import os, json, glob, html
from datetime import datetime

USERS_DIR = os.getenv("AC_USERS_DIR", "private/users")
PROFILE_HTML = os.getenv("AC_PROFILE_HTML", "profile.html")

def _iter_user_files():
    pattern = os.path.join(USERS_DIR, "*.json")
    return glob.glob(pattern)

def _filename_prefix(path):
    """prefix 'name' z 'name@example.com.json' -> 'name' """
    base = os.path.basename(path)
    if base.lower().endswith(".json"):
        base = base[:-5]
    return (base.split("@")[0]).lower()

def _safe_load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _joined_from_mtime(path):
    try:
        ts = os.path.getmtime(path)
        return datetime.utcfromtimestamp(ts).isoformat() + "Z"
    except Exception:
        return None

def _find_path_by_slug(slug:str):
    """Upřednostni shodu podle názvu souboru (rychlé a robustní).
       Když nenajdeme, zkus JSON pole 'slug' (pomalejší)."""
    slug = (slug or "").strip().lower()
    if not slug:
        return None

    # 1) Shoda prefixu názvu souboru
    for p in _iter_user_files():
        if _filename_prefix(p) == slug:
            return p

    # 2) Shoda JSON 'slug'
    for p in _iter_user_files():
        u = _safe_load_json(p)
        u_slug = (u.get("slug") or "").strip().lower()
        if u_slug and u_slug == slug:
            return p

    return None

def handle_profile_api(handler, parsed):
    slug = parsed.path.split("/api/profile/", 1)[1].strip("/").split("/", 1)[0]
    path = _find_path_by_slug(slug)
    if not path:
        return handler._json(404, {"ok": False, "error": "user not found"})

    u = _safe_load_json(path)

    # Fallbacky
    display = u.get("display_name") or u.get("nickname") or u.get("email") or slug
    avatar  = u.get("avatar_url") or u.get("avatar") or ""
    joined  = u.get("joined_at") or u.get("created_at") or _joined_from_mtime(path)
    vis     = (u.get("visibility") or "public").lower()
    titles  = u.get("titles") or ([u["title"]] if u.get("title") else [])

    out = {
        "slug": (u.get("slug") or slug),
        "display_name": display,
        "avatar_url": avatar,
        "joined_at": joined,
        "titles": titles,
        "visibility": vis
    }
    return handler._json(200, {"ok": True, "profile": out})

def handle_profile_page(handler, parsed):
    slug = parsed.path.split("/u/", 1)[1].strip("/").split("/", 1)[0]
    try:
        with open(PROFILE_HTML, "r", encoding="utf-8") as f:
            html_tpl = f.read()
    except FileNotFoundError:
        # minimalistický fallback HTML
        safe = html.escape(slug)
        return handler._html(200, f"""<!doctype html><meta charset="utf-8">
<title>@{safe} • AnimeCloud</title>
<h1 style="font-family:sans-serif">Načítám profil @{safe}…</h1>
<script>location.href='/api/profile/{safe}'</script>""")

    return handler._html(200, html_tpl.replace("{{SLUG}}", slug))
