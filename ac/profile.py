# ac/profile.py
import os, json, glob

USERS_DIR = os.getenv("AC_USERS_DIR", "private/users")
PROFILE_HTML = os.getenv("AC_PROFILE_HTML", "profile.html")

def _find_user_by_slug(slug):
    slug = (slug or "").strip().lower()
    for path in glob.glob(os.path.join(USERS_DIR, "*.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                u = json.load(f)
            if (u.get("slug") or "").lower() == slug:
                return u
        except: pass
    return None

def handle_profile_api(handler, parsed):
    slug = parsed.path.split("/api/profile/",1)[1].strip("/").split("/",1)[0]
    u = _find_user_by_slug(slug)
    if not u:
        return handler._json(404, {"ok":False,"error":"user not found"})
    pub = {
        "slug": u.get("slug"),
        "display_name": u.get("display_name") or u.get("nickname") or u.get("email"),
        "avatar_url": u.get("avatar_url") or u.get("avatar") or "/assets/default-avatar.png",
        "joined_at": u.get("joined_at") or u.get("created_at"),
        "titles": u.get("titles") or ([u["title"]] if u.get("title") else []),
        "visibility": u.get("visibility","public")
    }
    return handler._json(200, {"ok":True, "profile": pub})

def handle_profile_page(handler, parsed):
    slug = parsed.path.split("/u/",1)[1].strip("/").split("/",1)[0]
    try:
        with open(PROFILE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    except FileNotFoundError:
        # fallback HTML (když chybí profile.html)
        return handler._html(200, f"<!doctype html><meta charset='utf-8'><title>@{slug}</title>"
                               f"<h1 style='font:16px sans-serif'>Načítám profil @{slug}…</h1>"
                               f"<script>location.href='/api/profile/{slug}'</script>")
    # do šablony jen vložíme slug; zbytek si načte JS
    html = html.replace("{{SLUG}}", slug)
    return handler._html(200, html)
