# ac/profile_http.py
from __future__ import annotations
import os, json
from urllib.parse import parse_qs

USERS_DIR = os.environ.get("AC_USERS_DIR", os.path.join("data", "users"))
PROFILE_HTML = os.environ.get("AC_PROFILE_HTML", "profile.html")

PUBLIC_PROFILE_FIELDS = [
    "slug", "display_name", "avatar_url", "bio",
    "joined_at", "stats", "links", "badges"
]

def _load_user_record(slug: str):
    p = os.path.join(USERS_DIR, f"{slug}.json")
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _build_public_profile(u: dict) -> dict:
    pub = {k: u.get(k) for k in PUBLIC_PROFILE_FIELDS}
    pub["display_name"] = pub.get("display_name") or u.get("slug")
    pub["joined_at"]   = pub.get("joined_at") or u.get("created_at")
    pub["stats"]  = pub.get("stats")  or {"uploads": 0, "favorites": 0}
    pub["badges"] = pub.get("badges") or []
    pub["links"]  = pub.get("links")  or {}
    return pub

def handle_profile_api(handler, parsed_url):
    """
    GET /api/profile/<slug>[?t=TOKEN]
    """
    path = parsed_url.path  # např. /api/profile/meiyueh
    prefix = "/api/profile/"
    slug = path[len(prefix):].strip().lower()
    if not slug:
        return handler._json(400, {"error":"bad_request"})

    u = _load_user_record(slug)
    if not u:
        return handler._json(404, {"error":"not_found"})

    visibility = (u.get("visibility") or "private").lower()
    if visibility == "private":
        return handler._json(403, {"error":"profile_private"})
    if visibility == "link":
        qs = parse_qs(parsed_url.query or "")
        token = (qs.get("t") or [""])[0]
        if not token or token != (u.get("profile_share_token") or ""):
            return handler._json(403, {"error":"link_required"})

    return handler._json(200, {"profile": _build_public_profile(u)})

def handle_profile_page(handler, parsed_url):
    """
    GET /u/<slug>[?t=TOKEN]
    Vrátí statické profile.html (FE si sáhne na /api/profile/<slug>).
    """
    # profile.html může být v kořeni nebo jinde – nastav přes AC_PROFILE_HTML
    if not os.path.exists(PROFILE_HTML):
        return handler._json(500, {"error":"profile_html_missing"})
    try:
        with open(PROFILE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
        return handler._html(200, html)
    except Exception as e:
        return handler._json(500, {"error": str(e)})
