# ac/me.py
from __future__ import annotations
import os, json, secrets, time, re
from typing import Optional, Dict, Any
from http.cookies import SimpleCookie

# ENV overrides
USERS_DIR = os.environ.get("AC_USERS_DIR", os.path.join("data", "users"))

# --- Helpers ---------------------------------------------------------------

def _ensure_users_dir():
    os.makedirs(USERS_DIR, exist_ok=True)

def _user_path(slug: str) -> str:
    return os.path.join(USERS_DIR, f"{slug}.json")

def _load_user(slug: str) -> Optional[Dict[str, Any]]:
    p = _user_path(slug)
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _atomic_save_json(path: str, data: Dict[str, Any]):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _rand_token(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)

# snažíme se zjistit přihlášeného uživatele vícero cestami,
# abychom nemuseli sahat do tvého auth modulu; pokud máš v auth něco svého,
# můžeš to sem snadno doplnit.
def _get_me_slug(handler) -> Optional[str]:
    # 1) Pokud tvůj modul auth nabízí funkci, použij ji
    try:
        from ac import auth  # už ho stejně máš
        # zkus běžné varianty
        for fn in ("get_current_user_slug", "current_user_slug", "get_me_slug", "whoami_slug"):
            f = getattr(auth, fn, None)
            if callable(f):
                slug = f(handler)
                if slug:
                    return str(slug).strip().lower()
    except Exception:
        pass

    # 2) Authorization: Bearer <slug> (fallback pro dev)
    authz = handler.headers.get("Authorization") or ""
    if authz.lower().startswith("bearer "):
        slug = authz.split(" ", 1)[1].strip()
        if slug:
            return slug.lower()

    # 3) Cookie ac_user=<slug>
    cookie = handler.headers.get("Cookie")
    if cookie:
        c = SimpleCookie()
        c.load(cookie)
        if "ac_user" in c:
            slug = (c["ac_user"].value or "").strip()
            if slug:
                return slug.lower()

    return None

# validace a sanitizace
def _sanitize_links(links: Dict[str, Any]) -> Dict[str, str]:
    out = {}
    for k in ("kick", "steam", "web", "twitter", "youtube"):
        v = links.get(k)
        if not v:
            continue
        v = str(v).strip()
        if not re.match(r"^https?://", v):
            # povolíme i relativní (např. /profiles/..), ale nic jiného
            if not v.startswith("/"):
                continue
        out[k] = v
    return out

# sjednotíme výstup pro account.html (me)
def _build_me_payload(u: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "uid": u.get("uid") or u.get("id") or u.get("slug"),
        "slug": u.get("slug"),
        "display_name": u.get("display_name") or u.get("slug"),
        "avatar_url": u.get("avatar_url") or "/assets/default-avatar.png",
        "bio": u.get("bio") or "",
        "joined_at": u.get("joined_at") or u.get("created_at"),
        "created_at": u.get("created_at"),
        "visibility": (u.get("visibility") or "private").lower(),
        "profile_share_token": u.get("profile_share_token") or "",
        "stats": u.get("stats") or {"uploads": 0, "favorites": 0},
        "badges": u.get("badges") or [],
        "links": u.get("links") or {}
    }

# --- Handlery --------------------------------------------------------------

def handle_me_get(handler, parsed_url):
    """
    GET /api/me
    Vrací {"me": {...}} nebo 401.
    """
    slug = _get_me_slug(handler)
    if not slug:
        return handler._json(401, {"error": "unauthorized"})
    u = _load_user(slug)
    if not u:
        return handler._json(404, {"error": "user_not_found"})
    if not u.get("joined_at") and u.get("created_at"):
        u["joined_at"] = u["created_at"]
    return handler._json(200, {"me": _build_me_payload(u)})

def handle_me_update(handler, parsed_url):
    """
    POST /api/me/update
    Body JSON:
      { display_name?, avatar_url?, bio?, links?{kick,steam,web,twitter,youtube} }
    """
    slug = _get_me_slug(handler)
    if not slug:
        return handler._json(401, {"error": "unauthorized"})
    u = _load_user(slug)
    if not u:
        return handler._json(404, {"error": "user_not_found"})

    body = handler._read_body() or {}
    display_name = str(body.get("display_name") or "").strip()
    avatar_url   = str(body.get("avatar_url") or "").strip()
    bio          = str(body.get("bio") or "").strip()
    links        = body.get("links") or {}

    if display_name:
        u["display_name"] = display_name[:80]
    if avatar_url:
        # povolíme pouze http(s) nebo relativní url
        if re.match(r"^https?://", avatar_url) or avatar_url.startswith("/"):
            u["avatar_url"] = avatar_url[:512]
    u["bio"] = bio[:1000] if bio else ""

    if isinstance(links, dict):
        u["links"] = _sanitize_links(links)

    # inicializace některých polí
    u.setdefault("slug", slug)
    u.setdefault("uid", slug)
    u.setdefault("created_at", _now_iso())
    u.setdefault("stats", {"uploads": 0, "favorites": 0})
    u.setdefault("badges", [])

    _ensure_users_dir()
    _atomic_save_json(_user_path(slug), u)
    return handler._json(200, {"ok": True, "me": _build_me_payload(u)})

def handle_me_visibility(handler, parsed_url):
    """
    POST /api/me/profile_visibility
    Body JSON: { visibility: "public"|"private"|"link" }
    Vrací { ok: true, profile_share_token? }
    """
    slug = _get_me_slug(handler)
    if not slug:
        return handler._json(401, {"error": "unauthorized"})
    u = _load_user(slug)
    if not u:
        return handler._json(404, {"error": "user_not_found"})

    body = handler._read_body() or {}
    visibility = str(body.get("visibility") or "").strip().lower()
    if visibility not in ("public","private","link"):
        return handler._json(400, {"error": "bad_visibility"})

    u["visibility"] = visibility
    token_out = None
    if visibility == "link":
        # pokud token ještě není, vygenerujeme; nechceme rotaovat bez požadavku
        if not u.get("profile_share_token"):
            u["profile_share_token"] = _rand_token(18)
        token_out = u["profile_share_token"]
    else:
        # pro jistotu token necháme uložený (aby nezmizel při dočasném přepnutí),
        # ale můžeš odkomentovat níže pro jeho smazání:
        # u["profile_share_token"] = ""
        pass

    _atomic_save_json(_user_path(slug), u)
    payload = {"ok": True}
    if token_out:
        payload["profile_share_token"] = token_out
    return handler._json(200, payload)

def handle_me_profile_token(handler, parsed_url):
    """
    POST /api/me/profile_token
    Body JSON: { action: "rotate" }
    → vygeneruje nový token (zneplatní starý), vrátí { profile_share_token }
    """
    slug = _get_me_slug(handler)
    if not slug:
        return handler._json(401, {"error": "unauthorized"})
    u = _load_user(slug)
    if not u:
        return handler._json(404, {"error": "user_not_found"})

    body = handler._read_body() or {}
    action = str(body.get("action") or "").strip().lower()
    if action != "rotate":
        return handler._json(400, {"error": "bad_action"})

    u["profile_share_token"] = _rand_token(18)
    # ponecháme visibility jak je – typicky "link"
    _atomic_save_json(_user_path(slug), u)
    return handler._json(200, {"ok": True, "profile_share_token": u["profile_share_token"]})
