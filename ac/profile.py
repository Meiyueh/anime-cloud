# ac/profile.py
from __future__ import annotations
import os, json
from typing import Optional, Dict, Any
from flask import Blueprint, jsonify, request, send_from_directory

# Blueprint – namountujeme ho na root (viz server.py)
bp_profiles = Blueprint("profiles", __name__)

# Konfigurace cest (můžeš přepsat ENV proměnnými)
USERS_DIR = os.environ.get("AC_USERS_DIR", os.path.join("data", "users"))
PROFILE_HTML = os.environ.get("AC_PROFILE_HTML", "profile.html")

# Která pole smí ven do veřejného profilu
PUBLIC_PROFILE_FIELDS = [
    "slug", "display_name", "avatar_url", "bio",
    "joined_at", "stats", "links", "badges"
]

def _load_user_record(slug: str) -> Optional[Dict[str, Any]]:
    """Načte JSON uživatele ze složky USERS_DIR (slug.json)."""
    p = os.path.join(USERS_DIR, f"{slug}.json")
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _build_public_profile(u: Dict[str, Any]) -> Dict[str, Any]:
    pub = {k: u.get(k) for k in PUBLIC_PROFILE_FIELDS}
    pub["display_name"] = pub.get("display_name") or u.get("slug")
    pub["joined_at"] = pub.get("joined_at") or u.get("created_at")
    pub["stats"] = pub.get("stats") or {"uploads": 0, "favorites": 0}
    pub["badges"] = pub.get("badges") or []
    pub["links"] = pub.get("links") or {}
    return pub

@bp_profiles.get("/api/profile/<slug>")
def api_profile(slug: str):
    """Vrátí veřejný profil (podle visibility)."""
    slug = (slug or "").strip().lower()
    u = _load_user_record(slug)
    if not u:
        return jsonify({"error": "not_found"}), 404

    visibility = (u.get("visibility") or "private").lower()
    if visibility == "private":
        return jsonify({"error": "profile_private"}), 403

    if visibility == "link":
        token = request.args.get("t") or ""
        if not token or token != (u.get("profile_share_token") or ""):
            return jsonify({"error": "link_required"}), 403

    return jsonify({"profile": _build_public_profile(u)}), 200

@bp_profiles.get("/u/<slug>")
def serve_profile_page(slug: str):
    """
    Servíruje frontend profilovou stránku (statický soubor).
    Ta si sama zavolá /api/profile/<slug>.
    """
    # profile.html očekáváme v kořeni (nebo nastav AC_PROFILE_HTML)
    root = os.path.dirname(PROFILE_HTML) or "."
    fname = os.path.basename(PROFILE_HTML)
    return send_from_directory(root, fname)
