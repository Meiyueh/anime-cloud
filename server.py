#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, traceback
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

# --- Projektové moduly (načtou i .env přes settings) ---
from ac import settings
from ac import auth, uploads, anime, feedback
from ac import profile   # /u/<slug>, /api/profile/<slug>
from ac import me        # /api/me*, viz account.html

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class Handler(SimpleHTTPRequestHandler):
    # --- CORS & pomocné výstupy ---
    def _set_cors(self):
        # Pokud máš víc originů, dej např. "*", nebo join seznamu:
        self.send_header("Access-Control-Allow-Origin", settings.CORS_ORIGINS)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def end_headers(self):
        self._set_cors()
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        ctype = (self.headers.get("Content-Type") or "").lower()
        # sdílený parser z auth (JSON/form-data/x-www-form-urlencoded)
        return auth.parse_body(raw, ctype)

    def _json(self, code, obj):
        import json
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _html(self, code, html):
        data = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # --- ROUTING ---
    def do_GET(self):
        try:
            p = urlparse(self.path)

            # ===== Veřejné profily =====
            if p.path.startswith("/api/profile/"):   # JSON profil (public/link)
                return profile.handle_profile_api(self, p)
            if p.path.startswith("/u/"):             # HTML profilová stránka
                return profile.handle_profile_page(self, p)

            # ===== Účet přihlášeného uživatele (pro account.html) =====
            if p.path == "/api/me":
                return me.handle_me_get(self, p)

            # ===== Stávající endpointy =====
            if p.path == "/auth/verify":         return auth.handle_verify(self, p)
            if p.path == "/data/anime.json":     return anime.handle_anime_json(self)
            if p.path == "/uploads/counts":      return anime.handle_upload_counts(self)
            if p.path == "/stats":               return anime.handle_stats(self)
            if p.path == "/feedback/list":       return feedback.handle_feedback_list(self)

            # Static files (spadne to na SimpleHTTPRequestHandler)
            return super().do_GET()

        except Exception as e:
            traceback.print_exc()
            return self._json(500, {"ok": False, "error": str(e)})

    def do_POST(self):
        try:
            p = urlparse(self.path)

            # ===== Účet přihlášeného uživatele =====
            if p.path == "/api/me/update":             return me.handle_me_update(self, p)
            if p.path == "/api/me/profile_visibility": return me.handle_me_visibility(self, p)
            if p.path == "/api/me/profile_token":      return me.handle_me_profile_token(self, p)

            # ===== Auth / Uploady / Admin / Feedback =====
            if p.path == "/auth/register":       return auth.handle_register(self)
            if p.path == "/auth/login":          return auth.handle_login(self)
            if p.path == "/auth/resend":         return auth.handle_resend(self)

            if p.path == "/upload":              return uploads.handle_upload(self)
            if p.path == "/upload/sign":         return uploads.handle_upload_sign(self)
            if p.path == "/delete":              return uploads.handle_delete_file(self)

            if p.path == "/admin/add_anime":     return anime.handle_add_anime(self)
            if p.path == "/admin/upload_cover":  return anime.handle_upload_cover(self)

            if p.path == "/feedback":            return feedback.handle_feedback_save(self)
            if p.path == "/feedback/update":     return feedback.handle_feedback_update(self)

            # Utility
            if p.path == "/wipe_all":
                return self._json(200, {"ok": True, "status": "cloud wipe disabled"})

            return self._json(404, {"ok": False, "error": "Not found"})

        except Exception as e:
            traceback.print_exc()
            return self._json(500, {"ok": False, "error": str(e)})

def main():
    # volitelný bootstrap admina
    if getattr(settings, "ADMIN_BOOT_ENABLE", False):
        try:
            auth.bootstrap_admin_if_needed()
        except Exception:
            traceback.print_exc()

    os.chdir(BASE_DIR)
    httpd = HTTPServer(("0.0.0.0", settings.PORT), Handler)
    print(f"AnimeCloud server běží na http://0.0.0.0:{settings.PORT}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()
