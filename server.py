#!/usr/bin/env python3
import os, traceback
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

# Importy modulů (načtou i .env přes settings)
from ac import settings
from ac import auth, uploads, anime, feedback
from ac import profile_http   # ⬅️ PŘIDÁNO


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class Handler(SimpleHTTPRequestHandler):
    # --- CORS a utilitky výstupu ---
    def _set_cors(self):
        self.send_header("Access-Control-Allow-Origin", settings.CORS_ORIGINS)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def end_headers(self):
        self._set_cors()
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204); self.end_headers()

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        ctype = (self.headers.get("Content-Type") or "").lower()
        return auth.parse_body(raw, ctype)  # sdílený parser v auth/utils

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

            # --- NOVÉ PROFILOVÉ ENDPOINTY ---
            if p.path.startswith("/api/profile/"):
                return profile_http.handle_profile_api(self, p)
            if p.path.startswith("/u/"):
                return profile_http.handle_profile_page(self, p)

            # --- EXISTUJÍCÍ ENDPOINTY ---
            if p.path == "/auth/verify":         return auth.handle_verify(self, p)
            if p.path == "/data/anime.json":     return anime.handle_anime_json(self)
            if p.path == "/uploads/counts":      return anime.handle_upload_counts(self)
            if p.path == "/stats":               return anime.handle_stats(self)
            if p.path == "/feedback/list":       return feedback.handle_feedback_list(self)

            return super().do_GET()
        except Exception as e:
            traceback.print_exc()
            return self._json(500, {"ok":False,"error":str(e)})

    def do_POST(self):
        try:
            p = urlparse(self.path)
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

            if p.path == "/wipe_all":            return self._json(200, {"ok":True,"status":"cloud wipe disabled"})
            return self._json(404, {"ok":False,"error":"Not found"})
        except Exception as e:
            traceback.print_exc()
            return self._json(500, {"ok":False,"error":str(e)})

def main():
    if settings.ADMIN_BOOT_ENABLE:
        auth.bootstrap_admin_if_needed()
    os.chdir(BASE_DIR)
    httpd = HTTPServer(("0.0.0.0", settings.PORT), Handler)
    print(f"AnimeCloud server běží na http://0.0.0.0:{settings.PORT}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()


