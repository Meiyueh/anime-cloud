# ac/uploads.py
import os, io, json, mimetypes, sys, datetime, traceback
from urllib.parse import quote, parse_qs, urlparse, unquote
from google.cloud import storage
from . import settings

BUCKET_NAME = settings.GCS_BUCKET or ""
GCS_PUBLIC_BASE = f"https://storage.googleapis.com/{BUCKET_NAME}" if BUCKET_NAME else ""

def _json(handler, code, obj): return handler._json(code, obj)

def _get_bucket():
    if not BUCKET_NAME:
        print("[UPLOAD] GCS_BUCKET není nastaveno", file=sys.stderr)
        return None
    try:
        client = storage.Client()
        return client.bucket(BUCKET_NAME)
    except Exception as e:
        print(f"[UPLOAD] storage.Client() selhalo: {e}", file=sys.stderr)
        return None

def _read_request_body(handler):
    """Robustní načtení těla requestu jako dict (JSON/WWW-Form)."""
    try:
        length = int(handler.headers.get("Content-Length") or 0)
    except:
        length = 0
    raw = handler.rfile.read(length) if length > 0 else b""
    ctype = (handler.headers.get("Content-Type") or "").lower()
    body = {}
    if "application/json" in ctype:
        try:
            body = json.loads(raw.decode("utf-8") or "{}") or {}
        except Exception as e:
            print(f"[UPLOAD] JSON parse fail: {e}", file=sys.stderr)
            body = {}
    elif "application/x-www-form-urlencoded" in ctype:
        try:
            qs = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
            body = {k: (v[0] if isinstance(v, list) else v) for k, v in qs.items()}
        except Exception as e:
            print(f"[UPLOAD] form parse fail: {e}", file=sys.stderr)
            body = {}
    return body

def handle_upload_sign(handler):
    try:
        body = _read_request_body(handler) or {}

        # ————— path (přijmi aliasy + slož z anime/episode/quality/videoName, pokud přišlo) —————
        path = (
            body.get("path")
            or body.get("dst")
            or body.get("key")
            or body.get("object")
            or body.get("name")
            or body.get("filename")
            or ""
        )
        if not path:
            a = (body.get("anime") or "").strip()
            ep = body.get("episode")
            q = (body.get("quality") or "").strip()
            vn = (body.get("videoName") or "").strip()
            try:
                epstr = str(int(ep)).zfill(3)
            except:
                epstr = ""
            if a and epstr and q and vn:
                # fallback konstrukce cesty, pokud klient pošle pole zvlášť
                path = f"anime/{a}/ep{epstr}/{q}/{vn}"

        path = (path or "").lstrip("/").strip()

        if not path:
            return _json(handler, 400, {"ok": False, "error": "sign_failed: missing path"})

        ctype = (
            body.get("contentType")
            or body.get("content_type")
            or body.get("ctype")
            or body.get("type")
            or "application/octet-stream"
        )

        bucket = _get_bucket()
        if not bucket:
            return _json(handler, 500, {"ok": False, "error": "sign_failed: no bucket"})

        blob = bucket.blob(path)
        url = blob.generate_signed_url(
            version="v4",
            expiration=datetime.timedelta(minutes=10),
            method="PUT",
            content_type=ctype,
        )
        public_url = f"{GCS_PUBLIC_BASE}/{quote(blob.name)}"
        return _json(handler, 200, {"ok": True, "upload_url": url, "public_url": public_url})

    except Exception as e:
        traceback.print_exc()
        return _json(handler, 400, {"ok": False, "error": f"sign_failed: {e}"})

def handle_upload(handler):
    """Multipart fallback: field 'file' + optional 'path'."""
    try:
        import cgi
        fs = cgi.FieldStorage(
            fp=handler.rfile, headers=handler.headers,
            environ={'REQUEST_METHOD':'POST','CONTENT_TYPE': handler.headers.get('Content-Type')}
        )
        fileitem = fs['file'] if 'file' in fs else None
        path = fs.getfirst('path') if 'path' in fs else None
        if not fileitem or not fileitem.file:
            return _json(handler, 400, {"ok":False, "error":"missing file"})
        filename = fileitem.filename or "upload.bin"
        raw = fileitem.file.read()
        ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        if not path:
            path = f"uploads/{filename}"

        bucket = _get_bucket()
        if bucket:
            blob = bucket.blob(path)
            blob.cache_control = "public, max-age=0, no-cache"
            blob.upload_from_file(io.BytesIO(raw), content_type=ctype)
            try: blob.patch()
            except: pass
            public_url = f"{GCS_PUBLIC_BASE}/{path}"
            return _json(handler, 200, {"ok": True, "url": public_url, "path": path})
        else:
            # lokální fallback
            root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            dst = os.path.abspath(os.path.join(root, path))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f: f.write(raw)
            return _json(handler, 200, {"ok": True, "url": f"/{path}", "path": path})
    except Exception as e:
        traceback.print_exc()
        return _json(handler, 400, {"ok":False,"error":str(e)})

def _normalize_gcs_path(path_or_url: str, bucket_name: str) -> str:
    """
    Vezme buď 'anime/...' nebo úplné GCS URL a vrátí čistý object key bez počátečního '/'.
    Povolíme jen mazání pod prefixem 'anime/' jako bezpečnostní pojistku.
    """
    if not path_or_url:
        return ""

    s = path_or_url.strip()

    # Pokud je to URL, zkus z ní vyndat cestu
    if s.startswith("http://") or s.startswith("https://"):
        u = urlparse(s)
        # běžné public URL: https://storage.googleapis.com/<bucket>/<object>
        # případně mediaLink/selfLink (mají taky /<bucket>/<object> v path)
        parts = [p for p in u.path.split("/") if p]  # rozsekej a odfiltruj prázdné
        if not parts:
            return ""
        # najdi segment bucketu a vezmi zbytek jako object key
        key = ""
        for i, seg in enumerate(parts):
            if seg == bucket_name:
                key = "/".join(parts[i+1:])
                break
        if not key:
            # fallback: pokud path nezačíná bucketem (např. reverzní proxy), zkus bez 1. segmentu
            key = "/".join(parts[1:]) if len(parts) > 1 else parts[0]
        s = key

    s = unquote(s).lstrip("/")

    # bezpečnost: nechceme omylem mazat něco mimo náš „prostor“
    if not s.startswith("anime/"):
        # chceš-li povolit i jiné prefixy, přidej je sem:
        # if s.startswith(("anime/", "public/videos/", "public/subtitles/")): ...
        return ""

    return s

def handle_delete_file(handler):
    try:
        body = handler._read_body() or {}
        raw = body.get("path") or body.get("url") or body.get("public_url") or body.get("src") or ""
        path = _normalize_gcs_path(raw, BUCKET_NAME)

        if not path:
            return _json(handler, 400, {"ok": False, "error": "missing or invalid path"})

        bucket = _get_bucket()
        if bucket:
            try:
                blob = bucket.blob(path)
                blob.delete(if_generation_match=None)  # idempotentní
                return _json(handler, 200, {"ok": True, "deleted": path, "scope": "gcs"})
            except Exception as e:
                # Pokud nemáš storage.objects.delete právo, vrátí 403 — řekneme to nahlas
                return _json(handler, 400, {"ok": False, "error": f"gcs_delete_failed: {e}", "path": path})

        # --- Lokální fallback (dev režim)
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        dst = os.path.abspath(os.path.join(root, path))
        if os.path.exists(dst):
            os.remove(dst)
        return _json(handler, 200, {"ok": True, "deleted": path, "scope": "local"})
    except Exception as e:
        traceback.print_exc()
        return _json(handler, 400, {"ok": False, "error": str(e)})
