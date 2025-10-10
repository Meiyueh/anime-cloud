# ac/uploads.py
import os, io, json, cgi, mimetypes, traceback, sys
from datetime import timedelta
from google.cloud import storage

BUCKET_NAME = os.getenv("GCS_BUCKET", "")
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

def handle_upload_sign(handler):
    """POST JSON: { path, content_type | ctype | type } → { upload_url, public_url }"""
    try:
        body = handler._read_body() or {}
        path = (body.get("path") or "").lstrip("/")
        ctype = body.get("content_type") or body.get("ctype") or body.get("type") or "application/octet-stream"
        if not path:
            print("[UPLOAD] missing path v /upload/sign", file=sys.stderr)
            return _json(handler, 400, {"ok": False, "error": "missing path"})
        bucket = _get_bucket()
        if not bucket:
            return _json(handler, 400, {"ok": False, "error": "bucket not configured"})
        blob = bucket.blob(path)
        upload_url = blob.generate_signed_url(
            version="v4", expiration=timedelta(minutes=15), method="PUT",
            content_type=ctype
        )
        public_url = f"{GCS_PUBLIC_BASE}/{path}" if GCS_PUBLIC_BASE else f"/{path}"
        return _json(handler, 200, {"ok": True, "upload_url": upload_url, "public_url": public_url})
    except Exception as e:
        traceback.print_exc()
        return _json(handler, 400, {"ok": False, "error": str(e)})

def handle_upload(handler):
    """
    Multipart fallback: field 'file' + optional 'path'.
    """
    try:
        import cgi, io, mimetypes, sys
        fs = cgi.FieldStorage(fp=handler.rfile, headers=handler.headers,
                              environ={'REQUEST_METHOD':'POST',
                                       'CONTENT_TYPE': handler.headers.get('Content-Type')})
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
            # ↓↓↓ minimal cache-busting na straně GCS objektu
            blob.cache_control = "public, max-age=0, no-cache"
            blob.upload_from_file(io.BytesIO(raw), content_type=ctype)
            # zajistí zapsání cache_control metadat
            try:
                blob.patch()
            except Exception:
                pass
            public_url = f"{GCS_PUBLIC_BASE}/{path}"
            return _json(handler, 200, {"ok": True, "url": public_url, "path": path})
        else:
            # lokální fallback
            root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            dst = os.path.abspath(os.path.join(root, path))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(raw)
            return _json(handler, 200, {"ok": True, "url": f"/{path}", "path": path})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return _json(handler, 400, {"ok":False,"error":str(e)})

def handle_delete_file(handler):
    try:
        body = handler._read_body() or {}
        path = (body.get("path") or "").lstrip("/")
        if not path:
            return _json(handler, 400, {"ok":False,"error":"missing path"})
        bucket = _get_bucket()
        if bucket:
            blob = bucket.blob(path)
            blob.delete(if_generation_match=None)
            return _json(handler, 200, {"ok": True})
        # local fallback
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        dst = os.path.abspath(os.path.join(root, path))
        if os.path.exists(dst): os.remove(dst)
        return _json(handler, 200, {"ok": True})
    except Exception as e:
        return _json(handler, 400, {"ok":False,"error":str(e)})
