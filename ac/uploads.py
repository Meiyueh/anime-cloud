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
    """
    Smaže jeden nebo více souborů z GCS (nebo lokální fallback).
    Umí smazat i párové .srt titulky ke smazanému videu (stejný basename).

    Přijímané tvary payloadu:
      - {"path": "anime/<slug>/epNNN/<q>/<soubor>"}
      - {"paths": ["anime/...","anime/..."]}
      - {"url": "https://storage.googleapis.com/<bucket>/anime/..."}  # URL -> key
      - {"public_url": "..."}                                         # URL -> key
      - Legacy: {"anime":"one-piece","episode":45,"quality":"1080p","videoName":"1080p_1.mp4"}
               (+ volitelně "subsName": "1080p_1.srt")

    Vrací JSON: { ok, deleted:[...], not_found:[...], errors:[{path,error}] }
    """
    try:
        body = handler._read_body() or {}

        # --- nasbírej kandidáty ---
        candidates = []

        # 1) path (string)
        p = body.get("path")
        if isinstance(p, str) and p.strip():
            candidates.append(p.strip())

        # 2) paths (pole)
        ps = body.get("paths")
        if isinstance(ps, (list, tuple)):
            for it in ps:
                if isinstance(it, str) and it.strip():
                    candidates.append(it.strip())

        # 3) url / public_url (stringy)
        for k in ("url", "public_url"):
            u = body.get(k)
            if isinstance(u, str) and u.strip():
                candidates.append(u.strip())

        # 4) legacy tvar (video)
        slug = body.get("slug") or body.get("anime")
        ep   = body.get("episode") or body.get("ep")
        q    = body.get("quality") or body.get("q")
        vname= body.get("name") or body.get("videoName")
        if slug and ep is not None and q and vname:
            candidates.append(f"anime/{slug}/ep{str(int(ep)).zfill(3)}/{q}/{vname}")

        # 5) legacy tvar (subs explicitně – pokud je uveden)
        sname = body.get("subs") or body.get("subsName")
        if slug and ep is not None and q and sname:
            candidates.append(f"anime/{slug}/ep{str(int(ep)).zfill(3)}/{q}/{sname}")

        # --- normalizace: URL -> object name ---
        from urllib.parse import urlparse, unquote
        norm = []
        for x in candidates:
            s = (x or "").strip()
            if not s:
                continue
            if s.startswith(("http://", "https://")):
                u = urlparse(s)
                # očekáváme tvar /<bucket>/<key...>
                parts = u.path.split("/", 2)  # ["", "bucket", "key..."]
                if len(parts) >= 3 and parts[2]:
                    key = parts[2].lstrip("/")
                    norm.append(unquote(key))
                else:
                    key = u.path.lstrip("/")
                    if key:
                        norm.append(unquote(key))
            elif s.startswith("gs://"):
                after = s[5:]  # po "gs://"
                idx = after.find("/")
                key = after[idx+1:] if idx != -1 else ""
                key = key.lstrip("/")
                if key:
                    norm.append(unquote(key))
            else:
                norm.append(s.lstrip("/"))

        # --- rozšíření o párové .srt titulky ke VIDEÍM ---
        # Pokud soubor není .srt, přidáme i stejnojmenné .srt ve stejném adresáři.
        expanded = []
        for key in norm:
            if not key:
                continue
            expanded.append(key)
            # přidej párové SRT jen když nejde už o .srt
            name = key.rsplit("/", 1)[-1]
            dir_ = key[:-len(name)].rstrip("/")  # prefix s lomítkem nebo prázdný
            if "." in name:
                base, ext = name.rsplit(".", 1)
                if ext.lower() != "srt" and base:
                    srt_key = (dir_ + "/" if dir_ else "") + base + ".srt"
                    expanded.append(srt_key)

        # deduplikace
        seen = set()
        paths = [p for p in expanded if p and not (p in seen or seen.add(p))]

        if not paths:
            return _json(handler, 400, {"ok": False, "error": "missing path"})

        bucket = _get_bucket()
        deleted, not_found, errors = [], [], []

        if bucket:
            try:
                from google.api_core.exceptions import NotFound
            except Exception:
                class NotFound(Exception):
                    pass

            for key in paths:
                try:
                    blob = bucket.blob(key)
                    blob.delete(if_generation_match=None)
                    deleted.append(key)
                except NotFound:
                    not_found.append(key)
                except Exception as e:
                    errors.append({"path": key, "error": str(e)})

            code = 200 if not errors else 207
            return _json(handler, code, {
                "ok": len(errors) == 0,
                "deleted": deleted,
                "not_found": not_found,
                "errors": errors
            })

        # --- Lokální fallback (pokud není GCS bucket k dispozici) ---
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        for key in paths:
            try:
                dst = os.path.abspath(os.path.join(root, key))
                if os.path.exists(dst):
                    os.remove(dst)
                    deleted.append(key)
                else:
                    not_found.append(key)
            except Exception as e:
                errors.append({"path": key, "error": str(e)})

        code = 200 if not errors else 207
        return _json(handler, code, {
            "ok": len(errors) == 0,
            "deleted": deleted,
            "not_found": not_found,
            "errors": errors
        })

    except Exception as e:
        traceback.print_exc()
        return _json(handler, 400, {"ok": False, "error": str(e)})
