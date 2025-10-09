from urllib.parse import quote
from google.cloud import storage
from . import settings
import datetime as _dt, json

_client = storage.Client()
_bucket = _client.bucket(settings.GCS_BUCKET)

def bucket(): return _bucket

def public_url(path: str) -> str:
    parts = [quote(p) for p in path.split("/")]
    return f"https://storage.googleapis.com/{settings.GCS_BUCKET}/{'/'.join(parts)}"

def read_json(path: str, default=None, *, generation=None):
    """
    Načte JSON přímo z GCS. Když je zadána generation, načte přesně tu verzi objektu
    (silná konzistence a jistota read-after-write).
    """
    try:
        bl = _bucket.blob(path, generation=generation) if generation else _bucket.blob(path)
        if not bl.exists():
            return default
        data = bl.download_as_bytes()  # jde přímo přes GCS klienta (ne přes HTTP/CDN)
        return json.loads(data.decode("utf-8"))
    except Exception:
        return default

def write_json(path: str, obj):
    """
    Zapíše JSON a vrátí generation nové verze (int). Navíc nastaví Cache-Control: no-store,
    aby se přes případné HTTP cesty nikdy nevrátila stará verze.
    """
    bl = _bucket.blob(path)
    bl.cache_control = "no-store, max-age=0"
    bl.content_type = "application/json; charset=utf-8"
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    bl.upload_from_string(raw, content_type="application/json; charset=utf-8")
    try:
        bl.patch()  # persist Cache-Control
    except Exception:
        pass
    # vrátíme generation pro read-after-write kontrolu v auth.verify
    return int(bl.generation or 0)

def upload_bytes(path: str, raw: bytes, mime: str, cache_immutable=False):
    bl = _bucket.blob(path)
    if cache_immutable:
        bl.cache_control = "public, max-age=31536000, immutable"
    bl.upload_from_string(raw, content_type=mime or "application/octet-stream")
    return public_url(path)

def delete(path: str):
    bl = _bucket.blob(path)
    if bl.exists(): bl.delete(); return True
    return False

def list_prefix(prefix: str):
    return list(_client.list_blobs(settings.GCS_BUCKET, prefix=prefix))

def signed_put_url(path: str, content_type: str, minutes: int=30) -> str:
    bl = _bucket.blob(path)
    return bl.generate_signed_url(
        version="v4",
        expiration=_dt.timedelta(minutes=minutes),
        method="PUT",
        content_type=content_type or "application/octet-stream",
    )
