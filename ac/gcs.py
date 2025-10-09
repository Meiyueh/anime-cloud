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

def read_json(path: str, default=None):
    b = _bucket.blob(path)
    if not b.exists(): return default
    data = b.download_as_bytes()
    try: return json.loads(data.decode("utf-8"))
    except Exception: return default

def write_json(path: str, obj):
    raw = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    _bucket.blob(path).upload_from_string(raw, content_type="application/json; charset=utf-8")

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
