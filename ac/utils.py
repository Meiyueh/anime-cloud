import os, base64, hashlib, hmac, datetime

VIDEO_EXTS = (".mp4",".m4v",".webm",".mkv",".mov")
SUBS_EXTS  = (".srt",".vtt")

EXT_MIME = {
  ".mp4":"video/mp4",".m4v":"video/x-m4v",".webm":"video/webm",".mkv":"video/x-matroska",".mov":"video/quicktime",
  ".srt":"application/x-subrip",".vtt":"text/vtt",
  ".jpg":"image/jpeg",".jpeg":"image/jpeg",".png":"image/png",".webp":"image/webp",".gif":"image/gif",
}

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

def gen_token(nbytes=24)->str:
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("=")

def safe_name(name: str) -> str:
    if isinstance(name, bytes): name = name.decode("utf-8","ignore")
    keep = "._-()[]{}@+&= "
    name = "".join(ch for ch in name if ch.isalnum() or ch in keep)
    return name.replace("/", "").replace("\\", "").strip() or "file"

def guess_mime(filename: str, sniff: bytes|None=None, default="application/octet-stream"):
    fn = (filename or "").lower()
    for ext, mime in EXT_MIME.items():
        if fn.endswith(ext): return mime
    if sniff:
        if sniff.startswith(b"\x89PNG"): return "image/png"
        if sniff[:3] == b"\xff\xd8\xff": return "image/jpeg"
        if sniff.startswith(b"RIFF") and b"WEBP" in sniff[:16]: return "image/webp"
        if sniff[:4] == b"\x1a\x45\xdf\xa3": return "video/x-matroska"
        if sniff[:4] == b"ftyp": return "video/mp4"
    return default

def hash_password(password:str, salt:bytes=None, iterations:int=200_000)->str:
    if salt is None: salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2-sha256:{iterations}:{base64.urlsafe_b64encode(salt).decode()}:{dk.hex()}"

def verify_password(password:str, stored:str)->bool:
    try:
        algo, iters, salt_b64, hexhash = stored.split(":",3)
        if algo != "pbkdf2-sha256": return False
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        iters = int(iters)
        calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters).hex()
        return hmac.compare_digest(calc, hexhash)
    except Exception:
        return False
