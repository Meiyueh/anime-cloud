from . import gcs, settings
from .utils import safe_name, guess_mime
import cgi

def _parse_multipart(handler):
    env = {
        'REQUEST_METHOD': 'POST',
        'CONTENT_TYPE': handler.headers.get('Content-Type', ''),
        'CONTENT_LENGTH': handler.headers.get('Content-Length', '0'),
    }
    fs = cgi.FieldStorage(fp=handler.rfile, headers=handler.headers, environ=env, keep_blank_values=True)
    out={}
    if fs and fs.list:
        for item in fs.list:
            if not item.name: continue
            if item.filename:
                out[item.name]={"filename": item.filename, "file": item.file}
            else:
                out[item.name]=item.value
    return out

def handle_upload_sign(h):
    d = h._read_body() or {}
    anime   = (d.get("anime") or "").strip().lower()
    episode = int(str(d.get("episode") or "0"))
    quality = (d.get("quality") or "").strip()

    video_name = safe_name(d.get("videoName") or "")
    video_type = d.get("videoType") or "video/mp4"
    subs_name  = safe_name(d.get("subsName") or "") if d.get("subsName") else None
    subs_type  = d.get("subsType") or "application/x-subrip"

    if not anime or not episode or not quality or not video_name:
        return h._json(400, {"ok": False, "error": "missing_fields"})

    ep_folder = f"{int(episode):05d}"
    video_path = f"anime/{anime}/{ep_folder}/{quality}/{video_name}"
    subs_path  = f"anime/{anime}/{ep_folder}/{quality}/{subs_name}" if subs_name else None

    try:
        v_signed = gcs.signed_put_url(video_path, video_type, minutes=60)
        s_signed = gcs.signed_put_url(subs_path, subs_type, minutes=60) if subs_path else None
        return h._json(200, {
            "ok": True,
            "video": {"put_url": v_signed, "public_url": gcs.public_url(video_path), "content_type": video_type},
            "subs":  ({"put_url": s_signed, "public_url": gcs.public_url(subs_path), "content_type": subs_type} if s_signed else None)
        })
    except Exception as e:
        return h._json(500, {"ok": False, "error": f"sign_failed: {e.__class__.__name__}: {e}"})

def handle_upload(h):
    ctype = h.headers.get("Content-Type","")
    if not ctype.startswith("multipart/form-data"):
        return h._json(400, {"ok": False, "error": "expected_multipart"})

    form = _parse_multipart(h)
    anime   = (form.get("anime") or "").strip().lower()
    episode = int(form.get("episode") or 0)
    quality = (form.get("quality") or "").strip()
    v_item  = form.get("video")
    s_item  = form.get("subs")

    vname = safe_name(form.get("videoName") or (v_item or {}).get("filename") or "video.mp4")
    if "." not in vname: vname += ".mp4"
    sname = safe_name(form.get("subsName")  or (s_item or {}).get("filename") or "subs.srt")

    if not anime or not episode or not quality or not v_item:
        return h._json(400, {"ok": False, "error": "missing_fields"})

    ep_folder = f"{int(episode):05d}"
    v_mime = guess_mime(vname, default="video/mp4")
    s_mime = guess_mime(sname, default="application/x-subrip")

    v_path = f"anime/{anime}/{ep_folder}/{quality}/{vname}"
    s_path = f"anime/{anime}/{ep_folder}/{quality}/{sname}"

    v_blob = gcs.bucket().blob(v_path); v_blob.cache_control="public, max-age=31536000, immutable"
    v_file = v_item["file"]; v_file.seek(0)
    v_blob.upload_from_file(v_file, content_type=v_mime, rewind=True)

    s_url = None
    if s_item:
        s_blob = gcs.bucket().blob(s_path); s_blob.cache_control="public, max-age=31536000, immutable"
        s_file = s_item["file"]; s_file.seek(0)
        s_blob.upload_from_file(s_file, content_type=s_mime, rewind=True)
        s_url = gcs.public_url(s_path)

    return h._json(200, {"ok": True, "video": gcs.public_url(v_path), "subs": s_url})

def handle_delete_file(h):
    d = h._read_body()
    anime = (d.get("anime") or "").strip().lower()
    episode = int(d.get("episode") or 0)
    quality = (d.get("quality") or "").strip()
    name = safe_name(d.get("videoName") or "")
    if not anime or not episode or not quality or not name:
        return h._json(400, {"ok":False,"error":"Missing"})
    ep_folder = f"{int(episode):05d}"
    path = f"anime/{anime}/{ep_folder}/{quality}/{name}"
    ok = gcs.delete(path)
    return h._json(200 if ok else 404, {"ok":ok})
