import json, base64, re
from . import gcs, settings
from .utils import safe_name, guess_mime, VIDEO_EXTS

def handle_anime_json(h):
    data = gcs.read_json(settings.ANIME_JSON_CLOUD, []) or []
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    h.send_response(200)
    h.send_header("Content-Type","application/json; charset=utf-8")
    h.send_header("Cache-Control","no-store")
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)

def handle_add_anime(h):
    d = h._read_body()
    req = ["slug","title","episodes","genres","description","cover","status","year","studio"]
    if not all(k in d for k in req):
        return h._json(400, {"ok":False,"error":"missing_fields"})
    slug = safe_name(str(d["slug"]).lower())
    cover_in = d.get("cover")

    cover_path = ""
    if isinstance(cover_in, str) and cover_in.startswith("data:"):
        m = re.match(r"^data:(?P<mime>[\w/+.-]+);base64,(?P<b64>.*)$", cover_in, re.DOTALL)
        if not m: return h._json(400, {"ok":False,"error":"invalid_cover"})
        mime = m.group("mime").lower()
        raw  = base64.b64decode(m.group("b64"), validate=True)
        ext = {"image/jpeg":"jpg","image/jpg":"jpg","image/png":"png","image/webp":"webp","image/gif":"gif"}.get(mime,"jpg")
        cover_path = f"covers/{slug}.{ext}"
        cover_url  = gcs.upload_bytes(cover_path, raw, mime, cache_immutable=True)
    else:
        cover_url = str(cover_in or "")

    try:
        item = {
            "slug": slug,
            "title": str(d["title"]),
            "episodes": int(d["episodes"]),
            "genres": list(d["genres"]),
            "description": str(d["description"]),
            "cover": cover_url if cover_url.startswith("http") else cover_path if cover_url else "",
            "status": str(d["status"]),
            "year": int(d["year"]),
            "studio": str(d["studio"]),
        }
    except Exception as e:
        return h._json(400, {"ok":False, "error":f"fields:{e}"})

    items = gcs.read_json(settings.ANIME_JSON_CLOUD, []) or []
    items = [a for a in items if a.get("slug") != slug]
    items.append(item)
    gcs.write_json(settings.ANIME_JSON_CLOUD, items)
    return h._json(200, {"ok":True, "saved": item, "anime_json_url": gcs.public_url(settings.ANIME_JSON_CLOUD)})

def handle_upload_cover(h):
    from .uploads import _parse_multipart
    fields = _parse_multipart(h)
    slug = (fields.get("slug") or "").strip().lower()
    c_field = fields.get("cover")
    if not slug or not isinstance(c_field, dict):
        return h._json(400, {"ok":False,"error":"Missing"})
    mime = guess_mime(c_field.get("filename") or "cover.jpg", default="image/jpeg")
    ext = {"image/png":"png","image/webp":"webp","image/gif":"gif","image/jpeg":"jpg"}.get(mime,"jpg")
    path = f"covers/{slug}.{ext}"
    blob = gcs.bucket().blob(path); blob.cache_control="public, max-age=31536000, immutable"
    f = c_field["file"]; f.seek(0)
    blob.upload_from_file(f, content_type=mime)
    return h._json(200, {"ok":True, "path": gcs.public_url(path)})

def handle_upload_counts(h):
    blobs = gcs.list_prefix("anime/")
    ep_by_anime = {}
    for b in blobs:
        name = b.name
        if not name.startswith("anime/"): continue
        if not any(name.lower().endswith(ext) for ext in VIDEO_EXTS): continue
        parts = name.split("/")
        if len(parts) < 5: continue
        slug = parts[1]; ep_folder = parts[2]
        ep_by_anime.setdefault(slug, set()).add(ep_folder)
    by_anime = {slug: len(s) for slug, s in ep_by_anime.items()}
    return h._json(200, {"ok":True, "by_anime": by_anime})

def handle_stats(h):
    # users
    users_blobs = gcs.list_prefix(settings.USERS_JSON_CLOUD.rstrip("/") + "/")
    total = verified = 0
    import json as _json
    for b in users_blobs:
        if not b.name.endswith(".json"): continue
        total += 1
        try:
            data = _json.loads(b.download_as_bytes().decode("utf-8"))
            if data.get("verified"): verified += 1
        except Exception:
            pass

    # uploads
    blobs = gcs.list_prefix("anime/")
    uploads_total = 0
    ep_by_anime = {}
    for b in blobs:
        name_raw = b.name
        if not any(name_raw.lower().endswith(ext) for ext in VIDEO_EXTS): continue
        parts = name_raw.split("/")
        if len(parts) < 5: continue
        slug = parts[1]; ep_folder = parts[2]
        uploads_total += 1
        ep_by_anime[(slug, ep_folder)] = 1

    counts={}
    for (slug,_ep) in ep_by_anime.keys():
        counts[slug] = counts.get(slug,0)+1
    top_anime=None
    if counts:
        slug_top, n = max(counts.items(), key=lambda kv: kv[1])
        top_anime={"slug": slug_top, "episodes_uploaded": n}

    return h._json(200, {
        "ok": True,
        "users_total": total,
        "users_verified": verified,
        "uploads_total": uploads_total,
        "top_anime": top_anime
    })
