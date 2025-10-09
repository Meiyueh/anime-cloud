import json, time
from . import gcs, settings
from .utils import safe_name

def _normalize_ticket(rec: dict) -> dict:
    if not isinstance(rec, dict): return {}
    rec.setdefault("id", f"tkt_{int(time.time()*1000)}")
    rec.setdefault("status", "open")
    rec.setdefault("ts", int(time.time()*1000))
    if "messages" not in rec or not isinstance(rec["messages"], list) or not rec["messages"]:
        init = (rec.get("message") or "").strip()
        author = rec.get("user") or rec.get("name") or "anonym"
        rec["messages"] = ([{"id": rec["id"]+"_0","role":"user","author":author,"text":init,"ts":rec["ts"]}] if init else [])
    rec.pop("message", None)
    return rec

def handle_feedback_save(h):
    d = h._read_body()
    d = _normalize_ticket(d or {})
    fid = safe_name(d.get("id") or f"tkt_{int(time.time()*1000)}")
    path = f"{settings.FEEDBACK_PREFIX}/{fid}.json"
    gcs.write_json(path, d)
    return h._json(200, {"ok":True})

def handle_feedback_update(h):
    d = h._read_body()
    fid = safe_name(d.get("id") or "")
    if not fid: return h._json(400, {"ok":False,"error":"missing_id"})
    path = f"{settings.FEEDBACK_PREFIX}/{fid}.json"
    cur = gcs.read_json(path, {})
    if not cur: return h._json(404, {"ok":False,"error":"not_found"})
    cur = _normalize_ticket(cur)

    msg = (d.get("message") or "").strip()
    if msg:
        cur.setdefault("messages", [])
        cur["messages"].append({
            "id": f"{fid}_{len(cur['messages'])+1}",
            "role": d.get("role") or "admin",
            "author": d.get("author") or "admin",
            "text": msg,
            "ts": int(time.time()*1000)
        })
    if d.get("status"):
        cur["status"] = d["status"]

    gcs.write_json(path, cur)
    return h._json(200, {"ok":True, "saved":cur})

def handle_feedback_list(h):
    blobs = gcs.list_prefix(settings.FEEDBACK_PREFIX + "/")
    out = []
    for b in blobs:
        if not b.name.endswith(".json"): continue
        try:
            data = json.loads(b.download_as_bytes().decode("utf-8"))
            out.append(_normalize_ticket(data))
        except Exception:
            pass
    out.sort(key=lambda x: x.get("ts", 0), reverse=True)
    return h._json(200, {"ok":True, "items": out})
