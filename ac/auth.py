import json, time, smtplib, os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from urllib.parse import parse_qs
from . import settings, gcs
from .utils import now_iso, gen_token, hash_password, verify_password, safe_name

# --- users storage helpers ---
def _user_path(email:str)->str:
    base = settings.USERS_JSON_CLOUD.rstrip("/")
    return f"{base}/{email.lower()}.json"

def load_user(email:str):
    return gcs.read_json(_user_path(email), None)

def save_user(u:dict):
    return gcs.write_json(_user_path(u["email"]), u)

# --- token index (aby verify fungovalo 1:1) ---
def _token_index_path(tok:str)->str:
    return f"{settings.TOKEN_INDEX_PREFIX}/{tok}.json"

def token_index_put(tok:str, email:str, exp:int):
    gcs.write_json(_token_index_path(tok), {"email": email.lower(), "exp": int(exp or 0)})

def token_index_get(tok:str):
    rec = gcs.read_json(_token_index_path(tok), None)
    if not rec: return None
    try: exp = int(rec.get("exp") or 0)
    except Exception: exp = 0
    if exp and time.time() > exp:
        try: gcs.delete(_token_index_path(tok))
        except Exception: pass
        return None
    return (rec.get("email") or "").lower() or None

def token_index_delete(tok:str):
    try: gcs.delete(_token_index_path(tok))
    except Exception: pass

# --- utilities shared with server ---
def parse_body(raw:bytes, ctype:str):
    if "application/json" in ctype:
        try: return json.loads(raw.decode("utf-8"))
        except Exception: return {}
    if "application/x-www-form-urlencoded" in ctype:
        qs = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        return {k:(v[0] if isinstance(v,list) else v) for k,v in qs.items()}
    return {}

# --- email sender ---
def send_verification_email(to_email:str, verify_url:str):
    if settings.DEV_ECHO_VERIFICATION_LINK:
        print("[DEV] Verification link:", verify_url)

    msg = MIMEMultipart("alternative")
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USER or "no-reply@example.com"
    msg["To"] = to_email
    # Předmět
    msg["Subject"] = "Potvrď e-mail a aktivuj účet • AnimeCloud"
    
    # Plain-text fallback
    text = (
        "Vítej v AnimeCloud!\n\n"
        "Potvrď prosím svůj e-mail kliknutím na tento odkaz:\n"
        f"{verify_url}\n\n"
        "Pokud jsi o účet nežádal/a, tenhle e-mail ignoruj.\n"
    )
    
    # Připravíme inline logo (CID). Pokusíme se načíst SVG z repo cesty.
    cid_logo = "logo_ac"
    _logo_attached = False
    try:
        assets_dir = getattr(settings, "ASSETS_DIR", "assets")
        logo_path = getattr(settings, "EMAIL_LOGO_PATH", os.path.join(assets_dir, "logo.svg"))
        with open(logo_path, "rb") as f:
            part = MIMEBase("image", "svg+xml")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-ID", f"<{cid_logo}>")
        part.add_header("Content-Disposition", "inline", filename=os.path.basename(logo_path))
        msg.attach(part)
        _logo_attached = True
    except Exception as e:
        print("[MAIL] logo attach skipped:", e)
    
    # HTML verze (tabulky kvůli kompatibilitě; inline CSS; button funguje i v Outlooku)
    html = f"""\
    <!doctype html>
    <html lang="cs">
    <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Ověření účtu • AnimeCloud</title>
    <style>
      /* mobilní reset */
      @media (max-width:600px) {{
        .container {{ width: 100% !important; }}
        .card {{ padding: 20px !important; }}
        .btn a {{ display:block !important; }}
      }}
    </style>
    </head>
    <body style="margin:0;padding:0;background:#0e0e12;color:#fff;">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#0e0e12;">
        <tr>
          <td align="center" style="padding:24px 12px;">
            <table role="presentation" class="container" width="600" cellspacing="0" cellpadding="0" border="0" style="width:600px;max-width:100%;">
              <tr>
                <td align="left" style="padding:0 8px 18px 8px;">
                  {"<img src=\"cid:" + cid_logo + "\" alt=\"AnimeCloud\" width=\"140\" style=\"display:block;height:auto;border:0\">" if _logo_attached else "<div style='font:600 18px/1.2 system-ui,Segoe UI,Roboto;letter-spacing:.3px;color:#cfcff5'>AnimeCloud</div>"}
                </td>
              </tr>
              <tr>
                <td class="card" style="background:#181820;border:1px solid #2a2a36;border-radius:16px;padding:28px;">
                  <h1 style="margin:0 0 10px 0;font:700 22px/1.3 system-ui,Segoe UI,Roboto;color:#ffffff;">
                    Vítej v AnimeCloud 👋
                  </h1>
                  <p style="margin:0 0 16px 0;font:400 15px/1.6 system-ui,Segoe UI,Roboto;color:#d7d7e6;">
                    Potvrď prosím svůj e-mail kliknutím na tlačítko níže. Tím aktivuješ svůj účet.
                  </p>
    
                  <!-- Bulletproof button (tabulka) -->
                  <table role="presentation" cellspacing="0" cellpadding="0" border="0" class="btn" style="margin:18px 0 10px 0;">
                    <tr>
                      <td align="center" bgcolor="#7c5cff" style="border-radius:10px;">
                        <a href="{verify_url}" target="_blank"
                           style="font:600 15px/1 system-ui,Segoe UI,Roboto; color:#ffffff; text-decoration:none; padding:13px 18px; display:inline-block; border-radius:10px;">
                          Ověřit účet
                        </a>
                      </td>
                    </tr>
                  </table>
    
                  <p style="margin:12px 0 0 0;font:400 13px/1.6 system-ui,Segoe UI,Roboto;color:#a9a9bf;word-break:break-all;">
                    Pokud tlačítko nefunguje, zkopíruj tento odkaz do prohlížeče:<br>
                    <a href="{verify_url}" style="color:#b6a7ff;text-decoration:underline;">{verify_url}</a>
                  </p>
    
                  <hr style="border:0;border-top:1px solid #2a2a36;margin:22px 0;">
                  <p style="margin:0;font:400 12px/1.6 system-ui,Segoe UI,Roboto;color:#9494ad;">
                    Pokud jsi registraci nevyžadoval/a, můžeš tento e-mail ignorovat. Odkaz má časově omezenou platnost.
                  </p>
                </td>
              </tr>
              <tr>
                <td align="center" style="padding:16px 8px 0 8px;color:#7c7c9a;font:400 12px/1.6 system-ui,Segoe UI,Roboto;">
                  © {time.gmtime().tm_year} AnimeCloud
                </td>
              </tr>
              <tr><td style="height:12px;">&nbsp;</td></tr>
            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
    """
    
    # připojit části
    msg.attach(MIMEText(text, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    if settings.DEV_SAVE_LAST_EMAIL:
        with open("last_email.eml", "wb") as f: f.write(msg.as_bytes())

    if not (settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_PASS):
        print("[WARN] SMTP není kompletně nastaven – e-mail se neodeslal.")
        return

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30) as s:
        if settings.SMTP_DEBUG: s.set_debuglevel(1)
        if settings.SMTP_STARTTLS: s.starttls()
        s.ehlo()
        s.login(settings.SMTP_USER, settings.SMTP_PASS)
        s.sendmail(msg["From"], [to_email], msg.as_string())

# --- pages ---
def _verify_page(ok:bool, msg:str, redirect:str=None, delay_ms:int=0) -> str:
    meta = f'<meta http-equiv="refresh" content="{delay_ms/1000};url={redirect}">' if redirect else ""
    js   = f'<script>setTimeout(function(){{location.href="{redirect}";}}, {delay_ms});</script>' if redirect else ""
    color = "#9ef39b" if ok else "#ffb3b3"
    return f"""<!doctype html><html lang="cs"><head><meta charset="utf-8">{meta}
<title>Ověření účtu</title>
<style>body{{background:#0e0e12;color:#fff;font-family:system-ui;}}
.card{{max-width:720px;margin:60px auto;background:#181820;border:1px solid #2a2a36;border-radius:14px;padding:24px}}
h1{{margin:0 0 10px}} .msg{{color:{color};line-height:1.6}} a{{color:#7c5cff}}</style></head>
<body><div class="card"><h1>Ověření účtu</h1><p class="msg">{msg}</p></div>{js}</body></html>"""

# --- handlers ---
def handle_register(h):
    d = h._read_body()
    email = (d.get("email") or "").strip().lower()
    name  = (d.get("name") or email.split("@")[0]).strip()
    p1 = (d.get("password") or d.get("pass") or "").strip()
    p2 = (d.get("password2") or d.get("password_confirm") or d.get("confirm") or d.get("pass2") or p1).strip()

    if not email or not p1 or not p2:
        return h._json(400, {"ok": False, "error": "missing_fields"})

    import re
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return h._json(400, {"ok": False, "error": "invalid_email"})
    if p1 != p2:
        return h._json(400, {"ok": False, "error": "password_mismatch"})
    if load_user(email):
        return h._json(409, {"ok": False, "error": "email_exists"})

    # 1) spočti hash a hned si ověř, že verify_password na něj vrátí True
    new_hash = hash_password(p1)
    try:
        _selfcheck = verify_password(p1, new_hash)
    except Exception:
        _selfcheck = False
    print("[REGDBG2] email=", email,
          "len_pwd=", len(p1),
          "new_hash_prefix=", new_hash[:30],
          "selfcheck_ok=", _selfcheck)

    # 2) ulož uživatele s tímto hashem
    u = {
        "email": email,
        "name": name,
        "password_hash": new_hash,
        "verified": False,
        "role": "user",
        "created_at": now_iso(),
        "verify_token": gen_token(),
        "verify_expires": int(time.time()) + 60*60*48,
    }
    try:
        gen_user = save_user(u)  # měla by vracet generation z gcs.write_json
    except TypeError:
        gen_user = None

    # 3) přečti zpět přesně tuhle generaci a taky „latest“
    try:
        pth = _user_path(email)
        u_gen = gcs.read_json(pth, None, generation=gen_user) if gen_user else None
        u_latest = gcs.read_json(pth, None)
        print("[REGDBG2-READBACK]",
              "gen=", gen_user,
              "hash@gen_prefix=", (u_gen.get("password_hash","")[:30] if u_gen else None),
              "hash@latest_prefix=", (u_latest.get("password_hash","")[:30] if u_latest else None),
              "users_root=", settings.USERS_JSON_CLOUD)
    except Exception as e:
        print("[REGDBG2-READBACK] ERROR:", e)

    # 4) index tokenu a mail jako dřív
    tok, exp = u["verify_token"], u["verify_expires"]
    try:
        token_index_put(tok, email, exp)
    except Exception as e:
        print("[TOKEN-INDEX] put failed:", e)

    base = (settings.PUBLIC_BASE_URL or f"http://{h.headers.get('Host') or f'127.0.0.1:{settings.PORT}'}").rstrip("/")
    verify_url = f"{base}/auth/verify?t={tok}"
    try:
        send_verification_email(email, verify_url)
    except Exception as e:
        print("[MAIL] send error:", e)

    if settings.DEV_ECHO_VERIFICATION_LINK:
        print("[DEV] Verification link:", verify_url)

    return h._json(200, {"ok": True, "verify_url": verify_url, "gen": int(gen_user or 0)})

def handle_verify(h, parsed):
    qs = parse_qs(parsed.query)
    tok = (qs.get("t", [""])[0]).strip()
    email_from_index = token_index_get(tok) if tok else None

    # Fallback: starý tvar ?email=...&token=...
    email_q = (qs.get("email", [""])[0]).strip().lower()
    token_q = (qs.get("token", [""])[0]).strip()

    if not (tok or (email_q and token_q)):
        return h._html(400, _verify_page(False, "Ověření selhalo<br/>Chybí token."))

    # Vyber email + token z toho, co reálně máme
    email = (email_from_index or email_q or "").lower()
    tok_effective = tok or token_q

    u = load_user(email)
    if not u:
        return h._html(400, _verify_page(False, "Ověření selhalo<br/>Uživatel nenalezen."))

    # Už ověřený účet – přátelská odpověď
    if u.get("verified"):
        return h._html(200, _verify_page(True, "Účet už byl ověřen ✅", redirect="/login.html", delay_ms=800))

    # Expirace odkazu
    try:
        exp = int(u.get("verify_expires") or 0)
    except Exception:
        exp = 0
    if exp and time.time() > exp:
        return h._html(400, _verify_page(False, "Odkaz vypršel. Požádej o nový v aplikaci."))

    # Přijmout, pokud (a) index vrací email NEBO (b) URL token = user.verify_token
    stored_tok = (u.get("verify_token") or "").strip()
    if email_from_index is None and tok_effective != stored_tok:
        return h._html(400, _verify_page(False, "Token je neplatný. Požádej o nový ověřovací e-mail."))

    # Zapiš ověření a zneplatni token
    u["verified"] = True
    u["verified_at"] = now_iso()
    u["verify_token"] = None
    u["verify_expires"] = None
    gen = save_user(u)  # <- získáme generation nové verze objektu

    # Smaž token z indexu (pokud existuje)
    if tok_effective:
        try:
            token_index_delete(tok_effective)
        except Exception as e:
            print("[TOKEN-INDEX] delete failed:", e)

    # Silná validace: načti přes přesnou generation
    u_after = gcs.read_json(_user_path(email), None, generation=gen)

    # Měkký retry (3× krátká pauza), kdyby 'latest' ještě nebyl k dispozici bez generation
    if not (u_after and u_after.get("verified")):
        for _ in range(3):
            time.sleep(0.15)
            u_after = gcs.read_json(_user_path(email), None)
            if u_after and u_after.get("verified"):
                break

    if not (u_after and u_after.get("verified")):
        print("[VERIFY] WARN: read-after-write mismatch for", email, "USERS_JSON_CLOUD=", settings.USERS_JSON_CLOUD, "gen=", gen)
        return h._html(500, _verify_page(
            False,
            "Ověření proběhlo, ale uložení selhalo na úložišti. Zkus to za chvíli znovu nebo kontaktuj podporu."
        ))

    print(f"[VERIFY] {email} verified=True at {u_after.get('verified_at')}")
    return h._html(200, _verify_page(True, "Účet ověřen ✅<br/>Nyní se můžeš přihlásit.", redirect="/login.html", delay_ms=1200))


def handle_resend(h):
    d = h._read_body()
    email = (d.get("email") or "").strip().lower()
    u = load_user(email)
    if not u: return h._json(404, {"ok":False,"error":"not_found"})
    if u.get("verified"): return h._json(400, {"ok":False,"error":"already_verified"})

    u["verify_token"] = gen_token()
    u["verify_expires"] = int(time.time()) + 60*60*48
    save_user(u)

    tok, exp = u["verify_token"], u["verify_expires"]
    try: token_index_put(tok, email, exp)
    except Exception as e: print("[TOKEN-INDEX] put failed:", e)

    base = (settings.PUBLIC_BASE_URL or f"http://{h.headers.get('Host') or f'127.0.0.1:{settings.PORT}'}").rstrip("/")
    verify_url = f"{base}/auth/verify?t={tok}"
    try: send_verification_email(email, verify_url)
    except Exception as e: print("[MAIL] send error:", e)
    return h._json(200, {"ok": True, "verify_url": verify_url})

def handle_verify(h, parsed):
    qs = parse_qs(parsed.query)
    tok = (qs.get("t", [""])[0]).strip()
    email_from_index = token_index_get(tok) if tok else None

    # Fallback: starý tvar ?email=...&token=...
    email_q = (qs.get("email", [""])[0]).strip().lower()
    token_q = (qs.get("token", [""])[0]).strip()

    if not (tok or (email_q and token_q)):
        return h._html(400, _verify_page(False, "Ověření selhalo<br/>Chybí token."))

    # Vyber email + token z toho, co reálně máme
    email = (email_from_index or email_q or "").lower()
    tok_effective = tok or token_q

    u = load_user(email)
    if not u:
        return h._html(400, _verify_page(False, "Ověření selhalo<br/>Uživatel nenalezen."))

    # Pokud už je účet ověřený, vrať přátelskou hlášku
    if u.get("verified"):
        return h._html(200, _verify_page(True, "Účet už byl ověřen ✅", redirect="/login.html", delay_ms=800))

    # Kontrola expirace
    try:
        exp = int(u.get("verify_expires") or 0)
    except Exception:
        exp = 0
    if exp and time.time() > exp:
        return h._html(400, _verify_page(False, "Odkaz vypršel. Požádej o nový v aplikaci."))

    # Klíčové zpřísnění: akceptuj ověření, pokud (a) token index vrací tento email NEBO
    # (b) token v URL je totožný s user.verify_token (bez ohledu na index).
    stored_tok = (u.get("verify_token") or "").strip()
    if email_from_index is None and tok_effective != stored_tok:
        # Token index nezná token a zároveň nesedí s tím, co je u uživatele -> odmítnout
        return h._html(400, _verify_page(False, "Token je neplatný. Požádej o nový ověřovací e-mail."))

    # Proveď ověření a zneplatni token
    u["verified"] = True
    u["verified_at"] = now_iso()
    u["verify_token"] = None
    u["verify_expires"] = None
    save_user(u)

    # Pro jistotu smaž záznam z indexu (když existuje)
    if tok_effective:
        try: token_index_delete(tok_effective)
        except Exception as e: print("[TOKEN-INDEX] delete failed:", e)

    # Okamžitá read-after-write validace (odhalí špatný prefix/bucket nebo cache)
    u_after = load_user(email)
    if not (u_after and u_after.get("verified")):
        print("[VERIFY] WARN: read-after-write mismatch for", email, "USERS_JSON_CLOUD=", settings.USERS_JSON_CLOUD)
        return h._html(500, _verify_page(
            False,
            "Ověření proběhlo, ale uložení selhalo na úložišti. Zkus to za chvíli znovu nebo kontaktuj podporu."
        ))

    print(f"[VERIFY] {email} verified=True at {u_after.get('verified_at')}")
    return h._html(200, _verify_page(True, "Účet ověřen ✅<br/>Nyní se můžeš přihlásit.", redirect="/login.html", delay_ms=1200))


def handle_login(h):
    d = h._read_body()
    email = (d.get("email") or "").strip().lower()
    password = (d.get("password") or "").strip()
    if not email or not password:
        return h._json(400, {"ok": False, "error": "missing_fields"})

    path = _user_path(email)
    u = load_user(email)

    # DEBUG LOG – přesně ukáže, co jsme načetli a zda hash sedí
    try:
        pwd_ok = bool(u and verify_password(password, u.get("password_hash", "")))
    except Exception:
        pwd_ok = False
    print("[LOGINDBG]",
          "path=", path,
          "exists=", bool(u),
          "verified=", bool(u and u.get("verified")),
          "pwd_ok=", pwd_ok,
          "len_pwd=", len(password),
          "hash_prefix=", (u.get("password_hash", "")[:30] if u else ""),
          "USERS_JSON_CLOUD=", settings.USERS_JSON_CLOUD)

    if not u or not verify_password(password, u.get("password_hash", "")):
        return h._json(403, {"ok": False, "error": "invalid_credentials"})
    if not u.get("verified"):
        return h._json(403, {"ok": False, "error": "not_verified"})

    token = gen_token()
    payload = {
        "email": u["email"],
        "name": u.get("name"),
        "role": u.get("role", "user"),
        "profile": u.get("profile", {})
    }
    if settings.DEBUG_AUTH:
        print("[AUTH] login ok", payload)
    return h._json(200, {"ok": True, "user": payload, "token": token})


def bootstrap_admin_if_needed():
    if not (settings.ADMIN_BOOT_ENABLE and settings.ADMIN_EMAIL and settings.ADMIN_BOOT_PASSWORD): return
    if load_user(settings.ADMIN_EMAIL):
        print("[BOOT] Admin už existuje – nic nedělám."); return
    u = {
        "email": settings.ADMIN_EMAIL,
        "name": "Administrator",
        "password_hash": hash_password(settings.ADMIN_BOOT_PASSWORD),
        "verified": True,
        "role": "admin",
        "created_at": now_iso(),
        "verify_token": None,
        "verify_expires": None
    }
    save_user(u)
    print(f"[BOOT] Vytvořen admin účet: {settings.ADMIN_EMAIL}. Nezapomeň ADMIN_BOOT_ENABLE=false v .env.")
