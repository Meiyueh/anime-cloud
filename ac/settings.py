import os, datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_env_dotfile(path=os.path.join(BASE_DIR, ".env")):
    if not os.path.exists(path): return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k,v=line.split("=",1); k=k.strip(); v=v.strip().strip('"').strip("'")
            if k and k not in os.environ: os.environ[k]=v

load_env_dotfile()

PORT = int(os.getenv("PORT","8080"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS","*")
PUBLIC_BASE_URL = (os.getenv("PUBLIC_BASE_URL","").strip().rstrip("/"))

GCS_BUCKET = (os.getenv("GCS_BUCKET") or "").strip()
if not GCS_BUCKET:
    raise RuntimeError("Chybí GCS_BUCKET v .env")

ANIME_JSON_CLOUD = os.getenv("ANIME_JSON_CLOUD") or os.getenv("ANIME_JSONCLOUD") or "data/anime.json"
USERS_JSON_CLOUD = os.getenv("USERS_JSON_CLOUD") or os.getenv("USERS_DIR_CLOUD") or "private/users"
FEEDBACK_PREFIX   = os.getenv("FEEDBACK_PREFIX","feedback").strip()
TOKEN_INDEX_PREFIX= os.getenv("TOKEN_INDEX_PREFIX","private/tokens").strip().rstrip("/")

ADMIN_BOOT_ENABLE   = os.getenv("ADMIN_BOOT_ENABLE","false").lower()=="true"
ADMIN_EMAIL         = (os.getenv("ADMIN_EMAIL","")).strip().lower()
ADMIN_BOOT_PASSWORD = os.getenv("ADMIN_BOOT_PASSWORD","")

SMTP_HOST     = os.getenv("SMTP_HOST","")
SMTP_PORT     = int(os.getenv("SMTP_PORT","587"))
SMTP_USER     = os.getenv("SMTP_USER","")
SMTP_PASS     = os.getenv("SMTP_PASS","")
SMTP_FROM     = os.getenv("SMTP_FROM", SMTP_USER)
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS","true").lower()=="true"
SMTP_DEBUG    = os.getenv("SMTP_DEBUG","0") in ("1","true","True")

DEV_ECHO_VERIFICATION_LINK = os.getenv("DEV_ECHO_VERIFICATION_LINK","false").lower()=="true"
DEV_SAVE_LAST_EMAIL        = os.getenv("DEV_SAVE_LAST_EMAIL","false").lower()=="true"

DEBUG_AUTH = os.getenv("DEBUG_AUTH","false").lower()=="true"
EMAIL_LOGO_PATH = "assets/logo.png"
