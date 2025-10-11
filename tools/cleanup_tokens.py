#!/usr/bin/env python3
import os, time, datetime
from google.cloud import storage

BUCKET = os.environ.get("GCS_BUCKET", "anime-cloud")     # nebo načti z ac.settings
PREFIX = os.environ.get("TOKENS_PREFIX", "private/tokens/")
MAX_AGE = int(os.environ.get("TOKENS_MAX_AGE", "3600"))  # v sekundách (výchozí 1 hod)

def main():
    client = storage.Client()
    now = datetime.datetime.now(datetime.timezone.utc)
    deleted = scanned = 0

    for blob in client.list_blobs(BUCKET, prefix=PREFIX):
        scanned += 1

        # 1) preferuj vlastní TTL v metadatech (pokud jej při zápisu nastavíš)
        md = blob.metadata or {}
        exp = md.get("expires_at")  # unix timestamp jako string
        if exp:
            try:
                if time.time() >= float(exp):
                    blob.delete()
                    deleted += 1
                    continue
            except Exception:
                pass

        # 2) fallback: stáří podle time_created
        age = (now - blob.time_created).total_seconds()
        if age >= MAX_AGE:
            blob.delete()
            deleted += 1

    print(f"ok scanned={scanned} deleted={deleted}")

if __name__ == "__main__":
    main()
