"""Récupère l'emploi du temps Pronote (14 jours), le CHIFFRE, et l'écrit dans data/edt.enc.json.
Identifiants et mot de passe de chiffrement lus dans les Secrets GitHub, jamais dans le code."""
import os, json, base64, hmac, hashlib, datetime as dt
import pronotepy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

client = pronotepy.Client(
    os.environ["PRONOTE_URL"],
    username=os.environ["PRONOTE_USER"],
    password=os.environ["PRONOTE_PASS"],
)
if not client.logged_in:
    raise SystemExit("Connexion Pronote impossible (vérifie l'URL, l'identifiant et le mot de passe)")

start = dt.date.today()
end = start + dt.timedelta(days=14)
lessons = []
for l in client.lessons(start, end):
    lessons.append({
        "start": l.start.isoformat(),
        "end": l.end.isoformat(),
        "subject": l.subject.name if getattr(l, "subject", None) else None,
        "room": getattr(l, "classroom", None),
        "teacher": getattr(l, "teacher_name", None),
        "status": getattr(l, "status", None),
        "canceled": bool(getattr(l, "canceled", False)),
    })
lessons.sort(key=lambda x: x["start"])

plain = json.dumps({"lessons": lessons}, ensure_ascii=False, sort_keys=True).encode()
key = PBKDF2HMAC(hashes.SHA256(), 32, b"mon-cap-edt-v1", 200000).derive(os.environ["EDT_PASSPHRASE"].encode())
iv = hmac.new(key, plain, hashlib.sha256).digest()[:12]  # même contenu = même fichier (pas de commit inutile)
data = AESGCM(key).encrypt(iv, plain, None)
b64 = lambda b: base64.b64encode(b).decode()

os.makedirs("data", exist_ok=True)
with open("data/edt.enc.json", "w") as f:
    json.dump({"v": 1, "iv": b64(iv), "data": b64(data)}, f)
print(f"{len(lessons)} cours chiffrés et enregistrés")
