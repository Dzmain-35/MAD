import os
import json


DB_PATH = os.path.join("data", "imphash_db.json")


def load_imphash_db():
    if os.path.exists(DB_PATH):
        try:
            with open(DB_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_imphash_db(db):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=2)


def update_imphash_family(family_name, imphash):
    db = load_imphash_db()
    db.setdefault(family_name, [])
    if imphash not in db[family_name]:
        db[family_name].append(imphash)
        save_imphash_db(db)


def find_family_by_imphash(imphash):
    db = load_imphash_db()
    for family, imphashes in db.items():
        if imphash in imphashes:
            return family
    return None
