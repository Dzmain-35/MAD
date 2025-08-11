import os
import json

CACHE_BASE_DIR = ".cache"

def get_cache_path(cache_type, md5):
    dir_path = os.path.join(CACHE_BASE_DIR, cache_type)
    os.makedirs(dir_path, exist_ok=True)
    return os.path.join(dir_path, f"{md5}.json")

def read_cache(cache_type, md5):
    path = get_cache_path(cache_type, md5)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None

def write_cache(cache_type, md5, data):
    path = get_cache_path(cache_type, md5)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
