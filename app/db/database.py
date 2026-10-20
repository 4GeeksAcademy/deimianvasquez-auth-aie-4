from pathlib import Path

from tinydb import TinyDB

from app.core.config import PROJECT_ROOT, settings


DB_PATH = Path(settings.tinydb_path)
if not DB_PATH.is_absolute():
	DB_PATH = PROJECT_ROOT / DB_PATH
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

db = TinyDB(DB_PATH, indent=4, ensure_ascii=False)