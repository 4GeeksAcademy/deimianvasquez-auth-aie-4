from datetime import datetime, timezone

from tinydb import Query

from app.db.database import db
from app.core.security import hash_password


users_table = db.table("users")
user_query = Query()


def get_by_email(email: str) -> dict | None:
	record = users_table.get(user_query.email == email)
	return dict(record) if record else None


def get_by_id(user_id: int) -> dict | None:
	record = users_table.get(user_query.id == user_id)
	return dict(record) if record else None


def get_all() -> list[dict]:
	return [
		{key: value for key, value in user.items() if key != "password_hash"}
		for user in users_table.all()
	]


def create(user_data: dict) -> dict:
	email = str(user_data["email"])
	if users_table.contains(user_query.email == email):
		raise ValueError("Ya existe un usuario con ese email")

	password_hash = hash_password(user_data["password"])
	now = datetime.now(timezone.utc).isoformat()
	record = {
		**{key: value for key, value in user_data.items() if key != "password"},
		"email": email,
		"id": max((user.get("id", 0) for user in users_table), default=0) + 1,
		"password_hash": password_hash,
		"created_at": now,
		"update_at": now,
	}
	users_table.insert(record)
	return record
