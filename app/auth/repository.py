import hashlib
import time

from tinydb import Query

from app.db.database import db


revoked_tokens = db.table("revoked_tokens")
token_query = Query()


def _token_hash(token: str) -> str:
	return hashlib.sha256(token.encode("utf-8")).hexdigest()


def revoke_access_token(token: str, expires_at: int) -> None:
	token_hash = _token_hash(token)
	revoked_tokens.upsert(
		{"token_hash": token_hash, "expires_at": expires_at},
		token_query.token_hash == token_hash,
	)


def is_access_token_revoked(token: str) -> bool:
	revoked_tokens.remove(token_query.expires_at <= int(time.time()))
	return revoked_tokens.contains(token_query.token_hash == _token_hash(token))