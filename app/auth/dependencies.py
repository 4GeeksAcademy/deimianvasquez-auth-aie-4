from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyCookie

from app.core.config import settings
from app.auth.repository import is_access_token_revoked
from app.users.repository import get_by_id
from app.users.schema import UserPublic


access_token_cookie = APIKeyCookie(name="access_token", auto_error=False)


def get_access_token(
	token: Annotated[str | None, Depends(access_token_cookie)],
) -> str:
	if token is None:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="No se pudieron validar las credenciales",
			headers={"WWW-Authenticate": "Bearer"},
		)
	return token


def get_token_payload(
	token: Annotated[str, Depends(get_access_token)],
) -> dict[str, object]:
	credentials_exception = HTTPException(
		status_code=status.HTTP_401_UNAUTHORIZED,
		detail="No se pudieron validar las credenciales",
		headers={"WWW-Authenticate": "Bearer"},
	)

	try:
		payload = jwt.decode(
			token,
			settings.secret_key,
			algorithms=[settings.algorithm],
			options={"require": ["sub", "exp"]},
		)
	except jwt.InvalidTokenError:
		raise credentials_exception from None

	return payload


def get_current_user(
	token: Annotated[str, Depends(get_access_token)],
	payload: Annotated[dict[str, object], Depends(get_token_payload)],
) -> UserPublic:
	credentials_exception = HTTPException(
		status_code=status.HTTP_401_UNAUTHORIZED,
		detail="No se pudieron validar las credenciales",
		headers={"WWW-Authenticate": "Bearer"},
	)

	try:
		user_id = int(payload["sub"])
	except (KeyError, TypeError, ValueError):
		raise credentials_exception from None

	if is_access_token_revoked(token):
		raise credentials_exception

	user = get_by_id(user_id)
	if user is None:
		raise credentials_exception

	return UserPublic.model_validate(user)
