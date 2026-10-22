from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.auth.dependencies import get_access_token, get_current_user, get_token_payload
from app.auth.repository import revoke_access_token
from app.auth.schema import UserLogin
from app.core.config import settings
from app.core.security import create_access_token, verify_password
from app.users.repository import get_by_email
from app.users.schema import UserPublic


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", status_code=status.HTTP_204_NO_CONTENT)
def login(credentials: UserLogin, response: Response) -> None:
	user = get_by_email(str(credentials.email))
	if user is None or not verify_password(
		credentials.password, user["password_hash"]
	):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Email o contraseña incorrectos",
			headers={"WWW-Authenticate": "Bearer"},
		)

	response.set_cookie(
		key="access_token",
		value=create_access_token(str(user["id"])),
		max_age=settings.access_token_expire_minutes * 60,
		httponly=True,
		secure=settings.cookie_secure,
		samesite="lax",
		path="/",
	)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
	response: Response,
	token: Annotated[str, Depends(get_access_token)],
	payload: Annotated[dict[str, object], Depends(get_token_payload)],
	_: Annotated[UserPublic, Depends(get_current_user)],
) -> None:
	revoke_access_token(token, int(payload["exp"]))
	response.delete_cookie(
		key="access_token",
		httponly=True,
		secure=settings.cookie_secure,
		samesite="lax",
		path="/",
	)


