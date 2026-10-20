from typing import Annotated

from fastapi import APIRouter, HTTPException, status
from fastapi import Depends

from app.auth.dependencies import get_current_user, get_token_payload, oauth2_scheme
from app.auth.repository import revoke_access_token
from app.auth.schema import Token, UserLogin
from app.core.security import create_access_token, verify_password
from app.users.repository import get_by_email
from app.users.schema import UserPublic


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
def login(credentials: UserLogin) -> Token:
	user = get_by_email(str(credentials.email))
	if user is None or not verify_password(
		credentials.password, user["password_hash"]
	):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Email o contraseña incorrectos",
			headers={"WWW-Authenticate": "Bearer"},
		)

	return Token(access_token=create_access_token(str(user["id"])))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
	token: Annotated[str, Depends(oauth2_scheme)],
	payload: Annotated[dict[str, object], Depends(get_token_payload)],
	_: Annotated[UserPublic, Depends(get_current_user)],
) -> None:
	revoke_access_token(token, int(payload["exp"]))


