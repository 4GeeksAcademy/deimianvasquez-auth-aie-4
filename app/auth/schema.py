from typing import Annotated

from pydantic import AfterValidator, BaseModel, EmailStr


def _validate_password_length(password: str) -> str:
	if len(password.encode("utf-8")) > 72:
		raise ValueError("La contraseña no puede superar los 72 bytes")
	return password


PasswordInput = Annotated[str, AfterValidator(_validate_password_length)]


class UserLogin(BaseModel):
	email: EmailStr
	password: PasswordInput


class Token(BaseModel):
	access_token: str
