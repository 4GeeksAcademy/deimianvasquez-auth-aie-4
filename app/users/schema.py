from datetime import datetime
from enum import Enum

from pydantic import BaseModel, EmailStr

from app.auth.schema import PasswordInput, Token, UserLogin


class UserRole(str, Enum):
    ADMIN = "Admin"
    GENERAL = "General"


class UserCreate(BaseModel):
    lastname: str
    email: EmailStr
    rol: UserRole = UserRole.GENERAL
    password: PasswordInput


class UserPublic(BaseModel):
    id: int
    lastname: str
    email: EmailStr
    created_at: datetime
    update_at: datetime
    rol: UserRole

