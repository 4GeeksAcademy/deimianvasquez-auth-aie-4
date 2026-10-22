from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.dependencies import get_current_user as authenticate_user
from app.users.repository import create, get_all
from app.users.schema import UserCreate, UserPublic, UserRole


router = APIRouter(tags=["users"])


@router.post("/users", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserCreate) -> UserPublic:
	if user_data.rol != UserRole.GENERAL:
		raise HTTPException(
			status_code=status.HTTP_403_FORBIDDEN,
			detail="No puedes asignarte el rol de administrador",
		)

	try:
		user = create(user_data.model_dump(mode="json"))
	except ValueError as error:
		raise HTTPException(
			status_code=status.HTTP_409_CONFLICT,
			detail=str(error),
		) from error
	return UserPublic.model_validate(user)



@router.get("/users/me", response_model=UserPublic, include_in_schema=False)
def get_me(current_user: UserPublic = Depends(authenticate_user)) -> UserPublic:
	return current_user


def require_admin(
	current_user: UserPublic = Depends(authenticate_user),
) -> UserPublic:
	if current_user.rol != UserRole.ADMIN:
		raise HTTPException(
			status_code=status.HTTP_403_FORBIDDEN,
			detail="Se requiere el rol de administrador",
		)
	return current_user


@router.get("/users", response_model=list[UserPublic])
def list_users(_: UserPublic = Depends(require_admin)) -> list[UserPublic]:
	return [UserPublic.model_validate(user) for user in get_all()]