from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.auth.schemas import TokenResponse, UserLoginRequest, UserRegisterRequest, UserResponse
from app.auth.service import AuthService
from app.database.database import get_db
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserRegisterRequest, db: Session = Depends(get_db)) -> User:
    return AuthService.register(db, payload)


@router.post("/login", response_model=TokenResponse)
def login_user(payload: UserLoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    return AuthService.login(db, payload)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)) -> User:
    return current_user
