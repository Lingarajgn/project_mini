from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.auth.hashing import hash_password, verify_password
from app.auth.schemas import TokenResponse, UserLoginRequest, UserRegisterRequest
from app.auth.token import create_access_token
from app.models.user import User


class AuthService:
    @staticmethod
    def register(db: Session, payload: UserRegisterRequest) -> User:
        existing_user = db.query(User).filter(User.email == payload.email.lower()).first()
        if existing_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

        user = User(
            fullname=payload.fullname.strip(),
            email=payload.email.lower(),
            password=hash_password(payload.password),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def login(db: Session, payload: UserLoginRequest) -> TokenResponse:
        user = db.query(User).filter(User.email == payload.email.lower()).first()
        if not user or not verify_password(payload.password, user.password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        token = create_access_token({"sub": str(user.id), "email": user.email})
        return TokenResponse(access_token=token)
