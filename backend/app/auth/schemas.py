from pydantic import BaseModel, ConfigDict, EmailStr, field_validator


class UserRegisterRequest(BaseModel):
    fullname: str
    email: EmailStr
    password: str

    @field_validator("fullname")
    @classmethod
    def fullname_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("fullname is required")
        return value.strip()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("password must be at least 8 characters long")
        if not any(char.isupper() for char in value):
            raise ValueError("password must contain at least one uppercase letter")
        if not any(char.islower() for char in value):
            raise ValueError("password must contain at least one lowercase letter")
        if not any(char.isdigit() for char in value):
            raise ValueError("password must contain at least one number")
        return value


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    fullname: str
    email: str
    created_at: str
