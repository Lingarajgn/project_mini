from functools import lru_cache
from urllib.parse import quote_plus

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DB_HOST: str = "localhost"
    DB_PORT: int = 3306
    DB_USER: str = "root"
    DB_PASSWORD: str = ""
    DB_NAME: str = "mydb"
    DATABASE_URL: str | None = None
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    def model_post_init(self, __context) -> None:
        if not self.DATABASE_URL:
            encoded_user = quote_plus(self.DB_USER)
            encoded_password = quote_plus(self.DB_PASSWORD)
            self.DATABASE_URL = (
                f"mysql+pymysql://{encoded_user}:{encoded_password}@"
                f"{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
