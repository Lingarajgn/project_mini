from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.database import Base

if TYPE_CHECKING:
    from .routine import Routine
    from .task import Task


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    fullname: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[str] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    tasks: Mapped[list["Task"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    routines: Mapped[list["Routine"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
