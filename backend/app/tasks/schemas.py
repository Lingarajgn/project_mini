from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator


class TaskCreateRequest(BaseModel):
    title: str
    description: str | None = None
    priority: str = "medium"
    status: str = "pending"
    due_date: datetime | None = None

    @field_validator("title")
    @classmethod
    def title_required(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("title is required")
        return value.strip()

    @field_validator("priority")
    @classmethod
    def priority_valid(cls, value: str) -> str:
        allowed = {"low", "medium", "high"}
        if value.lower() not in allowed:
            raise ValueError("priority must be one of: low, medium, high")
        return value.lower()

    @field_validator("status")
    @classmethod
    def status_valid(cls, value: str) -> str:
        allowed = {"pending", "in_progress", "completed"}
        if value.lower() not in allowed:
            raise ValueError("status must be one of: pending, in_progress, completed")
        return value.lower()


class TaskUpdateRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    priority: str | None = None
    status: str | None = None
    due_date: datetime | None = None

    @field_validator("priority")
    @classmethod
    def priority_valid(cls, value: str | None) -> str | None:
        if value is None:
            return value
        allowed = {"low", "medium", "high"}
        if value.lower() not in allowed:
            raise ValueError("priority must be one of: low, medium, high")
        return value.lower()

    @field_validator("status")
    @classmethod
    def status_valid(cls, value: str | None) -> str | None:
        if value is None:
            return value
        allowed = {"pending", "in_progress", "completed"}
        if value.lower() not in allowed:
            raise ValueError("status must be one of: pending, in_progress, completed")
        return value.lower()


class TaskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    title: str
    description: str | None
    priority: str
    status: str
    due_date: datetime | None
    created_at: datetime
