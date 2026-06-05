from datetime import time

from pydantic import BaseModel, ConfigDict, field_validator


class RoutineCreateRequest(BaseModel):
    routine_name: str
    description: str | None = None
    start_time: time
    end_time: time

    @field_validator("routine_name")
    @classmethod
    def routine_name_required(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("routine_name is required")
        return value.strip()


class RoutineUpdateRequest(BaseModel):
    routine_name: str | None = None
    description: str | None = None
    start_time: time | None = None
    end_time: time | None = None


class RoutineResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    routine_name: str
    description: str | None
    start_time: time
    end_time: time
    created_at: str
