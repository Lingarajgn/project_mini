from pydantic import BaseModel


class DashboardResponse(BaseModel):
    total_tasks: int
    completed_tasks: int
    pending_tasks: int
    total_routines: int
    completion_rate: int
