from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.database.database import get_db
from app.models.user import User
from app.tasks.schemas import TaskCreateRequest, TaskResponse, TaskUpdateRequest
from app.tasks.service import TaskService

router = APIRouter(prefix="/tasks", tags=["tasks"])


@router.post("", response_model=TaskResponse, status_code=status.HTTP_201_CREATED)
def create_task(
    payload: TaskCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TaskResponse:
    return TaskService.create_task(db, current_user, payload)


@router.get("", response_model=list[TaskResponse])
def list_tasks(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[TaskResponse]:
    return TaskService.get_user_tasks(db, current_user)


@router.get("/{task_id}", response_model=TaskResponse)
def get_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TaskResponse:
    return TaskService.get_task_by_id(db, current_user, task_id)


@router.put("/{task_id}", response_model=TaskResponse)
def update_task(
    task_id: int,
    payload: TaskUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TaskResponse:
    return TaskService.update_task(db, current_user, task_id, payload)


@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    TaskService.delete_task(db, current_user, task_id)


@router.patch("/{task_id}/complete", response_model=TaskResponse)
def complete_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TaskResponse:
    return TaskService.complete_task(db, current_user, task_id)
