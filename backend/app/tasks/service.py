from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.task import Task
from app.models.user import User
from app.tasks.schemas import TaskCreateRequest, TaskUpdateRequest


class TaskService:
    @staticmethod
    def create_task(db: Session, user: User, payload: TaskCreateRequest) -> Task:
        task = Task(
            user_id=user.id,
            title=payload.title,
            description=payload.description,
            priority=payload.priority.lower(),
            status=payload.status.lower(),
            due_date=payload.due_date,
        )
        db.add(task)
        db.commit()
        db.refresh(task)
        return task

    @staticmethod
    def get_user_tasks(db: Session, user: User) -> list[Task]:
        return db.query(Task).filter(Task.user_id == user.id).order_by(Task.created_at.desc()).all()

    @staticmethod
    def get_task_by_id(db: Session, user: User, task_id: int) -> Task:
        task = db.query(Task).filter(Task.id == task_id, Task.user_id == user.id).first()
        if not task:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
        return task

    @staticmethod
    def update_task(db: Session, user: User, task_id: int, payload: TaskUpdateRequest) -> Task:
        task = TaskService.get_task_by_id(db, user, task_id)

        if payload.title is not None:
            task.title = payload.title.strip()
        if payload.description is not None:
            task.description = payload.description
        if payload.priority is not None:
            task.priority = payload.priority.lower()
        if payload.status is not None:
            task.status = payload.status.lower()
        if payload.due_date is not None:
            task.due_date = payload.due_date

        db.commit()
        db.refresh(task)
        return task

    @staticmethod
    def delete_task(db: Session, user: User, task_id: int) -> None:
        task = TaskService.get_task_by_id(db, user, task_id)
        db.delete(task)
        db.commit()

    @staticmethod
    def complete_task(db: Session, user: User, task_id: int) -> Task:
        task = TaskService.get_task_by_id(db, user, task_id)
        task.status = "completed"
        db.commit()
        db.refresh(task)
        return task
