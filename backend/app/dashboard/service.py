from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.routine import Routine
from app.models.task import Task
from app.models.user import User


class DashboardService:
    @staticmethod
    def get_dashboard_summary(db: Session, user: User) -> dict:
        total_tasks = db.query(func.count(Task.id)).filter(Task.user_id == user.id).scalar() or 0
        completed_tasks = (
            db.query(func.count(Task.id))
            .filter(Task.user_id == user.id, Task.status == "completed")
            .scalar()
            or 0
        )
        pending_tasks = (
            db.query(func.count(Task.id))
            .filter(Task.user_id == user.id, Task.status != "completed")
            .scalar()
            or 0
        )
        total_routines = db.query(func.count(Routine.id)).filter(Routine.user_id == user.id).scalar() or 0

        completion_rate = 0
        if total_tasks > 0:
            completion_rate = int((completed_tasks / total_tasks) * 100)

        return {
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "pending_tasks": pending_tasks,
            "total_routines": total_routines,
            "completion_rate": completion_rate,
        }
