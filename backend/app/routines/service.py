from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.routine import Routine
from app.models.user import User
from app.routines.schemas import RoutineCreateRequest, RoutineUpdateRequest


class RoutineService:
    @staticmethod
    def create_routine(db: Session, user: User, payload: RoutineCreateRequest) -> Routine:
        routine = Routine(
            user_id=user.id,
            routine_name=payload.routine_name,
            description=payload.description,
            start_time=payload.start_time,
            end_time=payload.end_time,
        )
        db.add(routine)
        db.commit()
        db.refresh(routine)
        return routine

    @staticmethod
    def get_user_routines(db: Session, user: User) -> list[Routine]:
        return db.query(Routine).filter(Routine.user_id == user.id).order_by(Routine.created_at.desc()).all()

    @staticmethod
    def get_routine_by_id(db: Session, user: User, routine_id: int) -> Routine:
        routine = db.query(Routine).filter(Routine.id == routine_id, Routine.user_id == user.id).first()
        if not routine:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Routine not found")
        return routine

    @staticmethod
    def update_routine(db: Session, user: User, routine_id: int, payload: RoutineUpdateRequest) -> Routine:
        routine = RoutineService.get_routine_by_id(db, user, routine_id)
        if payload.routine_name is not None:
            routine.routine_name = payload.routine_name.strip()
        if payload.description is not None:
            routine.description = payload.description
        if payload.start_time is not None:
            routine.start_time = payload.start_time
        if payload.end_time is not None:
            routine.end_time = payload.end_time
        db.commit()
        db.refresh(routine)
        return routine

    @staticmethod
    def delete_routine(db: Session, user: User, routine_id: int) -> None:
        routine = RoutineService.get_routine_by_id(db, user, routine_id)
        db.delete(routine)
        db.commit()
