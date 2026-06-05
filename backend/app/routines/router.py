from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.database.database import get_db
from app.models.user import User
from app.routines.schemas import RoutineCreateRequest, RoutineResponse, RoutineUpdateRequest
from app.routines.service import RoutineService

router = APIRouter(prefix="/routines", tags=["routines"])


@router.post("", response_model=RoutineResponse, status_code=status.HTTP_201_CREATED)
def create_routine(
    payload: RoutineCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RoutineResponse:
    return RoutineService.create_routine(db, current_user, payload)


@router.get("", response_model=list[RoutineResponse])
def list_routines(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[RoutineResponse]:
    return RoutineService.get_user_routines(db, current_user)


@router.get("/{routine_id}", response_model=RoutineResponse)
def get_routine(
    routine_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RoutineResponse:
    return RoutineService.get_routine_by_id(db, current_user, routine_id)


@router.put("/{routine_id}", response_model=RoutineResponse)
def update_routine(
    routine_id: int,
    payload: RoutineUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RoutineResponse:
    return RoutineService.update_routine(db, current_user, routine_id, payload)


@router.delete("/{routine_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_routine(
    routine_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    RoutineService.delete_routine(db, current_user, routine_id)
