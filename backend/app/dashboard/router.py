from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.dashboard.schemas import DashboardResponse
from app.dashboard.service import DashboardService
from app.database.database import get_db
from app.models.user import User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardResponse)
def get_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DashboardResponse:
    return DashboardService.get_dashboard_summary(db, current_user)
